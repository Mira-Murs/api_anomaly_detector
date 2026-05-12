#!/usr/bin/env python3
import json
import math
import statistics
import urllib.request
from datetime import datetime, timezone

NORMALIZER_URL = "http://localhost:8002/normalize"
FEATURE_EXTRACTOR_URL = "http://localhost:8005/extract"
ANOMALY_DETECTOR_URL = "http://localhost:8001/detect"

ENDPOINTS = [
    ("/", "GET"),
    ("/users/v1", "GET"),
    ("/users/v1/login", "POST"),
    ("/users/v1/register", "POST"),
    ("/books/v1", "GET"),
    ("/books/v1/{book_title}", "GET"),
    ("/me", "GET"),
]

NORMAL_PAYLOADS = [
    "{}",
    '{"username":"alice","password":"Password123"}',
    '{"email":"alice@example.com"}',
    '{"title":"book","author":"author"}',
]

ATTACK_PAYLOADS = [
    "' OR 1=1 -- UNION SELECT username,password FROM users",
    "<script>alert(document.cookie)</script>",
    "../../../../etc/passwd",
    "A" * 512 + "%27%22%3C%3E{}[]$" + "9f2a7c4b8d1e0f6a" * 16,
    '{"username":"admin\\" OR \\"1\\"=\\"1","password":"x"}',
]

FEATURE_NAMES = [
    "duration",
    "freq",
    "is_delete",
    "is_get",
    "is_post",
    "is_put",
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


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def score_event(event):
    normalized = post_json(NORMALIZER_URL, event)
    extracted = post_json(FEATURE_EXTRACTOR_URL, normalized)
    vector = extracted["feature_vector"]
    detected = post_json(ANOMALY_DETECTOR_URL, {"features": vector})
    return {
        "event": event,
        "features": vector,
        "anomaly_score": float(detected["anomaly_score"]),
    }


def auc_rank(normal_scores, attack_scores):
    pairs = 0
    wins = 0.0
    for a in attack_scores:
        for n in normal_scores:
            pairs += 1
            if a > n:
                wins += 1
            elif a == n:
                wins += 0.5
    return wins / pairs if pairs else 0.0


def summarize(label, rows):
    scores = [r["anomaly_score"] for r in rows]
    return {
        "label": label,
        "count": len(scores),
        "min": min(scores),
        "max": max(scores),
        "mean": statistics.mean(scores),
        "median": statistics.median(scores),
        "stdev": statistics.pstdev(scores) if len(scores) > 1 else 0.0,
    }


def main():
    normal_rows = []
    attack_rows = []

    for endpoint, method in ENDPOINTS:
        for payload in NORMAL_PAYLOADS:
            event = {
                "timestamp": now_iso(),
                "method": method,
                "url": endpoint,
                "status_code": 200,
                "body_length": max(80, len(payload)),
                "payload_preview": payload,
                "source": "model_validation_normal",
                "source_ip": "10.10.0.10",
            }
            normal_rows.append(score_event(event))

        for payload in ATTACK_PAYLOADS:
            event = {
                "timestamp": now_iso(),
                "method": method,
                "url": endpoint,
                "status_code": 400 if "passwd" in payload else 200,
                "body_length": max(120, len(payload)),
                "payload_preview": payload,
                "source": "model_validation_attack",
                "source_ip": "10.10.0.20",
            }
            attack_rows.append(score_event(event))

    normal_scores = [r["anomaly_score"] for r in normal_rows]
    attack_scores = [r["anomaly_score"] for r in attack_rows]
    normal_p95 = sorted(normal_scores)[max(0, math.ceil(0.95 * len(normal_scores)) - 1)]
    attack_above_p95 = sum(1 for s in attack_scores if s > normal_p95)

    print("=== Isolation Forest runtime validation ===")
    print(json.dumps(summarize("normal", normal_rows), indent=2))
    print(json.dumps(summarize("attack", attack_rows), indent=2))
    print()
    print(f"normal_p95: {normal_p95:.6f}")
    print(f"attack_above_normal_p95: {attack_above_p95}/{len(attack_scores)}")
    print(f"rank_auc_attack_greater_than_normal: {auc_rank(normal_scores, attack_scores):.4f}")

    print("\n=== Top attack samples ===")
    for row in sorted(attack_rows, key=lambda x: x["anomaly_score"], reverse=True)[:10]:
        event = row["event"]
        print(f"{row['anomaly_score']:.6f} {event['method']} {event['url']} payload={event['payload_preview'][:80]!r}")

    print("\n=== Feature averages: attack - normal ===")
    normal_avg = [statistics.mean(r["features"][i] for r in normal_rows) for i in range(len(FEATURE_NAMES))]
    attack_avg = [statistics.mean(r["features"][i] for r in attack_rows) for i in range(len(FEATURE_NAMES))]
    deltas = [(FEATURE_NAMES[i], attack_avg[i] - normal_avg[i], normal_avg[i], attack_avg[i]) for i in range(len(FEATURE_NAMES))]
    for name, delta, n_avg, a_avg in sorted(deltas, key=lambda x: abs(x[1]), reverse=True):
        print(f"{name:18} delta={delta:9.4f} normal_avg={n_avg:9.4f} attack_avg={a_avg:9.4f}")


if __name__ == "__main__":
    main()
