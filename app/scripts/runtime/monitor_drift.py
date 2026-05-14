#!/usr/bin/env python3
"""Проверяет дрейф признаков по критерию Колмогорова-Смирнова."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np
try:
    import redis
except ModuleNotFoundError:
    redis = None
from scipy.stats import ks_2samp


REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REF_PATH = Path(os.getenv("DRIFT_REF_PATH", "artifacts/data/monitoring/ref_features.json"))
CURRENT_KEY = os.getenv("DRIFT_CURRENT_KEY", "metrics:feature_window")
REPORT_KEY = os.getenv("DRIFT_REPORT_KEY", "metrics:drift_report")
FLAG_KEY = os.getenv("DRIFT_FLAG_KEY", "metrics:drift_detected")
UNCERTAINTY_KEY = os.getenv("DRIFT_UNCERTAINTY_KEY", "metrics:uncertainty")
P_THRESHOLD = float(os.getenv("DRIFT_P_THRESHOLD", "0.05"))
MIN_SAMPLES = int(os.getenv("DRIFT_MIN_SAMPLES", "20"))
WINDOW_SIZE = int(os.getenv("DRIFT_WINDOW_SIZE", "500"))


def load_reference(path: Path) -> dict[str, list[float]]:
    if not path.exists():
        raise FileNotFoundError(f"reference file not found: {path}")

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("reference file must contain a JSON object")

    result = {}
    for key, values in data.items():
        if isinstance(values, list) and values:
            result[key] = [float(x) for x in values]

    if not result:
        raise ValueError("reference file does not contain numeric feature arrays")

    return result


def load_current_from_file(path: Path) -> dict[str, list[float]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return {
            key: [float(x) for x in values]
            for key, values in data.items()
            if isinstance(values, list)
        }
    raise ValueError("current file must contain a JSON object")


def load_current_from_redis(client, key: str, limit: int) -> dict[str, list[float]]:
    rows = client.lrange(key, 0, limit - 1)
    result: dict[str, list[float]] = {}

    for row in rows:
        try:
            item = json.loads(row)
        except Exception:
            continue

        if not isinstance(item, dict):
            continue

        for feature_name, value in item.items():
            try:
                result.setdefault(feature_name, []).append(float(value))
            except Exception:
                continue

    return result


def evaluate(reference: dict[str, list[float]], current: dict[str, list[float]]) -> dict:
    features = sorted(set(reference) & set(current))
    checks = []

    for feature_name in features:
        ref_values = np.asarray(reference[feature_name], dtype=float)
        cur_values = np.asarray(current[feature_name], dtype=float)

        if len(ref_values) < MIN_SAMPLES or len(cur_values) < MIN_SAMPLES:
            continue

        stat, p_value = ks_2samp(ref_values, cur_values)
        checks.append({
            "feature": feature_name,
            "ks_statistic": float(stat),
            "p_value": float(p_value),
            "drift": bool(p_value < P_THRESHOLD),
            "reference_count": int(len(ref_values)),
            "current_count": int(len(cur_values)),
        })

    drift_detected = any(item["drift"] for item in checks)
    max_statistic = max((item["ks_statistic"] for item in checks), default=0.0)

    return {
        "drift_detected": drift_detected,
        "p_threshold": P_THRESHOLD,
        "min_samples": MIN_SAMPLES,
        "features_checked": len(checks),
        "max_ks_statistic": max_statistic,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", default=str(REF_PATH))
    parser.add_argument("--current-json", default="")
    args = parser.parse_args()

    reference = load_reference(Path(args.reference))

    client = None
    needs_redis = not bool(args.current_json)

    if needs_redis:
        if redis is None:
            raise RuntimeError("redis package is required when --current-json is not provided")
        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )

    if args.current_json:
        current = load_current_from_file(Path(args.current_json))
    else:
        current = load_current_from_redis(client, CURRENT_KEY, WINDOW_SIZE)

    report = evaluate(reference, current)

    if needs_redis:
        try:
            client.set(FLAG_KEY, "true" if report["drift_detected"] else "false")
            client.set(REPORT_KEY, json.dumps(report, ensure_ascii=False, sort_keys=True))
            client.set(UNCERTAINTY_KEY, str(report["max_ks_statistic"]))
        except Exception as exc:
            report["redis_write_error"] = type(exc).__name__

    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
