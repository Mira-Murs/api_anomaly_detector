#!/usr/bin/env python3
"""Непрерывный воркер – читает сырые события из Redis 'raw:*' и прогоняет через ML-конвейер."""

import json
import time
import requests
import redis
import os

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

NORMALIZER_URL = "http://localhost:8002/normalize"
EXTRACTOR_URL = "http://localhost:8005/extract"
DETECTOR_URL = "http://localhost:8001/detect"
RISK_URL = "http://localhost:8003/compute"
DECIDE_URL = "http://localhost:8007/decide"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def process_event(raw_json: str):
    try:
        raw = json.loads(raw_json)
    except Exception:
        return
    # Нормализация
    normal_payload = {
        "timestamp": raw.get("timestamp", ""),
        "method": raw.get("method", "GET"),
        "url": raw.get("url", "/"),
        "status_code": raw.get("status_code", 200),
        "body_length": raw.get("body_length", 0),
        "payload_preview": raw.get("payload_preview", ""),
        "source": "realtime"
    }
    try:
        resp_norm = requests.post(NORMALIZER_URL, json=normal_payload, timeout=5)
        resp_norm.raise_for_status()
        norm = resp_norm.json()
    except Exception as e:
        print(f"Normalizer error: {e}")
        return

    # Извлечение признаков (передаём source_ip для накопления сессии)
    try:
        feat_payload = dict(norm)
        feat_payload["source_ip"] = raw.get("source_ip", raw.get("user_id", "127.0.0.1"))
        resp_feat = requests.post(EXTRACTOR_URL, json=feat_payload, timeout=5)
        resp_feat.raise_for_status()
        feat = resp_feat.json()
        features = feat["feature_vector"]
    except Exception as e:
        print(f"Feature extractor error: {e}")
        return

    # Детекция аномалий
    try:
        resp_det = requests.post(DETECTOR_URL, json={"features": features}, timeout=5)
        resp_det.raise_for_status()
        anomaly_score = resp_det.json()["anomaly_score"]
    except Exception as e:
        print(f"Anomaly detector error: {e}")
        return

    # Оценка риска
    endpoint = raw.get("url", "/")
    user = raw.get("user_id", "realtime")
    try:
        resp_risk = requests.post(RISK_URL, json={
            "anomaly_score": anomaly_score,
            "endpoint_id": endpoint,
            "user_id": user
        }, timeout=5)
        resp_risk.raise_for_status()
        risk_data = resp_risk.json()
    except Exception as e:
        print(f"Risk engine error: {e}")
        return

    # Принятие решения
    payload_decide = {
        "risk_score": risk_data["risk_score"],
        "risk_zone": risk_data["risk_zone"],
        "endpoint_id": endpoint,
        "user_id": user,
        "payload_preview": raw.get("payload_preview", "")
    }
    try:
        resp_decide = requests.post(DECIDE_URL, json=payload_decide, timeout=5)
        resp_decide.raise_for_status()
        action = resp_decide.json().get("action", "unknown")
    except Exception as e:
        print(f"Decision error: {e}")
        return

    print(f"[{time.strftime('%H:%M:%S')}] {endpoint} -> {action} "
          f"(anomaly={anomaly_score:.3f}, risk={risk_data['risk_score']:.3f}, "
          f"zone={risk_data['risk_zone']})")

def main():
    print("Continuous worker started (Python). Polling Redis...")
    while True:
        try:
            keys = r.keys("raw:*")
            for key in keys:
                raw_json = r.get(key)
                if raw_json:
                    process_event(raw_json)
                r.delete(key)
        except Exception as e:
            print(f"Redis error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    main()
