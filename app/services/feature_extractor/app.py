from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import redis
import os
import httpx
import math
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")
r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
SESSION_METRICS_URL = os.getenv("SESSION_METRICS_URL", "http://session_metrics:8000")

class NormalizedEvent(BaseModel):
    method: str
    url: str
    status_code: int
    body_length: int
    payload_preview: str = ""
    source_ip: str = ""

def entropy(s):
    if not s: return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

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


def extract_features(event: NormalizedEvent, sm: dict):
    method = event.method.upper()
    url = event.url.lower()
    status = event.status_code
    body_len = event.body_length
    payload = event.payload_preview

    # HTTP method one-hot
    is_delete = 1.0 if method == 'DELETE' else 0.0
    is_get    = 1.0 if method == 'GET'    else 0.0
    is_post   = 1.0 if method == 'POST'   else 0.0
    is_put    = 1.0 if method == 'PUT'    else 0.0

    # Базовые числовые
    len_body = np.log1p(float(body_len))
    duration = 0.0

    # Поведенческие
    freq = float(sm.get('freq', 0.0))
    uniq_ep = float(sm.get('unique_endpoints', 0.0))
    mean_interval = float(sm.get('mean_interval', 0.0))

    # Контентные признаки
    url_entropy      = entropy(url)
    sqli_patterns = suspicious_pattern_score(payload)
    url_depth        = float(url.count('/'))
    payload_entropy  = entropy(payload)
    status_4xx       = 1.0 if 400 <= status < 500 else 0.0
    status_5xx       = 1.0 if status >= 500 else 0.0
    num_query        = float(url.count('?') + url.count('&') + url.count('='))
    payload_len      = np.log1p(float(len(payload))) if payload else 0.0

    features = [
        duration,
        freq,
        is_delete,
        is_get,
        is_post,
        is_put,
        len_body,
        mean_interval,
        url_entropy,
        sqli_patterns,
        url_depth,
        payload_entropy,
        status_4xx,
        status_5xx,
        num_query,
        payload_len,
        uniq_ep
    ]
    return features

@app.post("/extract")
async def extract(event: NormalizedEvent):
    source_ip = event.source_ip
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{SESSION_METRICS_URL}/update",
                                     json={"source_ip": source_ip, "endpoint": event.url}, timeout=0.5)
            if resp.status_code == 200:
                sm = resp.json()
            else:
                sm = {"freq": 0.0, "unique_endpoints": 0.0, "mean_interval": 0.0}
    except:
        sm = {"freq": 0.0, "unique_endpoints": 0.0, "mean_interval": 0.0}
    vec = extract_features(event, sm)
    return {"feature_vector": vec}

@app.get("/health")
async def health():
    return {"status": "ok"}
