from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis
import os
import httpx
import asyncio
import math
import json
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")
redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
VULN_CONTEXT_URL = os.getenv("VULN_CONTEXT_URL", "http://vuln_context:8000")

class RiskRequest(BaseModel):
    anomaly_score: float
    endpoint_id: str
    user_id: str = "anonymous"   # добавлено для сессий

class RiskResponse(BaseModel):
    risk_score: float
    risk_zone: str
    vulnerability_weight: float
    thresholds_used: dict
    cumulative_risk: float = 0.0

def norm_endpoint_id(value: str) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if not value.startswith("/"):
        value = "/" + value

    parts = []
    for part in value.split("/"):
        if part.startswith(":") and len(part) > 1:
            parts.append("{" + part[1:] + "}")
        else:
            parts.append(part)

    return "/".join(parts)

async def get_vulnerability_context(endpoint_id: str) -> dict:
    endpoint_id = norm_endpoint_id(endpoint_id)
    cache_key = f"risk_vuln_context:{endpoint_id}"
    cached = redis_client.get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    default = {
        "vulnerability_weight": 0.3,
        "cvss": 0.0,
        "exploitable": False,
        "applicable_findings_count": 0,
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{VULN_CONTEXT_URL}/vuln", json={"endpoint_id": endpoint_id}, timeout=2.0)
            if resp.status_code != 200:
                return default

            data = resp.json()
            applicable = data.get("applicable_findings") or []
            ctx = {
                "vulnerability_weight": float(data.get("vulnerability_weight", 0.3) or 0.3),
                "cvss": float(data.get("cvss", 0.0) or 0.0),
                "exploitable": bool(data.get("exploitable", False)),
                "applicable_findings_count": len(applicable),
            }
            redis_client.setex(cache_key, 3600, json.dumps(ctx))
            redis_client.setex(f"vuln_weight:{endpoint_id}", 3600, ctx["vulnerability_weight"])
            return ctx
        except Exception:
            return default

def get_thresholds():
    theta1_base = float(redis_client.get("config:theta1") or os.getenv("THETA1_DEFAULT", "0.6"))
    theta2_base = float(redis_client.get("config:theta2") or os.getenv("THETA2_DEFAULT", "1.0"))
    k_load = float(redis_client.get("config:k_load") or os.getenv("K_LOAD_DEFAULT", "0.2"))
    k_unc = float(redis_client.get("config:k_unc") or os.getenv("K_UNC_DEFAULT", "0.1"))
    L = float(redis_client.get("metrics:load") or 0.0)
    delta = float(redis_client.get("metrics:uncertainty") or 0.0)
    theta2_curr = min(1.5, theta2_base * (1 + k_load * L + k_unc * delta))
    epsilon = 0.05
    theta1_curr = min(theta2_curr - epsilon, theta1_base * (1 + 0.5 * k_load * L))
    return theta1_curr, theta2_curr

async def update_cumulative_risk(user_id: str, current_risk: float, gamma: float = 0.9) -> float:
    key = f"session_risk:{user_id}"
    prev = redis_client.get(key)
    prev_risk = float(prev) if prev is not None else 0.0
    S_t = gamma * prev_risk + (1 - gamma) * current_risk
    # Ограничим сверху 2.0
    S_t = min(S_t, 2.0)
    redis_client.setex(key, 3600, S_t)
    return S_t

@app.post("/compute", response_model=RiskResponse)
async def compute_risk(req: RiskRequest):
    endpoint_id = norm_endpoint_id(req.endpoint_id)
    vuln_ctx = await get_vulnerability_context(endpoint_id)
    vuln_weight = float(vuln_ctx.get("vulnerability_weight", 0.3) or 0.3)
    exploitable = bool(vuln_ctx.get("exploitable", False))

    # Diploma formula is preserved:
    # R(x) = f(x) * V(e)
    risk = req.anomaly_score * vuln_weight

    # Cumulative risk remains based on contextual risk.
    cum_risk = await update_cumulative_risk(req.user_id, risk)

    theta1, theta2 = get_thresholds()

    session_warn = float(redis_client.get("config:session_warn") or 1.0)
    session_block = float(redis_client.get("config:session_block") or 1.5)

    # Pure behavioral anomaly fallback:
    # SAST/DAST absence must not prove safety. A strong anomaly without
    # confirmed exploitability is escalated to MFA, not blocked.
    anomaly_warn = float(redis_client.get("config:anomaly_warn") or os.getenv("ANOMALY_WARN_DEFAULT", "0.85"))

    if (exploitable and risk >= theta2) or cum_risk >= session_block:
        zone = "blocked"
    elif risk >= theta1 or req.anomaly_score >= anomaly_warn or cum_risk >= session_warn:
        zone = "elevated"
    else:
        zone = "normal"

    return RiskResponse(
        risk_score=risk,
        risk_zone=zone,
        vulnerability_weight=vuln_weight,
        thresholds_used={
            "theta1": theta1,
            "theta2": theta2,
            "anomaly_warn": anomaly_warn,
            "exploitable": exploitable,
            "cvss": vuln_ctx.get("cvss", 0.0),
            "applicable_findings_count": vuln_ctx.get("applicable_findings_count", 0),
        },
        cumulative_risk=cum_risk
    )

@app.post("/update_config")
async def update_config(theta1: float = None, theta2: float = None, k_load: float = None, k_unc: float = None, session_warn: float = None, session_block: float = None):
    if theta1 is not None:
        redis_client.set("config:theta1", theta1)
    if theta2 is not None:
        redis_client.set("config:theta2", theta2)
    if k_load is not None:
        redis_client.set("config:k_load", k_load)
    if k_unc is not None:
        redis_client.set("config:k_unc", k_unc)
    if session_warn is not None:
        redis_client.set("config:session_warn", session_warn)
    if session_block is not None:
        redis_client.set("config:session_block", session_block)
    return {"status": "ok"}

@app.post("/update_metrics")
async def update_metrics(load: float = None, uncertainty: float = None):
    if load is not None:
        redis_client.set("metrics:load", load)
    if uncertainty is not None:
        redis_client.set("metrics:uncertainty", uncertainty)
    return {"status": "ok"}

@app.get("/health")
async def health():
    return {"status": "ok"}
