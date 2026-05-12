from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
import redis
import json
import os
import httpx
import uuid
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")
redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)

NORMALIZER_URL = os.getenv("NORMALIZER_URL", "http://normalizer:8000/normalize")
FEATURE_EXTRACTOR_URL = os.getenv("FEATURE_EXTRACTOR_URL", "http://feature_extractor:8000/extract")
ANOMALY_DETECTOR_URL = os.getenv("ANOMALY_DETECTOR_URL", "http://anomaly_detector:8000/detect")
RISK_ENGINE_URL = os.getenv("RISK_ENGINE_URL", "http://risk_engine:8000/compute")
RESPONSE_ORCHESTRATOR_URL = os.getenv("RESPONSE_ORCHESTRATOR_URL", "http://response_orchestrator:8000/decide")


class RawEvent(BaseModel):
    timestamp: str
    method: str
    url: str
    status_code: int
    body_length: int = 0
    payload_preview: str = ""
    attack_tag: str = ""
    is_anomaly: bool = False
    source: str = "unknown"
    source_ip: str = ""
    user_id: str = "anonymous"

    # Optional LLM/tool-call context.
    tool_name: str = ""
    tool_method: str = "POST"
    tool_endpoint: str = ""
    tool_arguments: dict = Field(default_factory=dict)
    user_confirmed: bool = False


def fill_source_ip(event: RawEvent, request: Request) -> None:
    if event.source_ip:
        return

    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        event.source_ip = forwarded_for.split(",")[0].strip()
    elif request.client:
        event.source_ip = request.client.host
    else:
        event.source_ip = "unknown"


async def post_json(client: httpx.AsyncClient, url: str, payload: dict, stage: str) -> dict:
    try:
        resp = await client.post(url, json=payload, timeout=2.0)
    except Exception as e:
        raise HTTPException(502, f"{stage} unavailable: {e}")

    if resp.status_code >= 400:
        raise HTTPException(502, f"{stage} failed with status {resp.status_code}: {resp.text[:300]}")

    try:
        return resp.json()
    except Exception as e:
        raise HTTPException(502, f"{stage} returned invalid JSON: {e}")


@app.post("/collect")
async def collect(event: RawEvent, request: Request):
    fill_source_ip(event, request)

    raw_key = f"raw:{uuid.uuid4()}"
    raw_payload = event.dict()
    redis_client.setex(raw_key, 3600, json.dumps(raw_payload))

    async with httpx.AsyncClient() as client:
        normalized = await post_json(client, NORMALIZER_URL, raw_payload, "normalizer")
        features = await post_json(client, FEATURE_EXTRACTOR_URL, normalized, "feature_extractor")
        feature_vector = features.get("feature_vector")

        if not isinstance(feature_vector, list):
            raise HTTPException(502, "feature_extractor response missing feature_vector")

        anomaly = await post_json(
            client,
            ANOMALY_DETECTOR_URL,
            {"features": feature_vector},
            "anomaly_detector",
        )

        endpoint_id = normalized.get("url") or event.url
        risk = await post_json(
            client,
            RISK_ENGINE_URL,
            {
                "anomaly_score": anomaly.get("anomaly_score", 0.0),
                "endpoint_id": endpoint_id,
                "user_id": event.user_id,
            },
            "risk_engine",
        )

        decision = await post_json(
            client,
            RESPONSE_ORCHESTRATOR_URL,
            {
                "risk_score": risk.get("risk_score", 0.0),
                "risk_zone": risk.get("risk_zone", "normal"),
                "endpoint_id": endpoint_id,
                "user_id": event.user_id,
                "payload_preview": event.payload_preview,
                "tool_name": event.tool_name,
                "tool_method": event.tool_method,
                "tool_endpoint": event.tool_endpoint,
                "tool_arguments": event.tool_arguments,
                "user_confirmed": event.user_confirmed,
            },
            "response_orchestrator",
        )

    result = {
        "status": "ok",
        "key": raw_key,
        "source_ip": event.source_ip,
        "normalized": normalized,
        "features": {
            "count": len(feature_vector),
        },
        "anomaly": anomaly,
        "risk": risk,
        "decision": decision,
    }

    redis_client.setex(f"processed:{raw_key}", 3600, json.dumps(result))
    return result


@app.get("/health")
async def health():
    return {"status": "ok"}
