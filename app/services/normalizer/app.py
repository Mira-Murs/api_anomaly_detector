from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis
import os
import json
import re
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")
redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)

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

class NormalizedEvent(BaseModel):
    method: str
    url: str
    status_code: int
    body_length: int
    payload_preview: str
    source_ip: str

@app.post("/normalize")
async def normalize(raw: RawEvent):
    url_lower = raw.url.lower()
    normalized_url = re.sub(r'(?<!:)/{2,}', '/', url_lower)
    normalized = NormalizedEvent(
        method=raw.method.upper(),
        url=normalized_url,
        status_code=raw.status_code,
        body_length=raw.body_length,
        payload_preview=raw.payload_preview[:200],
        source_ip=raw.source_ip
    )
    return normalized.dict()

@app.get("/health")
async def health():
    return {"status": "ok"}
