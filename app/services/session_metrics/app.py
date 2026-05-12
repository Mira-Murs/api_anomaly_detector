from fastapi import FastAPI
from pydantic import BaseModel
import redis
import os
import time
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")
r = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))

class UpdateRequest(BaseModel):
    source_ip: str
    endpoint: str

@app.post("/update")
async def update(req: UpdateRequest):
    now = time.time()
    ip = req.source_ip
    ep = req.endpoint

    # Добавляем временную метку
    r.rpush(f"session:{ip}:timestamps", str(now))
    # Оставляем только за последние 60 секунд
    r.ltrim(f"session:{ip}:timestamps", -100, -1)  # максимум 100
    # Удаляем старые (< now - 60)
    while True:
        oldest = r.lindex(f"session:{ip}:timestamps", 0)
        if oldest and float(oldest) < now - 60:
            r.lpop(f"session:{ip}:timestamps")
        else:
            break

    # Уникальные эндпоинты
    r.sadd(f"session:{ip}:endpoints", ep)
    r.expire(f"session:{ip}:timestamps", SESSION_TTL_SECONDS)
    r.expire(f"session:{ip}:endpoints", SESSION_TTL_SECONDS)
    unique_count = r.scard(f"session:{ip}:endpoints")

    # Частота и средний интервал
    timestamps = [float(ts) for ts in r.lrange(f"session:{ip}:timestamps", 0, -1)]
    count = len(timestamps)
    if count >= 2:
        mean_interval = (timestamps[-1] - timestamps[0]) / (count - 1)
        freq = 1.0 / mean_interval if mean_interval > 0 else 0.0
    else:
        freq = 0.0
        mean_interval = 0.0

    return {
        "freq": freq,
        "unique_endpoints": unique_count,
        "mean_interval": mean_interval
    }

@app.get("/health")
async def health():
    return {"status": "ok"}
