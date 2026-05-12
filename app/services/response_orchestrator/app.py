from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import redis
import os
import json
import logging
from enum import Enum
import re
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")

ORCHESTRATOR_DECISIONS_TOTAL = Counter(
    "orchestrator_decisions_total",
    "Total response orchestrator decisions by action and zone",
    ["action", "zone"],
)

ORCHESTRATOR_LLM_GUARD_TOTAL = Counter(
    "orchestrator_llm_guard_total",
    "Total LLM guard outcomes by action",
    ["action"],
)

redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True)
LLM_GUARD_CHECK_URL = os.getenv("LLM_GUARD_CHECK_URL", "http://llm_guard:8000/check")
LLM_GUARD_TOOL_URL = os.getenv("LLM_GUARD_TOOL_URL", "http://llm_guard:8000/verify_tool_call")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("response_orchestrator")

# Паттерны для детектирования вредоносных промптов
INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"system:\s*you are",
    r"override.*prompt",
    r"### Instruction:",
    r"<\|im_start\|>system",
]

def is_prompt_safe(prompt: str) -> bool:
    for pat in INJECTION_PATTERNS:
        if re.search(pat, prompt, re.IGNORECASE):
            return False
    return True

async def check_prompt_with_llm_guard(prompt: str):
    """
    Проверяет LLM-промпт через отдельный микросервис llm_guard.
    При недоступности сервиса использует локальный regex fallback.
    """
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(LLM_GUARD_CHECK_URL, json={"prompt": prompt, "context_type": "generic"}, timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                return bool(data.get("safe", True)), data.get("reason", "")
            logger.warning(f"llm_guard returned status {resp.status_code}; using local fallback")
    except Exception as e:
        logger.warning(f"llm_guard unavailable, using local fallback: {e}")

    return is_prompt_safe(prompt), "Local prompt-injection fallback triggered"


async def verify_tool_call_with_llm_guard(req):
    """
    Проверяет LLM tool/API call через llm_guard.
    Возвращает (allowed, action, reason, matched_rules, risk_delta).
    """
    if not req.tool_name and not req.tool_endpoint:
        return True, "allow", "", [], 0.0

    try:
        import httpx
        payload = {
            "tool_name": req.tool_name,
            "method": req.tool_method,
            "endpoint": req.tool_endpoint or req.endpoint_id,
            "arguments": req.tool_arguments or {},
            "user_confirmed": req.user_confirmed,
            "risk_zone": req.risk_zone,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(LLM_GUARD_TOOL_URL, json=payload, timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                return (
                    bool(data.get("safe", True)),
                    data.get("action", "allow"),
                    data.get("reason", ""),
                    data.get("matched_rules", []),
                    float(data.get("risk_delta", 0.0) or 0.0),
                )
            logger.warning(f"llm_guard tool verification returned status {resp.status_code}; allowing by fallback")
    except Exception as e:
        logger.warning(f"llm_guard tool verification unavailable: {e}")

    return True, "allow", "", [], 0.0


class DecisionRequest(BaseModel):
    risk_score: float
    risk_zone: str
    endpoint_id: str
    user_id: str = "anonymous"
    payload_preview: str = ""

    # Optional LLM/tool-call context. Existing API clients remain compatible.
    tool_name: str = ""
    tool_method: str = "POST"
    tool_endpoint: str = ""
    tool_arguments: dict = Field(default_factory=dict)
    user_confirmed: bool = False

class Action(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge_mfa"
    BLOCK = "block"

class DecisionResponse(BaseModel):
    action: Action
    message: str
    block_duration_seconds: int = 0

BLOCK_DURATIONS = {
    "elevated": 300,
    "blocked": 3600
}

@app.post("/decide", response_model=DecisionResponse)
async def decide(req: DecisionRequest):
    logger.info(f"Decision request: zone={req.risk_zone}, score={req.risk_score}, endpoint={req.endpoint_id}, user={req.user_id}")

    # Проверка LLM-промптов через микросервис llm_guard; локальный regex используется как fallback.
    LLM_ENDPOINTS = json.loads(redis_client.get("config:llm_endpoints") or '["/chat","/ask","/generate"]')
    if any(req.endpoint_id.startswith(ep) for ep in LLM_ENDPOINTS) and req.payload_preview:
        prompt_safe, guard_reason = await check_prompt_with_llm_guard(req.payload_preview)
        if not prompt_safe:
            req.risk_zone = "blocked"
            req.risk_score = max(req.risk_score, 1.5)
            logger.warning(f"LLM prompt injection detected for {req.endpoint_id}: {guard_reason}")

    tool_allowed, tool_action, tool_reason, tool_rules, tool_risk_delta = await verify_tool_call_with_llm_guard(req)
    if not tool_allowed or tool_action == "block":
        req.risk_zone = "blocked"
        req.risk_score = max(req.risk_score, 1.5)
        logger.warning(f"LLM tool/API call blocked for {req.endpoint_id}: {tool_reason}")
    elif tool_action == "challenge_mfa" and req.risk_zone == "normal":
        req.risk_zone = "elevated"
        req.risk_score = max(req.risk_score, 0.6)
        logger.warning(f"LLM tool/API call requires MFA for {req.endpoint_id}: {tool_reason}")

    # risk_engine is the source of truth for risk zoning.
    # response_orchestrator maps the already computed zone to an action.
    # llm_guard can only escalate the zone for LLM/tool misuse.
    effective_zone = req.risk_zone

    if effective_zone == "blocked":
        action = Action.BLOCK
        duration = BLOCK_DURATIONS["blocked"]
        message = f"Request blocked due to risk zone {effective_zone} and score {req.risk_score}"
        block_key = f"block:{req.endpoint_id}:{req.user_id}"
        redis_client.setex(block_key, duration, "blocked")
    elif effective_zone == "elevated":
        action = Action.CHALLENGE
        duration = BLOCK_DURATIONS["elevated"]
        message = "Risk elevated, MFA challenge required"
        mfa_key = f"mfa_pending:{req.user_id}"
        redis_client.setex(mfa_key, duration, req.endpoint_id)
    else:
        effective_zone = "normal"
        action = Action.ALLOW
        duration = 0
        message = "Request allowed"

    vuln_details = []
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            vu_resp = await client.get(f"http://vuln_context:8000/vuln/{req.endpoint_id}", timeout=1.0)
            if vu_resp.status_code == 200:
                vu_data = vu_resp.json()
                vuln_details = (vu_data.get("findings") or []) + (vu_data.get("related_findings") or [])
    except Exception as e:
        logger.warning(f"Could not fetch vuln details: {e}")

    incident = {
        "risk_score": req.risk_score,
        "risk_zone": effective_zone,
        "endpoint_id": req.endpoint_id,
        "user_id": req.user_id,
        "action": action.value,
        "message": message,
        "block_duration": duration,
        "vulnerability_details": vuln_details,
        "llm_tool_guard": {
            "tool_name": req.tool_name,
            "tool_endpoint": req.tool_endpoint,
            "action": tool_action,
            "reason": tool_reason,
            "matched_rules": tool_rules,
            "risk_delta": tool_risk_delta,
        }
    }
    redis_client.lpush("incidents", json.dumps(incident))

    logger.info(f"Decision: {action}, message: {message}")

    ORCHESTRATOR_DECISIONS_TOTAL.labels(action=action.value, zone=effective_zone).inc()
    ORCHESTRATOR_LLM_GUARD_TOTAL.labels(action=str(tool_action or "allow")).inc()
    return DecisionResponse(action=action, message=message, block_duration_seconds=duration)

@app.get("/health")
async def health():
    return {"status": "ok"}
