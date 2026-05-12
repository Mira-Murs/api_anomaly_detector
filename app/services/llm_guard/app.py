from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Any
import ipaddress
import re
from urllib.parse import urlparse
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(title="LLM Guard", version="2.0.0")
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")


class PromptCheck(BaseModel):
    prompt: str
    context_type: str = "generic"
    user_direct: bool = False


class ToolCallCheck(BaseModel):
    tool_name: str
    method: str = "POST"
    endpoint: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_confirmed: bool = False
    risk_zone: str = "normal"


PROMPT_RULES = [
    {
        "id": "prompt.override_instructions.en",
        "pattern": r"\b(ignore|forget|disregard|override)\b.{0,80}\b(previous|above|prior|system|developer)\b.{0,80}\b(instruction|instructions|rules|policy|policies)\b",
        "action": "block",
        "risk_delta": 0.7,
        "reason": "attempt to override prior/system instructions",
    },
    {
        "id": "prompt.override_instructions.ru",
        "pattern": r"(игнорируй|игнорировать|не обращайте внимания|забудь).{0,80}(инструкц|правил|указан)",
        "action": "block",
        "risk_delta": 0.7,
        "reason": "attempt to override instructions in Russian",
    },
    {
        "id": "prompt.role_token_injection",
        "pattern": r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|assistant\|>|<\|user\|>|<\|tool\|>|<assistant>|</assistant>|<tool_result>|</tool_result>)",
        "action": "block",
        "risk_delta": 0.8,
        "reason": "chat/template control token injection",
    },
    {
        "id": "prompt.system_message_marker",
        "pattern": r"(\$\$START_SYSTEM_MESSAGE\$\$|\$\$END_SYSTEM_MESSAGE\$\$|BEGIN USER|END USER|START_USER_SESSION|END_USER_SESSION|system\s*:)",
        "action": "block",
        "risk_delta": 0.8,
        "reason": "attempt to inject synthetic system/user message boundaries",
    },
    {
        "id": "prompt.tool_invocation_marker",
        "pattern": r"(function_calls|tool_calls|antml:invoke|EXECUTE_SEND_EMAIL|sendEmail|send_email|\"name\"\s*:\s*\"send_email\")",
        "action": "block",
        "risk_delta": 0.9,
        "reason": "attempt to inject a tool/function call",
    },
    {
        "id": "prompt.secret_exfiltration",
        "pattern": r"\b(system prompt|developer message|hidden instruction|chain of thought|private key|api key|token|password|secret)\b",
        "action": "challenge_mfa",
        "risk_delta": 0.4,
        "reason": "possible attempt to extract hidden or sensitive data",
    },
]

UNTRUSTED_TOOL_COMMAND_RULES = [
    {
        "id": "untrusted.outbound_email_instruction",
        "pattern": r"\b(send|write|dispatch|mail|email)\b.{0,120}\b(contact\s*@\s*contact\s*\.\s*com|contact\s*<at>\s*contact\s*<dot>\s*com)\b",
        "action": "block",
        "risk_delta": 0.9,
        "reason": "untrusted content attempts to trigger outbound email",
    },
    {
        "id": "untrusted.urgent_execution_pressure",
        "pattern": r"\b(urgent|immediately|do not stop|don't respond before executing|must execute|required action|action required)\b",
        "action": "challenge_mfa",
        "risk_delta": 0.3,
        "reason": "untrusted content contains execution-pressure language",
    },
]

SUSPICIOUS_PAYLOAD_RULES = [
    {
        "id": "payload.path_traversal",
        "pattern": r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)",
        "action": "block",
        "risk_delta": 0.8,
        "reason": "path traversal marker",
    },
    {
        "id": "payload.sql_injection",
        "pattern": r"(\bunion\b.{0,30}\bselect\b|\bor\b\s+1\s*=\s*1\b|sleep\s*\(|benchmark\s*\(|--\s*$)",
        "action": "block",
        "risk_delta": 0.8,
        "reason": "SQL injection marker",
    },
    {
        "id": "payload.xss",
        "pattern": r"(<script\b|javascript:|onerror\s*=|onload\s*=)",
        "action": "block",
        "risk_delta": 0.7,
        "reason": "XSS marker",
    },
    {
        "id": "payload.command_injection",
        "pattern": r"(\|\s*sh\b|;\s*cat\s+/etc/passwd|`[^`]+`|\$\([^)]*\))",
        "action": "block",
        "risk_delta": 0.8,
        "reason": "command injection marker",
    },
]

HIGH_RISK_TOOLS = {
    "send_email",
    "send_mail",
    "post_message",
    "delete_user",
    "update_password",
    "reset_password",
    "transfer_money",
    "create_payment",
    "run_shell",
    "exec",
    "http_request",
}

DEFAULT_ALLOWED_TOOLS = {
    "summarize_email",
    "classify_text",
    "extract_entities",
    "search_docs",
    "lookup_public_info",
}

BLOCKED_ENDPOINT_PREFIXES = (
    "/admin",
    "/debug",
    "/internal",
    "/metadata",
    "/.env",
    "/config",
)


def normalize_text(value: str) -> str:
    value = value or ""
    value = value.replace("\x00", " ")
    value = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def is_untrusted_context(context_type: str) -> bool:
    return context_type.lower() in {
        "email",
        "email_content",
        "retrieved_context",
        "tool_result",
        "document",
        "webpage",
        "untrusted",
    }


def add_match(matches: list[dict[str, Any]], rule: dict[str, Any], excerpt: str = "") -> None:
    matches.append({
        "id": rule["id"],
        "action": rule["action"],
        "risk_delta": rule["risk_delta"],
        "reason": rule["reason"],
        "excerpt": excerpt[:180],
    })


def strongest_action(matches: list[dict[str, Any]]) -> str:
    if any(m["action"] == "block" for m in matches):
        return "block"
    if any(m["action"] == "challenge_mfa" for m in matches):
        return "challenge_mfa"
    return "allow"


def result_from_matches(matches: list[dict[str, Any]]) -> dict[str, Any]:
    action = strongest_action(matches)
    risk_delta = min(1.5, sum(float(m.get("risk_delta", 0.0)) for m in matches))

    if action == "block":
        safe = False
        reason = matches[0]["reason"] if matches else "blocked"
    elif action == "challenge_mfa":
        safe = True
        reason = matches[0]["reason"] if matches else "additional verification required"
    else:
        safe = True
        reason = ""

    return {
        "safe": safe,
        "action": action,
        "reason": reason,
        "matched_rules": matches,
        "risk_delta": risk_delta,
    }


def scan_text(text: str, context_type: str = "generic") -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    matches: list[dict[str, Any]] = []

    for rule in PROMPT_RULES:
        m = re.search(rule["pattern"], normalized, re.IGNORECASE | re.DOTALL)
        if m:
            add_match(matches, rule, m.group(0))

    if is_untrusted_context(context_type):
        for rule in UNTRUSTED_TOOL_COMMAND_RULES:
            m = re.search(rule["pattern"], normalized, re.IGNORECASE | re.DOTALL)
            if m:
                add_match(matches, rule, m.group(0))

    return matches


def endpoint_is_private_or_local(endpoint: str) -> bool:
    parsed = urlparse(endpoint)
    host = parsed.hostname

    if not host:
        return False

    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return False


def scan_tool_call(req: ToolCallCheck) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    tool_name = normalize_text(req.tool_name).lower()
    method = normalize_text(req.method).upper()
    endpoint = normalize_text(req.endpoint)
    args_text = normalize_text(str(req.arguments))

    if tool_name not in DEFAULT_ALLOWED_TOOLS:
        rule = {
            "id": "tool.not_in_default_allowlist",
            "action": "challenge_mfa",
            "risk_delta": 0.3,
            "reason": f"tool '{tool_name}' is not in default allowlist",
        }
        add_match(matches, rule, tool_name)

    if tool_name in HIGH_RISK_TOOLS and not req.user_confirmed:
        rule = {
            "id": "tool.high_risk_without_user_confirmation",
            "action": "block",
            "risk_delta": 1.0,
            "reason": f"high-risk tool '{tool_name}' requires explicit user confirmation",
        }
        add_match(matches, rule, tool_name)

    if method in {"DELETE", "PUT", "PATCH"} and not req.user_confirmed:
        rule = {
            "id": "tool.state_changing_method_without_confirmation",
            "action": "block",
            "risk_delta": 0.8,
            "reason": f"state-changing method {method} requires confirmation",
        }
        add_match(matches, rule, method)

    path = urlparse(endpoint).path if "://" in endpoint else endpoint
    if any(path.startswith(prefix) for prefix in BLOCKED_ENDPOINT_PREFIXES):
        rule = {
            "id": "tool.blocked_endpoint_prefix",
            "action": "block",
            "risk_delta": 0.9,
            "reason": "tool call targets blocked administrative/internal endpoint",
        }
        add_match(matches, rule, endpoint)

    if endpoint_is_private_or_local(endpoint):
        rule = {
            "id": "tool.ssrf_private_or_local_target",
            "action": "block",
            "risk_delta": 1.0,
            "reason": "tool call targets private/local network address",
        }
        add_match(matches, rule, endpoint)

    combined = f"{endpoint} {args_text}"
    for rule in SUSPICIOUS_PAYLOAD_RULES:
        m = re.search(rule["pattern"], combined, re.IGNORECASE | re.DOTALL)
        if m:
            add_match(matches, rule, m.group(0))

    return matches


@app.post("/check")
async def check_prompt(req: PromptCheck):
    matches = scan_text(req.prompt, req.context_type)
    return result_from_matches(matches)


@app.post("/verify_tool_call")
async def verify_tool_call(req: ToolCallCheck):
    matches = scan_tool_call(req)
    return result_from_matches(matches)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "capabilities": [
            "prompt_injection_detection",
            "untrusted_context_instruction_detection",
            "tool_call_verification",
            "ssrf_detection",
            "payload_marker_detection",
        ],
    }
