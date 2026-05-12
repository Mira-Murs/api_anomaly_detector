from fastapi import FastAPI
from pydantic import BaseModel
import redis
import os
import json
import glob
import logging
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vuln_context")

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=6379,
    decode_responses=True
)

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/app/reports"))
DETAILS_TTL = int(os.getenv("DETAILS_TTL", "43200"))
V_BASE = float(os.getenv("V_BASE", "0.3"))

SEVERITY_TO_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "ERROR": 8.0,
    "MEDIUM": 5.0,
    "WARNING": 6.0,
    "LOW": 3.0,
    "INFO": 0.0,
    "UNKNOWN": 0.0,
}

ZAP_RISK_TO_CVSS = {
    "0": 0.0,
    "1": 3.0,
    "2": 5.0,
    "3": 8.0,
    "4": 9.5,
}


class VulnRequest(BaseModel):
    endpoint_id: str


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def norm_path(value: str) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if value.strip("/") == "__global__":
        return "__global__"
    if value.startswith("http://") or value.startswith("https://"):
        value = urlparse(value).path or "/"
    if not value.startswith("/"):
        value = "/" + value

    # Canonicalize route parameters:
    # /users/:username and /users/{username} must map to the same endpoint.
    parts = []
    for part in value.split("/"):
        if part.startswith(":") and len(part) > 1:
            parts.append("{" + part[1:] + "}")
        else:
            parts.append(part)
    value = "/".join(parts)

    return value


def norm_file_path(value: str) -> str:
    return str(value or "").replace("\\", "/").strip()


def compute_weight(cvss: float, exploitable: bool, base: float = V_BASE) -> float:
    value = (safe_float(cvss) / 10.0) * (1 + 0.5 * (1 if exploitable else 0))
    return round(max(base, value), 6)


def read_json(path: Path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def severity_to_cvss(severity: str) -> float:
    return SEVERITY_TO_CVSS.get(str(severity or "UNKNOWN").upper(), 0.0)


def dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in items or []:
        key = (
            item.get("source"),
            item.get("rule") or item.get("cve") or item.get("name") or item.get("title"),
            item.get("file") or item.get("url") or item.get("target"),
            item.get("line"),
            item.get("package"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def max_cvss(items: List[Dict[str, Any]]) -> float:
    return max((safe_float(x.get("cvss", 0.0)) for x in items or []), default=0.0)


def has_exploitable(items: List[Dict[str, Any]]) -> bool:
    return any(bool(x.get("exploitable")) for x in items or [])


def security_like_semgrep(item: Dict[str, Any]) -> bool:
    category = str(item.get("category") or "").lower()
    severity = str(item.get("severity") or "").upper()
    rule = str(item.get("rule") or "").lower()
    msg = str(item.get("message") or "").lower()
    text = rule + " " + msg

    if category == "security":
        return True

    words = [
        "injection", "secret", "password", "token", "api key", "apikey",
        "ssrf", "xss", "csrf", "unsafe", "exec", "eval", "prompt",
        "llm", "mcp", "hardcoded", "deserialization"
    ]
    return severity in {"ERROR", "WARNING"} or any(w in text for w in words)


def file_match(a: str, b: str) -> bool:
    a = norm_file_path(a).lstrip("/")
    b = norm_file_path(b).lstrip("/")
    if not a or not b:
        return False
    return a == b or a.endswith(b) or b.endswith(a)


def trivy_cvss(vuln: Dict[str, Any]) -> float:
    scores = []
    cvss = vuln.get("CVSS") or {}
    if isinstance(cvss, dict):
        for vendor_data in cvss.values():
            if isinstance(vendor_data, dict):
                for key in ("V3Score", "V2Score"):
                    if key in vendor_data:
                        scores.append(safe_float(vendor_data.get(key), 0.0))
    if scores:
        return max(scores)
    return severity_to_cvss(vuln.get("Severity"))


def load_noir_endpoints() -> Dict[str, Dict[str, Any]]:
    endpoints = {}
    for filename in glob.glob(str(REPORTS_DIR / "api_endpoints*.json")):
        try:
            data = read_json(Path(filename))
        except Exception as e:
            logger.warning("Cannot parse Noir report %s: %s", filename, e)
            continue

        raw = data.get("endpoints", []) if isinstance(data, dict) else data
        for ep in raw or []:
            if not isinstance(ep, dict):
                continue
            url = norm_path(ep.get("url", ""))
            if not url:
                continue

            details = ep.get("details", {}) or {}
            code_paths = []
            for cp in details.get("code_paths", []) or []:
                if isinstance(cp, dict):
                    path = cp.get("path", "")
                else:
                    path = str(cp)
                if path:
                    code_paths.append(norm_file_path(path))

            method = str(ep.get("method", "") or "").upper()
            technology = details.get("technology", "")

            if url not in endpoints:
                endpoints[url] = {
                    "endpoint_id": url,
                    "method": method,
                    "methods": [method] if method else [],
                    "code_paths": code_paths,
                    "technology": technology
                }
            else:
                existing = endpoints[url]

                if method and method not in existing.get("methods", []):
                    existing.setdefault("methods", []).append(method)

                # Keep method as a comma-separated display field, but do not let
                # repeated Noir entries overwrite endpoint context.
                existing["method"] = ",".join(existing.get("methods", []))

                for cp in code_paths:
                    if cp not in existing.get("code_paths", []):
                        existing.setdefault("code_paths", []).append(cp)

                if technology and not existing.get("technology"):
                    existing["technology"] = technology
    return endpoints


def load_semgrep() -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    all_items = []
    by_path = {}

    for filename in glob.glob(str(REPORTS_DIR / "semgrep*.json")):
        try:
            data = read_json(Path(filename))
        except Exception as e:
            logger.warning("Cannot parse Semgrep report %s: %s", filename, e)
            continue

        for finding in data.get("results", []) or []:
            if not isinstance(finding, dict):
                continue

            path = norm_file_path(finding.get("path", ""))
            extra = finding.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            severity = extra.get("severity", "INFO")
            cvss = safe_float(metadata.get("cvss"), severity_to_cvss(severity))

            item = {
                "source": "semgrep",
                "file": path,
                "line": (finding.get("start") or {}).get("line"),
                "rule": finding.get("check_id", ""),
                "message": extra.get("message", ""),
                "severity": severity,
                "category": metadata.get("category"),
                "confidence": metadata.get("confidence"),
                "technology": metadata.get("technology", []),
                "cvss": cvss
            }

            all_items.append(item)
            by_path.setdefault(path, []).append(item)

    return all_items, by_path


def load_trivy() -> List[Dict[str, Any]]:
    items = []

    for filename in glob.glob(str(REPORTS_DIR / "trivy*.json")):
        try:
            data = read_json(Path(filename))
        except Exception as e:
            logger.warning("Cannot parse Trivy report %s: %s", filename, e)
            continue

        for result in data.get("Results", []) or []:
            target = result.get("Target", "")
            result_type = result.get("Type", "")
            for vuln in result.get("Vulnerabilities", []) or []:
                cvss = trivy_cvss(vuln)
                items.append({
                    "source": "trivy",
                    "target": target,
                    "type": result_type,
                    "cve": vuln.get("VulnerabilityID", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "cvss": cvss
                })

    return items


def load_zap() -> List[Dict[str, Any]]:
    items = []

    primary_zap = REPORTS_DIR / "zap.json"
    zap_files = [primary_zap] if primary_zap.exists() else [Path(x) for x in glob.glob(str(REPORTS_DIR / "zap*.json"))]

    for filename in zap_files:
        try:
            data = read_json(Path(filename))
        except Exception as e:
            logger.warning("Cannot parse ZAP report %s: %s", filename, e)
            continue

        for site in data.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                riskcode = str(alert.get("riskcode", "0"))
                cvss = ZAP_RISK_TO_CVSS.get(riskcode, 0.0)

                urls = []
                if alert.get("url"):
                    urls.append(alert.get("url"))
                for inst in alert.get("instances", []) or []:
                    if isinstance(inst, dict) and inst.get("uri"):
                        urls.append(inst.get("uri"))

                if not urls:
                    urls = [""]

                for raw_url in urls:
                    items.append({
                        "source": "zap",
                        "url": raw_url,
                        "endpoint_id": norm_path(raw_url) if raw_url else "",
                        "name": alert.get("name", ""),
                        "alert": alert.get("alert") or alert.get("name", ""),
                        "riskdesc": alert.get("riskdesc", ""),
                        "riskcode": riskcode,
                        "confidence": alert.get("confidence", ""),
                        "cweid": alert.get("cweid", ""),
                        "description": alert.get("desc", ""),
                        "solution": alert.get("solution", ""),
                        "cvss": cvss,
                        "exploitable": cvss >= 5.0
                    })

    return items


def cve_applicable_to_endpoint(vuln: Dict[str, Any], meta: Dict[str, Any]) -> bool:
    """Conservative dependency-to-endpoint correlation for the prototype.

    A CVE is endpoint-applicable only when the endpoint has discovered code
    context and the vulnerable package belongs to the runtime stack that serves
    the endpoint. This prevents project-wide CVEs from being blindly attached
    to every endpoint while still allowing framework-level CVEs to influence
    endpoints served by that framework.
    """
    package = str(vuln.get("package") or "").lower()
    technology = str(meta.get("technology") or "").lower()
    code_paths = meta.get("code_paths", []) or []

    if not package:
        return False

    # Without endpoint code context, keep CVE project-wide only.
    if not code_paths and not technology:
        return False

    runtime_packages = {
        "flask",
        "werkzeug",
        "jinja2",
        "itsdangerous",
        "pyjwt",
        "jwt",
        "requests",
        "urllib3",
    }

    if package in runtime_packages:
        return True

    # Technology hints from API discovery may mention the framework directly.
    if package and package in technology:
        return True

    return False


def select_applicable_cves(meta: Dict[str, Any], trivy_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    selected = []
    for vuln in trivy_items:
        if cve_applicable_to_endpoint(vuln, meta):
            item = dict(vuln)
            item["applicability"] = "dependency_used_by_endpoint_runtime_stack"
            selected.append(item)
    return dedupe(selected)


def zap_actionable_for_endpoint(item: Dict[str, Any]) -> bool:
    """Return True only for DAST findings that are useful for endpoint risk context."""
    try:
        riskcode = int(str(item.get("riskcode", "0")))
    except Exception:
        riskcode = 0

    try:
        cweid = int(str(item.get("cweid", "-1")))
    except Exception:
        cweid = -1

    # riskcode=0 contains informational ZAP observations such as
    # "Authentication Request Identified" or cacheability noise.
    # cweid=-1 is not a real weakness classification.
    return riskcode > 0 and cweid > 0


def select_endpoint_findings(endpoint_id: str, meta: Dict[str, Any], semgrep_by_path: Dict[str, List[Dict[str, Any]]], zap_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    selected = []

    for cp in meta.get("code_paths", []) or []:
        for path, findings in semgrep_by_path.items():
            if file_match(cp, path):
                selected.extend([x for x in findings if security_like_semgrep(x)])

    endpoint = norm_path(endpoint_id)
    for item in zap_items:
        if norm_path(item.get("endpoint_id", "")) == endpoint and zap_actionable_for_endpoint(item):
            selected.append(item)

    return dedupe(selected)


def store_endpoint(endpoint_id: str, payload: Dict[str, Any]) -> None:
    endpoint_id = norm_path(endpoint_id)

    findings = dedupe(payload.get("findings", []) or [])
    related = dedupe(payload.get("related_findings", []) or [])
    scope = payload.get("scope", "endpoint")

    # applicable_findings are the findings proven usable for this endpoint
    # by the correlation layer. Reports and endpoint risk must use this field,
    # not raw project-wide related_findings.
    applicable = dedupe(payload.get("applicable_findings", findings) or [])

    # Global context can still use all global findings for project-wide view.
    # Endpoint context is weighted only by applicable endpoint findings.
    findings_for_weight = dedupe(findings + related) if scope == "global" else applicable

    cvss = max_cvss(findings_for_weight)
    exploitable = bool(payload.get("exploitable", False)) or has_exploitable(findings_for_weight)
    weight = compute_weight(cvss, exploitable)

    payload["endpoint_id"] = endpoint_id
    payload["findings"] = findings
    payload["applicable_findings"] = applicable
    payload["related_findings"] = related
    payload["cvss"] = cvss
    payload["exploitable"] = exploitable
    payload["vulnerability_weight"] = weight

    redis_client.setex(f"vuln_weight:{endpoint_id}", DETAILS_TTL, str(weight))
    redis_client.setex(f"vuln_details:{endpoint_id}", DETAILS_TTL, json.dumps(payload, ensure_ascii=False))


def clear_vuln_cache() -> None:
    for key in list(redis_client.scan_iter("vuln_weight:*")):
        redis_client.delete(key)
    for key in list(redis_client.scan_iter("vuln_details:*")):
        redis_client.delete(key)


def load_reports() -> Dict[str, int]:
    endpoints = load_noir_endpoints()
    semgrep_all, semgrep_by_path = load_semgrep()
    trivy_items = load_trivy()
    zap_items = load_zap()

    semgrep_security = [x for x in semgrep_all if security_like_semgrep(x)]
    # Project-wide context includes CVE, security-relevant SAST and DAST findings.
    # ZAP findings are also kept endpoint-specific through select_endpoint_findings().
    global_findings = dedupe(trivy_items + semgrep_security + zap_items)

    store_endpoint("__global__", {
        "endpoint_id": "__global__",
        "scope": "global",
        "method": "",
        "code_paths": [],
        "findings": global_findings,
        "related_findings": [],
        "exploitable": has_exploitable(zap_items),
        "mapping_confidence": "global"
    })

    if not endpoints:
        endpoints = {
            "/": {
                "endpoint_id": "/",
                "method": "",
                "code_paths": [],
                "technology": ""
            }
        }

    for endpoint_id, meta in endpoints.items():
        exact = select_endpoint_findings(endpoint_id, meta, semgrep_by_path, zap_items)
        applicable_cves = select_applicable_cves(meta, trivy_items)
        applicable = dedupe(exact + applicable_cves)

        store_endpoint(endpoint_id, {
            "endpoint_id": endpoint_id,
            "scope": "endpoint",
            "method": meta.get("method", ""),
            "code_paths": meta.get("code_paths", []),
            "findings": exact,
            "applicable_findings": applicable,
            "related_findings": global_findings,
            "exploitable": has_exploitable(applicable),
            "mapping_confidence": "exact" if applicable else "global"
        })

    counts = {
        "endpoints": len(endpoints),
        "semgrep": len(semgrep_all),
        "security_semgrep": len(semgrep_security),
        "trivy": len(trivy_items),
        "zap": len(zap_items),
        "global_findings": len(global_findings)
    }
    logger.info("Loaded vulnerability context: %s", counts)
    return counts


def get_details(endpoint_id: str) -> Dict[str, Any]:
    endpoint_id = norm_path(endpoint_id)

    raw = redis_client.get(f"vuln_details:{endpoint_id}")
    if raw:
        return json.loads(raw)

    # Unknown endpoints must not inherit project-wide findings as applicable
    # vulnerability context. Global findings are useful as related context in
    # reports, but they must not increase runtime risk for an unmapped endpoint.
    global_raw = redis_client.get("vuln_details:__global__")
    related_findings = []

    if global_raw:
        try:
            global_details = json.loads(global_raw)
            related_findings = dedupe(
                (global_details.get("findings") or []) +
                (global_details.get("related_findings") or [])
            )
        except Exception:
            related_findings = []

    return {
        "vulnerability_weight": V_BASE,
        "cvss": 0.0,
        "findings": [],
        "applicable_findings": [],
        "related_findings": related_findings,
        "exploitable": False,
        "mapping_confidence": "global_related_only",
        "scope": "global_related_only"
    }


def build_response(endpoint_id: str) -> Dict[str, Any]:
    details = get_details(endpoint_id)
    findings = details.get("findings", []) or []
    applicable = details.get("applicable_findings", []) or findings
    related = details.get("related_findings", []) or []

    # Endpoint response must keep applicable endpoint findings separate from
    # informational project-wide related_findings.
    scope = details.get("scope", "endpoint")
    findings_for_score = dedupe(findings + related) if scope == "global" else applicable

    cvss = max_cvss(findings_for_score)
    exploitable = bool(details.get("exploitable", False)) or has_exploitable(findings_for_score)
    weight = safe_float(details.get("vulnerability_weight"), compute_weight(cvss, exploitable))

    return {
        "vulnerability_weight": weight,
        "cvss": cvss,
        "findings": findings,
        "applicable_findings": applicable,
        "related_findings": related,
        "exploitable": exploitable,
        "mapping_confidence": details.get("mapping_confidence", "global")
    }


@app.on_event("startup")
def startup():
    logger.info("REPORTS_DIR=%s exists=%s", REPORTS_DIR, REPORTS_DIR.exists())
    if REPORTS_DIR.exists() and any(REPORTS_DIR.glob("*.json")):
        load_reports()
    else:
        logger.warning("No JSON reports found in %s", REPORTS_DIR)


@app.post("/vuln")
async def post_vuln(req: VulnRequest):
    return build_response(req.endpoint_id)


@app.get("/vuln/{endpoint_id:path}")
async def get_vuln(endpoint_id: str):
    return build_response(endpoint_id)


@app.post("/reload")
async def reload_reports():
    clear_vuln_cache()
    counts = load_reports()
    return {"status": "reloaded", "counts": counts}


@app.get("/debug/keys")
async def debug_keys():
    return {
        "vuln_weight_keys": list(redis_client.scan_iter("vuln_weight:*"))[:100],
        "vuln_details_keys": list(redis_client.scan_iter("vuln_details:*"))[:100]
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
