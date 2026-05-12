import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
REPORTS = PROJECT_ROOT / "artifacts" / "reports"

def norm_path(p):
    if not p:
        return ""
    p = str(p).strip()
    return p if p.startswith("/") else "/" + p

def compute_weight(cvss, exploitable, base=0.3):
    return max(base, (cvss / 10.0) * (1 + 0.5 * (1 if exploitable else 0)))

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_noir():
    path = REPORTS / "api_endpoints.json"
    if not path.exists():
        return []
    data = load_json(path)
    return data.get("endpoints", [])

def load_semgrep():
    path = REPORTS / "semgrep.json"
    if not path.exists():
        return []
    data = load_json(path)
    return data.get("results", [])

def load_trivy():
    path = REPORTS / "trivy.json"
    if not path.exists():
        return []
    data = load_json(path)
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            cvss_info = vuln.get("CVSS", {})
            cvss = cvss_info.get("nvd", {}).get(
                "V3Score",
                cvss_info.get("ghsa", {}).get(
                    "V3Score",
                    cvss_info.get("redhat", {}).get("V3Score", 0.0)
                )
            )
            findings.append({
                "source": "trivy",
                "scope": "global",
                "target": target,
                "package": vuln.get("PkgName", ""),
                "cve": vuln.get("VulnerabilityID", ""),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cvss": cvss,
                "fixed_version": vuln.get("FixedVersion", ""),
                "description": vuln.get("Description", "")
            })
    return findings

def semgrep_to_entry(f):
    metadata = f.get("extra", {}).get("metadata", {}) or {}
    cvss = 5.0
    if "cvss" in metadata:
        try:
            cvss = float(metadata["cvss"])
        except Exception:
            pass
    return {
        "source": "semgrep",
        "scope": "endpoint",
        "file": f.get("path", ""),
        "line": f.get("start", {}).get("line", ""),
        "rule": f.get("check_id", ""),
        "message": f.get("extra", {}).get("message", ""),
        "severity": f.get("extra", {}).get("severity", "INFO"),
        "cvss": cvss
    }

def build_context():
    endpoints = load_noir()
    semgrep = load_semgrep()
    trivy = load_trivy()

    semgrep_by_path = {}
    for finding in semgrep:
        path = finding.get("path", "")
        semgrep_by_path.setdefault(path, []).append(semgrep_to_entry(finding))

    endpoint_context = {}
    for ep in endpoints:
        url = norm_path(ep.get("url", ""))
        details = ep.get("details", {}) or {}
        code_paths = [cp.get("path", "") for cp in details.get("code_paths", []) or [] if cp.get("path")]
        endpoint_findings = []
        for cp in code_paths:
            endpoint_findings.extend(semgrep_by_path.get(cp, []))
        combined = endpoint_findings + trivy
        max_cvss = max((f.get("cvss", 0) for f in combined), default=0.0)
        exploitable = False
        endpoint_context[url] = {
            "endpoint_id": url,
            "method": ep.get("method", ""),
            "code_paths": code_paths,
            "findings": combined,
            "endpoint_findings_count": len(endpoint_findings),
            "global_findings_count": len(trivy),
            "cvss": max_cvss,
            "exploitable": exploitable,
            "vulnerability_weight": compute_weight(max_cvss, exploitable)
        }

    global_findings = []
    for url, item in endpoint_context.items():
        global_findings.extend(item.get("findings", []))

    global_cvss = max((f.get("cvss", 0) for f in global_findings), default=0.0)
    result = {
        "meta": {
            "generated_from": ["api_endpoints.json", "semgrep.json", "trivy.json"],
            "zap_included": False,
            "reason": "artifacts/reports/zap.json is HTML report, not JSON"
        },
        "endpoints": endpoint_context,
        "__global__": {
            "findings": trivy,
            "cvss": max((f.get("cvss", 0) for f in trivy), default=0.0),
            "exploitable": False,
            "vulnerability_weight": compute_weight(max((f.get("cvss", 0) for f in trivy), default=0.0), False)
        }
    }

    out = REPORTS / "endpoint_context.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(out)
    print("endpoints:", len(endpoint_context))
    print("global_trivy_findings:", len(trivy))

if __name__ == "__main__":
    build_context()
