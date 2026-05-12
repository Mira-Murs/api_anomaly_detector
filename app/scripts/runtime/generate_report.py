import redis
import json
import os
import re
from datetime import datetime
from pathlib import Path

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports"))
RECOMMENDED_FIXES_FILE = REPORTS_DIR / "recommended_fixes.yaml"
MAX_ENDPOINT_FINDINGS = int(os.getenv("MAX_ENDPOINT_FINDINGS", "5"))
MAX_GLOBAL_FINDINGS = int(os.getenv("MAX_GLOBAL_FINDINGS", "8"))

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "ERROR": 4,
    "MEDIUM": 3,
    "WARNING": 2,
    "LOW": 1,
    "INFO": 0,
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def safe_json_loads(value, default):
    try:
        return json.loads(value) if value else default
    except Exception:
        return default


def extract_cves(finding):
    """
    Extract CVE identifiers from any scanner finding.

    Trivy is the primary CVE source, but Semgrep or ZAP may also include CVE
    references in rule IDs, messages, descriptions or metadata. If the same CVE
    appears in multiple tools, it must be counted once in the unique finding
    summary.
    """
    values = []

    for key in ("cve", "id", "rule", "message", "description", "title", "alert"):
        value = finding.get(key)
        if value:
            values.append(str(value))

    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        for value in metadata.values():
            if isinstance(value, (str, int, float)):
                values.append(str(value))
            elif isinstance(value, list):
                values.extend(str(x) for x in value)

    text = " ".join(values)
    return sorted({m.upper() for m in CVE_RE.findall(text)})


def finding_key(f):
    source = f.get("source", "")
    cves = extract_cves(f)

    # If any tool references a CVE, the CVE is the canonical identity.
    # This prevents double counting when both Trivy and Semgrep mention
    # the same CVE.
    if cves:
        package = (
            f.get("package")
            or f.get("component")
            or f.get("dependency")
            or f.get("target")
            or ""
        )
        return ("cve", tuple(cves), str(package).lower())

    if source == "trivy":
        return ("trivy", f.get("cve", ""), f.get("package", ""))

    if source == "semgrep":
        return ("semgrep", f.get("file", ""), f.get("line", ""), f.get("rule", ""))

    if source == "zap":
        # Count DAST findings by vulnerability category, not by every affected URL.
        # A single ZAP alert may appear on many endpoints; it should be one
        # unique finding in the executive summary, while affected URLs remain
        # available inside the raw ZAP report.
        alert = f.get("alert") or f.get("name") or ""
        return ("zap", alert, f.get("cweid", ""), f.get("riskcode", ""), f.get("riskdesc", ""))

    return (source, json.dumps(f, sort_keys=True, ensure_ascii=False))


def finding_group(f):
    """
    Group used only for report statistics.

    CVE references are counted as CVE findings even if they were surfaced by
    Semgrep. Non-CVE Semgrep findings remain SAST findings.
    """
    if extract_cves(f) or f.get("source") == "trivy":
        return "cve"
    if f.get("source") == "semgrep":
        return "sast"
    if f.get("source") == "zap":
        return "dast"
    return "other"


def dedupe_findings(items):
    result = []
    seen = set()

    for item in items:
        key = finding_key(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)

    return result


def finding_score(f):
    severity = str(f.get("severity") or f.get("risk") or "").upper()
    cvss = f.get("cvss")

    try:
        cvss = float(cvss)
    except Exception:
        cvss = 0.0

    return (cvss, SEVERITY_RANK.get(severity, 0))


def sort_findings(items):
    return sorted(dedupe_findings(items), key=finding_score, reverse=True)


def summarize_findings(items):
    unique = dedupe_findings(items)
    summary = {
        "unique_total": len(unique),
        "sast": 0,
        "cve": 0,
        "dast": 0,
        "dast_security": 0,
        "dast_informational": 0,
        "other": 0,
    }

    for item in unique:
        group = finding_group(item)
        summary[group] = summary.get(group, 0) + 1

        if group == "dast":
            try:
                riskcode = int(str(item.get("riskcode", "0")))
            except Exception:
                riskcode = 0

            if riskcode > 0:
                summary["dast_security"] += 1
            else:
                summary["dast_informational"] += 1

    return summary


def norm_endpoint_id(value: str) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if value.strip("/") == "__global__":
        return "__global__"
    if not value.startswith("/"):
        value = "/" + value

    parts = []
    for part in value.split("/"):
        if part.startswith(":") and len(part) > 1:
            parts.append("{" + part[1:] + "}")
        else:
            parts.append(part)

    return "/".join(parts)


def get_redis():
    return redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)


def get_details_from_redis(r, endpoint):
    endpoint = norm_endpoint_id(endpoint)
    candidates = [f"vuln_details:{endpoint}"]

    if endpoint and not endpoint.startswith("/"):
        candidates.append(f"vuln_details:/{endpoint}")

    for key in candidates:
        raw = r.get(key)
        if raw:
            return safe_json_loads(raw, {})

    return {}


def get_global_details(r):
    raw = r.get("vuln_details:__global__")
    return safe_json_loads(raw, {}) if raw else {}


def incident_key(i):
    endpoint = norm_endpoint_id(i.get("endpoint_id", ""))
    return (endpoint, i.get("user_id", ""), i.get("action", ""))


def load_unique_incidents(r):
    unique = {}

    for line in r.lrange("incidents", 0, -1):
        incident = safe_json_loads(line, None)
        if not incident:
            continue

        key = incident_key(incident)
        incident["endpoint_id"] = key[0]

        if key not in unique or float(incident.get("risk_score", 0)) > float(unique[key].get("risk_score", 0)):
            unique[key] = incident

    return unique


def format_finding_line(d):
    if d.get("source") == "semgrep":
        return f"SAST: {d.get('file','')}:{d.get('line','')} [{d.get('severity','')}] {d.get('rule','')}"

    if d.get("source") == "zap":
        return f"DAST: {d.get('url','')} [{d.get('risk','')}] {d.get('alert','')} (CWE: {d.get('cweid','')})"

    if d.get("source") == "trivy":
        return f"CVE: {d.get('cve','')} CVSS:{d.get('cvss','')} Package:{d.get('package','')}"

    cves = extract_cves(d)
    if cves:
        return f"CVE: {', '.join(cves)} Source:{d.get('source','unknown')}"

    return f"{d.get('source','unknown')}: {d}"


def finding_message(d):
    return d.get("message") or d.get("description") or d.get("title") or ""


def recommendation_for_finding(d):
    if d.get("source") == "semgrep":
        location = d.get("file", "unknown file")
        return f"Fix in {location}: {finding_message(d)}"

    if d.get("source") == "trivy":
        package = d.get("package", "unknown package")
        cve = d.get("cve", "unknown CVE")
        fixed = d.get("fixed_version")

        if fixed:
            return f"Upgrade {package} to {fixed} to fix {cve}"

        return f"Upgrade or replace {package} to remediate {cve}"

    if d.get("source") == "zap":
        alert = d.get("alert", "DAST finding")
        url = d.get("url", "affected endpoint")
        return f"Remediate DAST finding on {url}: {alert}"

    return f"Review finding: {format_finding_line(d)}"


def yaml_scalar(value):
    text = "" if value is None else str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def finding_location(d):
    if d.get("source") == "semgrep":
        file = d.get("file") or "unknown file"
        line = d.get("line")
        return f"{file}:{line}" if line else file

    if d.get("source") == "zap":
        return d.get("url") or d.get("endpoint_id") or "affected endpoint"

    if d.get("source") == "trivy":
        package = d.get("package") or "unknown package"
        target = d.get("target") or ""
        return f"{target}:{package}" if target else package

    return d.get("location") or d.get("file") or d.get("url") or "unknown"


def finding_cwe(d):
    cwe = d.get("cweid") or d.get("cwe") or ""
    if cwe in ("", "-1", -1, None):
        return "-"
    text = str(cwe)
    return text if text.upper().startswith("CWE-") else f"CWE-{text}"


def finding_cve_text(d):
    cves = extract_cves(d)
    if cves:
        return ", ".join(cves)
    return d.get("cve") or "-"


def write_finding_object(lines, d, indent="      "):
    lines.append(f"{indent}- source: {yaml_scalar(d.get('source', 'unknown'))}")
    lines.append(f"{indent}  group: {yaml_scalar(finding_group(d))}")
    lines.append(f"{indent}  finding: {yaml_scalar(format_finding_line(d))}")
    lines.append(f"{indent}  location: {yaml_scalar(finding_location(d))}")
    lines.append(f"{indent}  cve: {yaml_scalar(finding_cve_text(d))}")
    lines.append(f"{indent}  cwe: {yaml_scalar(finding_cwe(d))}")
    lines.append(f"{indent}  recommendation: {yaml_scalar(recommendation_for_finding(d))}")

    if d.get("package"):
        lines.append(f"{indent}  package: {yaml_scalar(d.get('package'))}")

    if d.get("fixed_version"):
        lines.append(f"{indent}  fixed_version: {yaml_scalar(d.get('fixed_version'))}")


def severity_rank(value, order):
    return order.get(str(value or "").lower(), -1)


def dedupe_text(values):
    result = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def finding_key(finding):
    return (
        str(finding.get("source", "")),
        str(finding.get("group", "")),
        str(finding.get("finding", "")),
        str(finding.get("location", "")),
        str(finding.get("cve", "")),
        str(finding.get("cwe", "")),
    )


def build_remediation_targets(fixes):
    action_order = {"allow": 0, "challenge_mfa": 1, "block": 2}
    zone_order = {"normal": 0, "elevated": 1, "blocked": 2}

    targets = {}

    for item in fixes:
        endpoint = item.get("endpoint", "unknown")
        target = targets.setdefault(endpoint, {
            "endpoint": endpoint,
            "affected_users": [],
            "max_risk_score": 0.0,
            "highest_risk_zone": "normal",
            "strongest_action": "allow",
            "findings": [],
            "recommendations": [],
            "risk_prioritized": [],
        })

        user = str(item.get("user", "")).strip()
        if user and user not in target["affected_users"]:
            target["affected_users"].append(user)

        risk_score = float(item.get("risk_score", 0.0) or 0.0)
        target["max_risk_score"] = max(target["max_risk_score"], risk_score)

        risk_zone = item.get("risk_zone", "normal")
        if severity_rank(risk_zone, zone_order) > severity_rank(target["highest_risk_zone"], zone_order):
            target["highest_risk_zone"] = risk_zone

        action = item.get("action", "allow")
        if severity_rank(action, action_order) > severity_rank(target["strongest_action"], action_order):
            target["strongest_action"] = action

        existing_finding_keys = {finding_key(f) for f in target["findings"]}
        for finding in item.get("findings") or []:
            key = finding_key(finding)
            if key not in existing_finding_keys:
                existing_finding_keys.add(key)
                target["findings"].append(finding)

        target["recommendations"].extend(item.get("recommendations") or [])
        target["risk_prioritized"].extend(item.get("risk_prioritized") or [])

    result = []
    for target in targets.values():
        target["affected_users"] = sorted(target["affected_users"])
        target["recommendations"] = dedupe_text(target["recommendations"])
        target["risk_prioritized"] = dedupe_text(target["risk_prioritized"])
        target["findings"] = sort_findings(target["findings"])
        result.append(target)

    return sorted(
        result,
        key=lambda item: (
            severity_rank(item["strongest_action"], action_order),
            severity_rank(item["highest_risk_zone"], zone_order),
            item["max_risk_score"],
            item["endpoint"],
        ),
        reverse=True,
    )


def write_recommended_fixes(fixes, global_findings, report_summary):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append(f"generated_at: {yaml_scalar(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))}")
    lines.append("summary:")
    lines.append(f"  unique_vulnerabilities: {report_summary['unique_total']}")
    lines.append(f"  sast_findings: {report_summary['sast']}")
    lines.append(f"  cve_findings: {report_summary['cve']}")
    lines.append(f"  dast_findings: {report_summary['dast']}")
    lines.append(f"  dast_security_findings: {report_summary['dast_security']}")
    lines.append(f"  dast_informational_findings: {report_summary['dast_informational']}")
    lines.append(f"  risk_prioritized_findings: {report_summary['risk_prioritized']}")

    lines.append("incidents:")

    if not fixes:
        lines.append("  []")
    else:
        for item in fixes:
            lines.append(f"  - endpoint: {yaml_scalar(item['endpoint'])}")
            lines.append(f"    user: {yaml_scalar(item['user'])}")
            lines.append(f"    risk_score: {item['risk_score']:.3f}")
            lines.append(f"    risk_zone: {yaml_scalar(item['risk_zone'])}")
            lines.append(f"    action: {yaml_scalar(item['action'])}")

            structured_findings = item.get("findings") or []
            lines.append("    findings:")
            if not structured_findings:
                lines.append("      []")
            else:
                for finding in structured_findings:
                    write_finding_object(lines, finding, indent="      ")

            correlated = item.get("risk_prioritized") or []
            lines.append("    risk_prioritized:")
            if not correlated:
                lines.append("      []")
            else:
                for finding in correlated:
                    lines.append(f"      - {yaml_scalar(finding)}")

            lines.append("    recommendations:")
            for rec in item["recommendations"]:
                lines.append(f"      - {yaml_scalar(rec)}")

    lines.append("remediation_targets:")
    remediation_targets = build_remediation_targets(fixes)
    if not remediation_targets:
        lines.append("  []")
    else:
        for target in remediation_targets:
            lines.append(f"  - endpoint: {yaml_scalar(target['endpoint'])}")
            lines.append("    affected_users:")
            if not target["affected_users"]:
                lines.append("      []")
            else:
                for user in target["affected_users"]:
                    lines.append(f"      - {yaml_scalar(user)}")
            lines.append(f"    max_risk_score: {target['max_risk_score']:.3f}")
            lines.append(f"    highest_risk_zone: {yaml_scalar(target['highest_risk_zone'])}")
            lines.append(f"    strongest_action: {yaml_scalar(target['strongest_action'])}")

            lines.append("    findings:")
            if not target["findings"]:
                lines.append("      []")
            else:
                for finding in target["findings"]:
                    write_finding_object(lines, finding, indent="      ")

            lines.append("    risk_prioritized:")
            if not target["risk_prioritized"]:
                lines.append("      []")
            else:
                for finding in target["risk_prioritized"]:
                    lines.append(f"      - {yaml_scalar(finding)}")

            lines.append("    recommendations:")
            if not target["recommendations"]:
                lines.append("      []")
            else:
                for rec in target["recommendations"]:
                    lines.append(f"      - {yaml_scalar(rec)}")

    lines.append("project_wide_fixes:")
    selected_global = sort_findings(global_findings)[:MAX_GLOBAL_FINDINGS]

    if not selected_global:
        lines.append("  []")
    else:
        for d in selected_global:
            write_finding_object(lines, d, indent="  ")

    RECOMMENDED_FIXES_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    r = get_redis()
    unique = load_unique_incidents(r)
    filtered = {k: v for k, v in unique.items() if v.get("action") != "allow"}

    global_details = get_global_details(r)
    global_findings = global_details.get("findings", []) or []

    fixes_for_yaml = []
    all_report_findings = list(global_findings)
    risk_prioritized_keys = set()
    risk_prioritized_lines = []

    print("======== ML-BASED ANOMALY DETECTION REPORT ========")
    print(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

    if not filtered:
        print("No critical or suspicious incidents recorded.")
    else:
        print("--- Prioritized Incidents ---")

        for i in sorted(filtered.values(), key=lambda x: float(x.get("risk_score", 0)), reverse=True):
            endpoint = norm_endpoint_id(i.get("endpoint_id", ""))
            action = i.get("action", "")
            risk_score = float(i.get("risk_score", 0))
            risk_zone = i.get("risk_zone", "")
            user = i.get("user_id", "")

            print(f"Endpoint: {endpoint}  Risk: {risk_score:.3f}  Zone: {risk_zone}  Action: {action}")
            print(f"  User: {user}  Reason: {i.get('message', '')}")

            details = get_details_from_redis(r, endpoint)
            applicable_findings = sort_findings(details.get("applicable_findings", []) or [])
            endpoint_findings = sort_findings(details.get("findings", []) or [])
            incident_findings = sort_findings(i.get("vulnerability_details", []) or [])
            findings = applicable_findings or endpoint_findings or incident_findings
            all_report_findings.extend(findings)

            recommendations = []
            risk_prioritized_for_incident = []

            if findings:
                print("  Endpoint-specific vulnerabilities contributing to risk:")

                for d in findings[:MAX_ENDPOINT_FINDINGS]:
                    print(f"    - {format_finding_line(d)}")
                    msg = finding_message(d)

                    if msg:
                        print(f"      {msg}")

                    recommendations.append(recommendation_for_finding(d))

                    # Risk prioritization means: the endpoint produced a runtime
                    # elevated/block decision and this finding is mapped to that
                    # endpoint. This is a prioritization signal, not standalone
                    # proof of exploitability.
                    if action in ("challenge_mfa", "block"):
                        line = (
                            f"{format_finding_line(d)} -> endpoint {endpoint}, "
                            f"risk score {risk_score:.3f}, action {action}"
                        )
                        key = finding_key(d)

                        if key not in risk_prioritized_keys:
                            risk_prioritized_keys.add(key)
                            risk_prioritized_lines.append(line)

                        risk_prioritized_for_incident.append(line)
            else:
                print("  Endpoint-specific vulnerabilities: none mapped directly")
                print("  Note: risk may still include anomaly score, cumulative session risk, and project-wide vulnerability context.")

            if risk_prioritized_for_incident:
                print("  Risk-prioritized findings:")
                for line in risk_prioritized_for_incident:
                    print(f"    - {line}")

            if action in ("challenge_mfa", "block"):
                print("  Recommended actions:")

                for rec in recommendations:
                    print(f"    - {rec}")

                policy_rec = f"Review access policies for endpoint {endpoint}"
                print(f"    - {policy_rec}")
                recommendations.append(policy_rec)

                if risk_score >= 0.6:
                    monitor_rec = "Consider temporary blocking or increased monitoring"
                    print(f"    - {monitor_rec}")
                    recommendations.append(monitor_rec)

            fixes_for_yaml.append({
                "endpoint": endpoint,
                "user": user,
                "risk_score": risk_score,
                "risk_zone": risk_zone,
                "action": action,
                "findings": findings[:MAX_ENDPOINT_FINDINGS],
                "risk_prioritized": risk_prioritized_for_incident,
                "recommendations": recommendations or [f"Review endpoint {endpoint} and correlated telemetry"],
            })

            print()

    report_summary = summarize_findings(all_report_findings)
    report_summary["risk_prioritized"] = len(risk_prioritized_keys)

    print("--- Vulnerability Summary ---")
    print(f"Unique vulnerability findings: {report_summary['unique_total']}")
    print(f"  SAST findings: {report_summary['sast']}")
    print(f"  CVE findings: {report_summary['cve']}")
    print(f"  DAST findings: {report_summary['dast']}")
    print(f"    DAST security findings: {report_summary['dast_security']}")
    print(f"    DAST informational findings: {report_summary['dast_informational']}")
    print(f"  Risk-prioritized findings: {report_summary['risk_prioritized']}")

    if risk_prioritized_lines:
        print("  Risk-prioritized finding locations:")
        for line in risk_prioritized_lines:
            print(f"    - {line}")

    print("\n--- Project-wide Vulnerability Context ---")
    selected_global = sort_findings(global_findings)[:MAX_GLOBAL_FINDINGS]
    print(f"Showing top {len(selected_global)} of {len(dedupe_findings(global_findings))} global findings.")

    for d in selected_global:
        print(f"    - {format_finding_line(d)}")
        msg = finding_message(d)

        if msg:
            print(f"      {msg}")

    write_recommended_fixes(fixes_for_yaml, global_findings, report_summary)
    print(f"\nRecommended fixes YAML: {RECOMMENDED_FIXES_FILE}")
    print("=======================================================")


if __name__ == "__main__":
    main()
