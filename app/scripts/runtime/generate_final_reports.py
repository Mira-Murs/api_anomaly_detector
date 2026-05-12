#!/usr/bin/env python3
import contextlib
import io
import json
import os
import re
import sys
from pathlib import Path

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports"))
FULL_REPORT_FILE = REPORTS_DIR / "final_security_report.txt"
SHORT_REPORT_FILE = REPORTS_DIR / "security_summary.txt"
PUBLIC_REPORTS_DIR = Path(os.getenv("PUBLIC_REPORTS_DIR", str(REPORTS_DIR)))

# generate_report.py is copied to /app in the vuln_context container.
# On host, this script can also be compiled safely.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, "/app")

import generate_report as gr  # noqa: E402


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def load_evidence_summary():
    path = REPORTS_DIR / "evidence.json"
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    if isinstance(data, dict):
        if isinstance(data.get("summary"), dict):
            return data["summary"]

        keys = ("probes_total", "blocked", "challenge_mfa", "allowed", "errors")
        return {k: data.get(k) for k in keys if k in data}

    return {}


def load_evidence_endpoints():
    path = REPORTS_DIR / "evidence.json"
    if not path.exists():
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()

    endpoints = set()
    if isinstance(data, dict):
        for item in data.get("probes", []):
            ep = gr.norm_endpoint_id(item.get("endpoint", ""))
            if ep:
                endpoints.add(ep)
    return endpoints


def cve_text(finding):
    cves = gr.extract_cves(finding)
    if cves:
        return ", ".join(cves)

    cve = finding.get("cve")
    return cve if cve else "-"


def close_location(finding):
    source = finding.get("source")

    if source == "semgrep":
        file = finding.get("file") or "unknown file"
        line = finding.get("line")
        rule = finding.get("rule") or ""
        if line:
            return f"{file}:{line} ({rule})"
        return f"{file} ({rule})"

    if source == "trivy":
        package = finding.get("package") or "unknown package"
        fixed = finding.get("fixed_version")
        if fixed:
            return f"package {package}, upgrade to {fixed}"
        return f"package {package}, upgrade or replace dependency"

    if source == "zap":
        url = finding.get("url") or "affected endpoint"
        alert = finding.get("alert") or finding.get("name") or "DAST finding"
        return f"{url} / HTTP response or server config ({alert})"

    return gr.format_finding_line(finding)


def finding_title(finding):
    return (
        finding.get("message")
        or finding.get("title")
        or finding.get("alert")
        or finding.get("name")
        or finding.get("description")
        or gr.format_finding_line(finding)
    )

def short_text(value, limit=180):
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def short_finding_title(finding):
    return short_text(finding_title(finding), 180)


def short_report_priority(finding, risk_score, action):
    source = finding.get("source")
    has_cve = cve_text(finding) != "-"
    riskcode = 0

    if source == "zap":
        try:
            riskcode = int(str(finding.get("riskcode", "0")))
        except Exception:
            riskcode = 0

    # Higher tuple is more important.
    return (
        1 if action == "block" else 0,
        1 if has_cve else 0,
        1 if source == "trivy" else 0,
        risk_score,
        1 if source == "semgrep" else 0,
        riskcode,
    )


def severity_label(risk_score, action):
    if action == "block":
        return "HIGH/BLOCKED"
    if action == "challenge_mfa":
        return "ELEVATED/MFA"
    if risk_score >= 0.6:
        return "HIGH"
    if risk_score >= 0.47:
        return "ELEVATED"
    return "NORMAL"


def build_short_report():
    r = gr.get_redis()
    unique = gr.load_unique_incidents(r)
    incidents = [
        item for item in unique.values()
        if item.get("action") != "allow"
        and item.get("risk_zone") != "normal"
    ]

    # Process high-risk incidents first when choosing the strongest
    # representative finding for each unique vulnerability.
    incidents.sort(key=lambda x: safe_float(x.get("risk_score")), reverse=True)

    evidence = load_evidence_summary()
    evidence_endpoints = load_evidence_endpoints()
    if evidence_endpoints:
        incidents = [
            item for item in incidents
            if gr.norm_endpoint_id(item.get("endpoint_id", "")) in evidence_endpoints
        ]

    lines = []
    lines.append("======== SECURITY SUMMARY REPORT ========")

    if evidence:
        lines.append("")
        lines.append("--- Runtime evidence ---")
        lines.append(f"Probes total: {evidence.get('probes_total', '-')}")
        lines.append(f"Blocked: {evidence.get('blocked', '-')}")
        lines.append(f"Challenge MFA: {evidence.get('challenge_mfa', '-')}")
        lines.append(f"Allowed: {evidence.get('allowed', '-')}")
        lines.append(f"Errors: {evidence.get('errors', '-')}")

    lines.append("")
    lines.append("--- Prioritized critical/elevated items, least to most critical ---")

    if not incidents:
        lines.append("No elevated or blocked incidents recorded.")
        lines.append("=========================================")
        return "\n".join(lines) + "\n"

    max_items = int(os.getenv("SHORT_REPORT_MAX_ITEMS", "20"))
    candidates = {}

    for incident in incidents:
        endpoint = gr.norm_endpoint_id(incident.get("endpoint_id", ""))
        action = incident.get("action", "")
        risk_score = safe_float(incident.get("risk_score"))
        risk_zone = incident.get("risk_zone", "")

        details = gr.get_details_from_redis(r, endpoint)

        endpoint_findings = details.get("findings", []) or []
        related_findings = details.get("related_findings", []) or []
        incident_findings = incident.get("vulnerability_details", []) or []

        # Short report is an analyst-facing prioritization view:
        # include endpoint findings plus related CVE context so the analyst
        # sees the concrete dependency/package fix when runtime risk is high.
        # Short ML report should include only findings that are directly
        # mapped to the runtime endpoint/action. Project-wide related CVEs are
        # useful in the full report, but they are not enough by themselves to
        # claim endpoint-level exploitability.
        def is_short_report_applicable(finding):
            # Short ML report should contain actionable endpoint-level findings.
            # Drop project-wide CVE context and DAST informational/noise alerts.
            if gr.finding_group(finding) == "cve":
                return False

            if finding.get("source") == "zap":
                try:
                    riskcode = int(str(finding.get("riskcode", "0")))
                except Exception:
                    riskcode = 0

                try:
                    cweid = int(str(finding.get("cweid", "-1")))
                except Exception:
                    cweid = -1

                return riskcode > 0 and cweid > 0

            return True

        findings = gr.sort_findings([
            f for f in endpoint_findings
            if is_short_report_applicable(f)
        ])

        if not findings:
            findings = gr.sort_findings([
                f for f in incident_findings
                if is_short_report_applicable(f)
            ])

        if not findings:
            key = ("runtime", endpoint, action)
            item = {
                "priority": (1 if action == "block" else 0, 0, 0, risk_score, 0, 0),
                "endpoint": endpoint,
                "action": action,
                "risk_score": risk_score,
                "risk_zone": risk_zone,
                "close_at": "review endpoint policy and runtime telemetry",
                "cve": "-",
                "finding": short_text(incident.get("message", "Runtime anomaly without mapped scanner finding")),
            }
            if key not in candidates or item["priority"] > candidates[key]["priority"]:
                candidates[key] = item
            continue

        for finding in findings:
            # Keep the same vulnerability separately per response class.
            # Otherwise a later/higher block incident hides the MFA/elevated class.
            key = (action, gr.finding_key(finding))
            item = {
                "priority": short_report_priority(finding, risk_score, action),
                "endpoint": endpoint,
                "action": action,
                "risk_score": risk_score,
                "risk_zone": risk_zone,
                "close_at": close_location(finding),
                "cve": cve_text(finding),
                "finding": short_finding_title(finding),
                "fix": gr.recommendation_for_finding(finding),
            }
            if key not in candidates or item["priority"] > candidates[key]["priority"]:
                candidates[key] = item

    # Keep the most important unique findings, but display them from
    # least critical to most critical for easier reading.
    ranked = sorted(candidates.values(), key=lambda x: x["priority"], reverse=True)

    if max_items > 0 and len(ranked) > max_items:
        selected = ranked[:max_items]

        # Ensure the elevated/MFA class is visible when it exists.
        if not any(item.get("action") == "challenge_mfa" for item in selected):
            best_elevated = next((item for item in ranked if item.get("action") == "challenge_mfa"), None)
            if best_elevated:
                selected[-1] = best_elevated
    else:
        selected = ranked

    selected = sorted(selected, key=lambda x: x["priority"])

    for idx, item in enumerate(selected, start=1):
        lines.append("")
        lines.append(
            f"{idx}. {severity_label(item['risk_score'], item['action'])} | "
            f"{item['endpoint']} | risk={item['risk_score']:.3f} | "
            f"zone={item['risk_zone']} | action={item['action']}"
        )
        lines.append(f"Close at: {item['close_at']}")
        lines.append(f"CVE: {item['cve']}")
        lines.append(f"Finding: {item['finding']}")
        lines.append(f"Fix: {item['fix']}")

    if len(candidates) > max_items:
        lines.append("")
        lines.append(f"Output limited to top {max_items} unique findings. Full report: {PUBLIC_REPORTS_DIR / 'final_security_report.txt'}")

    return "\n".join(lines) + "\n"



def build_grouped_short_report():
    r = gr.get_redis()
    unique = gr.load_unique_incidents(r)
    incidents = [
        item for item in unique.values()
        if item.get("action") != "allow"
        and item.get("risk_zone") != "normal"
    ]

    incidents.sort(key=lambda x: safe_float(x.get("risk_score")))

    evidence = load_evidence_summary()
    evidence_endpoints = load_evidence_endpoints()
    if evidence_endpoints:
        incidents = [
            item for item in incidents
            if gr.norm_endpoint_id(item.get("endpoint_id", "")) in evidence_endpoints
        ]

    lines = []
    lines.append("======== SECURITY SUMMARY REPORT ========")

    if evidence:
        lines.append("")
        lines.append("--- Runtime evidence ---")
        lines.append(f"Probes total: {evidence.get('probes_total', '-')}")
        lines.append(f"Blocked: {evidence.get('blocked', '-')}")
        lines.append(f"Challenge MFA: {evidence.get('challenge_mfa', '-')}")
        lines.append(f"Allowed: {evidence.get('allowed', '-')}")
        lines.append(f"Errors: {evidence.get('errors', '-')}")

    lines.append("")
    lines.append("--- Grouped critical/elevated items, least to most critical ---")

    if not incidents:
        lines.append("No elevated or blocked incidents recorded.")
        lines.append("=========================================")
        return "\n".join(lines) + "\n"

    max_endpoints_per_section = int(os.getenv("SHORT_REPORT_MAX_ENDPOINTS_PER_SECTION", "8"))
    max_findings_per_endpoint = int(os.getenv("SHORT_REPORT_MAX_FINDINGS_PER_ENDPOINT", "8"))

    grouped = {
        "challenge_mfa": {},
        "block": {},
    }

    def finding_display_priority(finding):
        source = finding.get("source")
        has_cve = cve_text(finding) != "-"

        try:
            riskcode = int(str(finding.get("riskcode", "0")))
        except Exception:
            riskcode = 0

        return (
            0 if has_cve else 1,
            0 if source == "trivy" else 1,
            0 if source == "semgrep" else 1,
            0 if source == "zap" else 1,
            -riskcode,
            short_finding_title(finding),
        )

    def add_group_item(action, endpoint, incident, finding):
        risk_score = safe_float(incident.get("risk_score"))
        risk_zone = incident.get("risk_zone", "")

        bucket = grouped.setdefault(action, {})
        group = bucket.setdefault(endpoint, {
            "endpoint": endpoint,
            "action": action,
            "risk_score": risk_score,
            "risk_zone": risk_zone,
            "findings": {},
        })

        if risk_score > group["risk_score"]:
            group["risk_score"] = risk_score
            group["risk_zone"] = risk_zone

        if finding is None:
            key = ("runtime", endpoint, action, incident.get("message", ""))
            item = {
                "sort_key": (2, 1, 1, 1, 0, "runtime"),
                "source": "RUNTIME",
                "title": short_text(incident.get("message", "Runtime anomaly without mapped scanner finding")),
                "close_at": "review endpoint policy and runtime telemetry",
                "rule": "-",
                "cwe": "-",
                "cve": "-",
                "fix": "Review endpoint policy, runtime telemetry and access controls for this anomaly.",
            }
        else:
            key = gr.finding_key(finding)
            source = str(finding.get("source") or "unknown").upper()
            rule = finding.get("rule") or "-"
            cwe = finding.get("cweid") or finding.get("cwe") or "-"

            if source == "TRIVY" or cve_text(finding) != "-":
                source = "CVE"
            elif source == "SEMGREP":
                source = "SAST"
            elif source == "ZAP":
                source = "DAST"

            item = {
                "sort_key": finding_display_priority(finding),
                "source": source,
                "title": short_finding_title(finding),
                "close_at": close_location(finding),
                "rule": rule,
                "cwe": cwe,
                "cve": cve_text(finding),
                "fix": gr.recommendation_for_finding(finding),
            }

        if key not in group["findings"]:
            group["findings"][key] = item

    for incident in incidents:
        endpoint = gr.norm_endpoint_id(incident.get("endpoint_id", ""))
        action = incident.get("action", "")

        if action not in ("challenge_mfa", "block"):
            continue

        details = gr.get_details_from_redis(r, endpoint)

        applicable_findings = details.get("applicable_findings", []) or []

        # The report does not decide exploitability/applicability.
        # vuln_context/risk correlation must provide applicable_findings.
        findings = gr.sort_findings(applicable_findings)

        if not findings:
            add_group_item(action, endpoint, incident, None)
            continue

        for finding in findings:
            add_group_item(action, endpoint, incident, finding)

    section_defs = [
        ("challenge_mfa", "MODERATE RISK / MFA"),
        ("block", "BLOCKED / CRITICAL"),
    ]

    any_section = False

    for action, title in section_defs:
        groups = list(grouped.get(action, {}).values())

        if not groups:
            continue

        any_section = True
        lines.append("")
        lines.append(f"--- {title} ---")

        # Select the most critical endpoint groups first, then display the
        # selected set from least to most critical for readability.
        ranked_groups = sorted(
            groups,
            key=lambda item: item["risk_score"],
            reverse=True,
        )
        selected_groups = ranked_groups[:max_endpoints_per_section]
        selected_groups = sorted(
            selected_groups,
            key=lambda item: item["risk_score"],
        )

        for endpoint_idx, group in enumerate(selected_groups, start=1):
            lines.append("")
            lines.append(
                f"{endpoint_idx}. {group['endpoint']} | "
                f"risk={group['risk_score']:.3f} | "
                f"zone={group['risk_zone']} | "
                f"action={group['action']}"
            )
            lines.append("   Vulnerabilities:")

            findings = sorted(
                group["findings"].values(),
                key=lambda item: item["sort_key"],
            )

            selected_findings = findings[:max_findings_per_endpoint]

            for finding_idx, finding in enumerate(selected_findings, start=1):
                lines.append(f"   {finding_idx}) Vulnerability: {finding['title']}")
                lines.append(f"      Location: {finding['close_at']}")

                if finding.get("cwe") and finding["cwe"] != "-":
                    lines.append(f"      CWE: {finding['cwe']}")

                if finding.get("cve") and finding["cve"] != "-":
                    lines.append(f"      CVE: {finding['cve']}")

                lines.append(f"      Fix: {finding['fix']}")

            if len(findings) > max_findings_per_endpoint:
                lines.append(
                    f"      ... {len(findings) - max_findings_per_endpoint} more findings for this endpoint/action"
                )

        if len(groups) > max_endpoints_per_section:
            lines.append("")
            lines.append(
                f"Section limited to top {max_endpoints_per_section} endpoints."
            )

    if not any_section:
        lines.append("No elevated or blocked incidents recorded.")

    return "\n".join(lines) + "\n"



def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    full_buffer = io.StringIO()
    with contextlib.redirect_stdout(full_buffer):
        gr.main()

    FULL_REPORT_FILE.write_text(full_buffer.getvalue(), encoding="utf-8")

    short_text = build_grouped_short_report()
    SHORT_REPORT_FILE.write_text(short_text, encoding="utf-8")

    print(short_text, end="")


if __name__ == "__main__":
    main()
