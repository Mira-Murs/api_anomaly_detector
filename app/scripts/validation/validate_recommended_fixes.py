import argparse
import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_FILE = ROOT / "schemas" / "recommended_fixes_contract.json"


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))


def require_fields(obj: dict[str, Any], fields: list[str], prefix: str, errors: list[str]) -> None:
    for field in fields:
        if field not in obj:
            errors.append(f"{prefix}.{field} is required")


def validate_finding(finding: Any, idx: str, contract: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(finding, dict):
        errors.append(f"{idx} must be an object")
        return

    require_fields(finding, contract["required_finding_fields"], idx, errors)

    allowed = contract["allowed_values"]

    group = finding.get("group")
    if group is not None and group not in allowed["finding_group"]:
        errors.append(f"{idx}.group unsupported: {group}")

    source = finding.get("source")
    if source is not None and source not in allowed["finding_source"]:
        errors.append(f"{idx}.source unsupported: {source}")

    recommendation = finding.get("recommendation")
    if recommendation is not None and not str(recommendation).strip():
        errors.append(f"{idx}.recommendation must not be empty")


def validate_file(path: Path) -> None:
    contract = load_contract()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    errors: list[str] = []

    if not isinstance(data, dict):
        raise SystemExit("recommended fixes YAML must be a mapping/object")

    require_fields(data, contract["required_top_level_fields"], "root", errors)

    summary = data.get("summary") or {}
    if not isinstance(summary, dict):
        errors.append("root.summary must be an object")
    else:
        require_fields(summary, contract["required_summary_fields"], "summary", errors)
        for key in contract["required_summary_fields"]:
            value = summary.get(key)
            if value is not None and (not isinstance(value, int) or value < 0):
                errors.append(f"summary.{key} must be a non-negative integer")

    incidents = data.get("incidents") or []
    if not isinstance(incidents, list):
        errors.append("root.incidents must be a list")
        incidents = []

    allowed = contract["allowed_values"]
    risk_min = float(contract["ci_cd_rules"]["risk_score_min"])
    risk_max = float(contract["ci_cd_rules"]["risk_score_max"])

    for i, incident in enumerate(incidents, 1):
        prefix = f"incidents[{i}]"
        if not isinstance(incident, dict):
            errors.append(f"{prefix} must be an object")
            continue

        require_fields(incident, contract["required_incident_fields"], prefix, errors)

        risk_score = incident.get("risk_score")
        if risk_score is not None:
            if not isinstance(risk_score, (int, float)) or not (risk_min <= float(risk_score) <= risk_max):
                errors.append(f"{prefix}.risk_score must be number in [{risk_min}, {risk_max}]")

        risk_zone = incident.get("risk_zone")
        if risk_zone is not None and risk_zone not in allowed["risk_zone"]:
            errors.append(f"{prefix}.risk_zone unsupported: {risk_zone}")

        action = incident.get("action")
        if action is not None and action not in allowed["action"]:
            errors.append(f"{prefix}.action unsupported: {action}")

        findings = incident.get("findings") or []
        if not isinstance(findings, list):
            errors.append(f"{prefix}.findings must be a list")
        else:
            for j, finding in enumerate(findings, 1):
                validate_finding(finding, f"{prefix}.findings[{j}]", contract, errors)

        risk_prioritized = incident.get("risk_prioritized") or []
        if not isinstance(risk_prioritized, list):
            errors.append(f"{prefix}.risk_prioritized must be a list")

        recommendations = incident.get("recommendations") or []
        if not isinstance(recommendations, list):
            errors.append(f"{prefix}.recommendations must be a list")
        elif not recommendations:
            errors.append(f"{prefix}.recommendations must not be empty")

    remediation_targets = data.get("remediation_targets") or []
    if not isinstance(remediation_targets, list):
        errors.append("root.remediation_targets must be a list")
        remediation_targets = []

    for i, target in enumerate(remediation_targets, 1):
        prefix = f"remediation_targets[{i}]"
        if not isinstance(target, dict):
            errors.append(f"{prefix} must be an object")
            continue

        require_fields(target, contract.get("required_remediation_target_fields", []), prefix, errors)

        max_risk_score = target.get("max_risk_score")
        if max_risk_score is not None:
            if not isinstance(max_risk_score, (int, float)) or not (risk_min <= float(max_risk_score) <= risk_max):
                errors.append(f"{prefix}.max_risk_score must be number in [{risk_min}, {risk_max}]")

        highest_risk_zone = target.get("highest_risk_zone")
        if highest_risk_zone is not None and highest_risk_zone not in allowed["risk_zone"]:
            errors.append(f"{prefix}.highest_risk_zone unsupported: {highest_risk_zone}")

        strongest_action = target.get("strongest_action")
        if strongest_action is not None and strongest_action not in allowed["action"]:
            errors.append(f"{prefix}.strongest_action unsupported: {strongest_action}")

        affected_users = target.get("affected_users") or []
        if not isinstance(affected_users, list):
            errors.append(f"{prefix}.affected_users must be a list")

        findings = target.get("findings") or []
        if not isinstance(findings, list):
            errors.append(f"{prefix}.findings must be a list")
        else:
            for j, finding in enumerate(findings, 1):
                validate_finding(finding, f"{prefix}.findings[{j}]", contract, errors)

        risk_prioritized = target.get("risk_prioritized") or []
        if not isinstance(risk_prioritized, list):
            errors.append(f"{prefix}.risk_prioritized must be a list")

        recommendations = target.get("recommendations") or []
        if not isinstance(recommendations, list):
            errors.append(f"{prefix}.recommendations must be a list")
        elif not recommendations:
            errors.append(f"{prefix}.recommendations must not be empty")

    project_wide = data.get("project_wide_fixes") or []
    if not isinstance(project_wide, list):
        errors.append("root.project_wide_fixes must be a list")
        project_wide = []

    for i, finding in enumerate(project_wide, 1):
        validate_finding(finding, f"project_wide_fixes[{i}]", contract, errors)

    if errors:
        print(f"recommended_fixes_validation_failed: {len(errors)} error(s)")
        for err in errors[:80]:
            print("-", err)
        if len(errors) > 80:
            print(f"... {len(errors) - 80} more errors")
        raise SystemExit(1)

    print(
        "recommended_fixes_validation_ok: "
        f"incidents={len(incidents)} "
        f"remediation_targets={len(remediation_targets)} "
        f"project_wide_fixes={len(project_wide)}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate recommended_fixes.yaml contract.")
    parser.add_argument(
        "path",
        nargs="?",
        default="artifacts/reports/recommended_fixes.yaml",
        help="Path to recommended_fixes.yaml",
    )
    args = parser.parse_args()
    validate_file(Path(args.path))


if __name__ == "__main__":
    main()
