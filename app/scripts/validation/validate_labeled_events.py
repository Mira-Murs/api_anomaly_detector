import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_FILE = ROOT / "schemas" / "labeled_event_contract.json"

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
STATUS_MIN = 100
STATUS_MAX = 599


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))


def load_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        raise SystemExit(f"{path} is empty")

    if path.suffix.lower() == ".jsonl":
        records = []
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except Exception as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSONL line: {exc}")
        return records

    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return data["records"]

    raise SystemExit("Expected JSON list, JSON object with records[], or JSONL file")


def parse_timestamp(value: Any, idx: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"record {idx}: event.timestamp must be a non-empty string")

    normalized = value.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(normalized)
    except Exception as exc:
        raise ValueError(f"record {idx}: event.timestamp must be ISO-8601 compatible: {exc}")


def validate_record(record: dict[str, Any], idx: int, contract: dict[str, Any]) -> list[str]:
    errors = []

    if not isinstance(record, dict):
        return [f"record {idx}: must be an object"]

    event = record.get("event")
    label = record.get("label")

    if not isinstance(event, dict):
        errors.append(f"record {idx}: missing object event")
        event = {}

    if not isinstance(label, dict):
        errors.append(f"record {idx}: missing object label")
        label = {}

    for field in contract["record_shape"]["event"]["required"]:
        if field not in event:
            errors.append(f"record {idx}: event.{field} is required")

    for field in contract["record_shape"]["label"]["required"]:
        if field not in label:
            errors.append(f"record {idx}: label.{field} is required")

    if "timestamp" in event:
        try:
            parse_timestamp(event["timestamp"], idx)
        except ValueError as exc:
            errors.append(str(exc))

    method = str(event.get("method", "")).upper()
    if method and method not in HTTP_METHODS:
        errors.append(f"record {idx}: event.method unsupported: {method}")

    status = event.get("status_code")
    if status is not None:
        if not isinstance(status, int) or not (STATUS_MIN <= status <= STATUS_MAX):
            errors.append(f"record {idx}: event.status_code must be int in [{STATUS_MIN}, {STATUS_MAX}]")

    if "body_length" in event and (not isinstance(event["body_length"], int) or event["body_length"] < 0):
        errors.append(f"record {idx}: event.body_length must be non-negative int")

    if "payload_preview" in event and not isinstance(event["payload_preview"], str):
        errors.append(f"record {idx}: event.payload_preview must be string")

    if "tool_arguments" in event and not isinstance(event["tool_arguments"], dict):
        errors.append(f"record {idx}: event.tool_arguments must be object")

    if "user_confirmed" in event and not isinstance(event["user_confirmed"], bool):
        errors.append(f"record {idx}: event.user_confirmed must be bool")

    if "is_anomaly" in label and not isinstance(label["is_anomaly"], bool):
        errors.append(f"record {idx}: label.is_anomaly must be bool")

    allowed = contract["allowed_values"]
    for field in ["attack_family", "expected_action", "label_source", "label_confidence"]:
        value = label.get(field)
        if value is not None and value not in allowed[field]:
            errors.append(f"record {idx}: label.{field} unsupported: {value}")

    if label.get("is_anomaly") is False and label.get("attack_family") != "normal":
        errors.append(f"record {idx}: non-anomaly labels must use attack_family=normal")

    if label.get("is_anomaly") is True and label.get("attack_family") == "normal":
        errors.append(f"record {idx}: anomaly labels must not use attack_family=normal")

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate labeled runtime API/LLM event datasets.")
    parser.add_argument("path", help="Path to .json or .jsonl labeled dataset")
    args = parser.parse_args()

    contract = load_contract()
    records = load_records(Path(args.path))

    errors = []
    for idx, record in enumerate(records, 1):
        errors.extend(validate_record(record, idx, contract))

    if errors:
        print(f"labeled_events_validation_failed: {len(errors)} error(s)")
        for err in errors[:50]:
            print("-", err)
        if len(errors) > 50:
            print(f"... {len(errors) - 50} more errors")
        raise SystemExit(1)

    print(f"labeled_events_validation_ok: {len(records)} records")


if __name__ == "__main__":
    main()
