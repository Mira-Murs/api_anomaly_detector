import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_FILE = ROOT / "schemas" / "runtime_contracts.json"

REQUIRED_SCHEMAS = {
    "raw_api_event",
    "normalized_api_event",
    "feature_vector",
    "anomaly_result",
    "vulnerability_context",
    "risk_result",
    "decision_result",
    "llm_tool_context",
    "label_schema",
}

EXPECTED_FEATURES = [
    "duration",
    "freq",
    "is_delete",
    "is_get",
    "is_post",
    "is_put",
    "len_body",
    "mean_interval",
    "url_entropy",
    "suspicious_patterns",
    "url_depth",
    "payload_entropy",
    "status_4xx",
    "status_5xx",
    "num_query",
    "payload_len",
    "uniq_ep",
]


def main() -> None:
    data = json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))

    schemas = data.get("schemas")
    if not isinstance(schemas, dict):
        raise SystemExit("runtime_contracts.json missing schemas object")

    missing = sorted(REQUIRED_SCHEMAS - set(schemas))
    if missing:
        raise SystemExit(f"missing required schemas: {missing}")

    feature_schema = schemas["feature_vector"]
    features = feature_schema.get("ordered_features")
    if features != EXPECTED_FEATURES:
        raise SystemExit(f"feature vector mismatch: {features}")

    if feature_schema.get("length") != len(EXPECTED_FEATURES):
        raise SystemExit("feature vector length mismatch")

    decision_mapping = schemas["decision_result"].get("mapping", {})
    expected_mapping = {
        "normal": "allow",
        "elevated": "challenge_mfa",
        "blocked": "block",
    }
    if decision_mapping != expected_mapping:
        raise SystemExit(f"decision mapping mismatch: {decision_mapping}")

    print("runtime_contracts_validation_ok")


if __name__ == "__main__":
    main()
