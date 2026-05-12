import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

NORMALIZER_URL_DEFAULT = "http://localhost:8002/normalize"
FEATURE_EXTRACTOR_URL_DEFAULT = "http://localhost:8005/extract"
ANOMALY_DETECTOR_URL_DEFAULT = "http://localhost:8001/update_model"

DEFAULT_DATASET = "artifacts/data/labeled_samples/runtime_labeled_sample.jsonl"
VALIDATOR = "app/scripts/validation/validate_labeled_events.py"

CONFIDENCE_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def post_json(url: str, payload: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {raw[:500]}") from exc


def load_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []

    if path.suffix.lower() == ".jsonl":
        records = []
        for line in text.splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records

    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return data["records"]

    raise SystemExit("Expected JSON list, JSON object with records[], or JSONL file")


def validate_dataset(path: Path) -> None:
    validator = Path(VALIDATOR)
    if not validator.exists():
        raise SystemExit(f"Validator not found: {VALIDATOR}")

    result = subprocess.run(
        [sys.executable, str(validator), str(path)],
        text=True,
        capture_output=True,
    )

    if result.stdout.strip():
        print(result.stdout.strip())

    if result.returncode != 0:
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        raise SystemExit(result.returncode)


def is_training_allowed(record: dict[str, Any], min_confidence: str) -> bool:
    label = record.get("label") or {}

    if label.get("is_anomaly") is not False:
        return False

    if label.get("attack_family") != "normal":
        return False

    if label.get("expected_action") != "allow":
        return False

    confidence = str(label.get("label_confidence", "low")).lower()
    return CONFIDENCE_RANK.get(confidence, 0) >= CONFIDENCE_RANK[min_confidence]


def event_to_normalizer_payload(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": event.get("timestamp", ""),
        "method": event.get("method", "GET"),
        "url": event.get("url", "/"),
        "status_code": int(event.get("status_code", 200)),
        "body_length": int(event.get("body_length", 0)),
        "payload_preview": event.get("payload_preview", ""),
        "attack_tag": "",
        "is_anomaly": False,
        "source": "adaptation_labeled",
        "source_ip": event.get("source_ip", ""),
    }


def build_vectors(records: list[dict[str, Any]], normalizer_url: str, feature_extractor_url: str) -> list[list[float]]:
    vectors = []

    for record in records:
        event = record.get("event") or {}
        norm_payload = event_to_normalizer_payload(event)

        try:
            normalized = post_json(normalizer_url, norm_payload, timeout=5)
            extracted = post_json(feature_extractor_url, normalized, timeout=5)
            feature_vector = extracted.get("feature_vector")

            if isinstance(feature_vector, list) and len(feature_vector) == 17:
                vectors.append(feature_vector)
            else:
                print(f"Skipped record with invalid feature_vector for url={event.get('url')}")
        except Exception as exc:
            print(f"Skipped record url={event.get('url')} reason={type(exc).__name__}: {exc}")

    return vectors


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely adapt the anomaly model from validated benign labeled examples."
    )
    parser.add_argument(
        "dataset",
        nargs="?",
        default=DEFAULT_DATASET,
        help=f"Path to labeled .json/.jsonl dataset. Default: {DEFAULT_DATASET}",
    )
    parser.add_argument("--normalizer-url", default=NORMALIZER_URL_DEFAULT)
    parser.add_argument("--feature-extractor-url", default=FEATURE_EXTRACTOR_URL_DEFAULT)
    parser.add_argument("--anomaly-detector-url", default=ANOMALY_DETECTOR_URL_DEFAULT)
    parser.add_argument("--min-confidence", choices=["low", "medium", "high"], default="high")
    parser.add_argument("--max-samples", type=int, default=50)
    parser.add_argument("--apply", action="store_true", help="Actually call /update_model. Without this flag, dry-run only.")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise SystemExit(f"Dataset not found: {dataset_path}")

    validate_dataset(dataset_path)

    records = load_records(dataset_path)
    allowed_records = [
        record for record in records
        if is_training_allowed(record, args.min_confidence)
    ]

    if args.max_samples > 0:
        allowed_records = allowed_records[: args.max_samples]

    print(f"records_total: {len(records)}")
    print(f"training_allowed_records: {len(allowed_records)}")
    print(f"min_confidence: {args.min_confidence}")

    if not allowed_records:
        print("No benign labeled records allowed for adaptation.")
        return

    vectors = build_vectors(
        allowed_records,
        args.normalizer_url,
        args.feature_extractor_url,
    )

    print(f"vectors_built: {len(vectors)}")

    if not vectors:
        print("No vectors built; model update skipped.")
        return

    if not args.apply:
        print("dry_run: true")
        print("No model update performed. Re-run with --apply to update the model.")
        return

    payload = {
        "samples": vectors,
        "labels": ["normal"] * len(vectors),
    }

    response = post_json(args.anomaly_detector_url, payload, timeout=30)
    print("update_model_status: ok")
    print(json.dumps(response, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
