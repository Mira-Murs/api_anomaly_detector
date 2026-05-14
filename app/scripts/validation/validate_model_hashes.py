import hashlib
import json
from pathlib import Path

MODEL_FILES = [
    Path("artifacts/models/isolation_forest_final.joblib"),
    Path("artifacts/models/scaler.joblib"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ok = True

    for model_path in MODEL_FILES:
        hash_path = model_path.with_suffix(".hash")

        if not model_path.exists():
            print(f"ERROR missing model file {model_path}")
            ok = False
            continue

        if not hash_path.exists():
            print(f"ERROR missing hash file {hash_path}")
            ok = False
            continue

        try:
            expected = json.loads(hash_path.read_text(encoding="utf-8"))["hash"]
        except Exception as exc:
            print(f"ERROR invalid hash file {hash_path}: {exc}")
            ok = False
            continue

        actual = sha256_file(model_path)

        if actual != expected:
            print(f"ERROR hash mismatch {model_path}")
            print(f"expected {expected}")
            print(f"actual   {actual}")
            ok = False
        else:
            print(f"OK {model_path}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
