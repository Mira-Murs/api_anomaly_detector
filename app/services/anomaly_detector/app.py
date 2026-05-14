from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import numpy as np
import joblib
import hashlib
from model_loader import ModelLoader
import os
import math
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from scipy.special import expit
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app, include_in_schema=False, endpoint="/metrics")
MODEL_PATH = "/app/models/isolation_forest_final.joblib"
SCALER_PATH = "/app/models/scaler.joblib"
MODELS_DIR = Path("/app/models")
TRAINING_DATA_PATH = MODELS_DIR / "training_data.npy"
REJECTED_SAMPLES_PATH = MODELS_DIR / "rejected_adaptation_samples.npy"
ADAPTATION_AUDIT_PATH = MODELS_DIR / "adaptation_audit.jsonl"
MAX_UPDATE_SAMPLES = int(os.getenv("MAX_UPDATE_SAMPLES", "50"))
MIN_ACCEPTED_UPDATE_SAMPLES = int(os.getenv("MIN_ACCEPTED_UPDATE_SAMPLES", "1"))
model = None
scaler = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit(event: dict) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    event = dict(event)
    event.setdefault("timestamp", utc_now_iso())
    with ADAPTATION_AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def backup_file(path: str, suffix: str) -> str | None:
    src = Path(path)
    if not src.exists():
        return None
    backup = src.with_name(f"{src.name}.{suffix}.bak")
    shutil.copy2(src, backup)
    return str(backup)


def atomic_joblib_dump(obj, path: str) -> None:
    dst = Path(path)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    joblib.dump(obj, tmp)
    os.replace(tmp, dst)


def atomic_npy_save(path: Path, arr: np.ndarray) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    np.save(tmp, arr)
    generated = Path(str(tmp) + ".npy")
    if generated.exists():
        os.replace(generated, path)
    else:
        os.replace(tmp, path)


@app.on_event("startup")
def load_model():
    global model, scaler
    model = ModelLoader(MODEL_PATH).load()
    scaler = ModelLoader(SCALER_PATH).load()

class FeatureVector(BaseModel):
    features: list

class UpdateData(BaseModel):
    samples: list
    labels: list | None = None


FEATURE_NAMES = [
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


def validate_feature_matrix(X: np.ndarray) -> None:
    if X.ndim == 1:
        X = X.reshape(1, -1)

    if X.shape[1] != 17:
        raise HTTPException(400, "Each sample must have 17 features")

    if np.any(np.isnan(X)) or np.any(np.isinf(X)):
        raise HTTPException(400, "Invalid values in samples: NaN or Inf")

    if np.any(X < 0):
        raise HTTPException(400, "Invalid values in samples: negative feature value")

    # Defensive upper bounds against malformed or poisoned training updates.
    max_bounds = np.array([
        3600.0, 10000.0, 1.0, 1.0, 1.0, 1.0, 20.0, 86400.0, 8.0,
        50.0, 50.0, 8.0, 1.0, 1.0, 100.0, 20.0, 10000.0
    ])

    if np.any(X > max_bounds):
        raise HTTPException(400, "Invalid values in samples: feature exceeds safe bound")


def normal_adaptation_mask(X: np.ndarray) -> np.ndarray:
    """Accept only benign-looking samples for online adaptation."""
    suspicious_patterns = X[:, 9]
    status_4xx = X[:, 12]
    status_5xx = X[:, 13]
    payload_len = X[:, 15]
    freq = X[:, 1]

    return (
        (suspicious_patterns <= 0.0)
        & (status_4xx == 0.0)
        & (status_5xx == 0.0)
        & (payload_len <= 5.0)
        & (freq <= 50.0)
    )



def runtime_signal_boost(features: list) -> tuple[float, dict]:
    """
    Calibrates the Isolation Forest score with direct runtime indicators.

    This layer uses only request-derived runtime features. It does not use
    SAST, DAST or CVE metadata; those remain in risk_engine/vuln_context.
    """
    freq = float(features[1])
    suspicious_patterns = float(features[9])
    status_4xx = float(features[12])
    status_5xx = float(features[13])
    payload_len = float(features[15])

    boost = 0.0
    reasons = {}

    if suspicious_patterns > 0:
        part = min(0.24, 0.045 * suspicious_patterns)
        boost += part
        reasons["suspicious_patterns"] = {
            "value": suspicious_patterns,
            "boost": part,
        }

    if payload_len > 4.5:
        part = min(0.06, 0.015 * (payload_len - 4.5))
        boost += part
        reasons["large_payload"] = {
            "value": payload_len,
            "boost": part,
        }

    if suspicious_patterns > 0 and status_4xx > 0:
        part = 0.035
        boost += part
        reasons["suspicious_payload_with_4xx"] = {
            "value": status_4xx,
            "boost": part,
        }

    if suspicious_patterns > 0 and status_5xx > 0:
        part = 0.055
        boost += part
        reasons["suspicious_payload_with_5xx"] = {
            "value": status_5xx,
            "boost": part,
        }

    if suspicious_patterns > 0 and freq > 20:
        part = min(0.05, 0.005 * (freq - 20))
        boost += part
        reasons["high_frequency_suspicious_session"] = {
            "value": freq,
            "boost": part,
        }

    return min(boost, 0.35), reasons



def write_hash_file(path: str) -> str:
    artifact_path = Path(path)
    hash_path = artifact_path.with_suffix(".hash")
    h = hashlib.sha256()
    with artifact_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    tmp_path = hash_path.with_suffix(hash_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump({"hash": h.hexdigest()}, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp_path.replace(hash_path)
    return str(hash_path)


@app.post("/detect")
async def detect(fv: FeatureVector):
    if len(fv.features) != 17:
        raise HTTPException(status_code=400, detail=f"Expected 17 features, got {len(fv.features)}")
    if any(math.isnan(x) or math.isinf(x) for x in fv.features):
        raise HTTPException(status_code=400, detail="Features contain NaN or Inf")

    arr = np.array(fv.features).reshape(1, -1)
    arr_scaled = scaler.transform(arr)
    score = float(model.score_samples(arr_scaled)[0])
    base_model_score = float(expit(-score))

    boost, boost_reasons = runtime_signal_boost(fv.features)
    anomaly_score = min(0.99, max(base_model_score, base_model_score + boost))

    return {
        "anomaly_score": anomaly_score,
        "base_model_score": base_model_score,
        "runtime_boost": boost,
        "runtime_boost_reasons": boost_reasons,
    }

@app.post("/update_model")
async def update_model(data: UpdateData):
    global model, scaler

    X_new = np.array(data.samples, dtype=float)
    if X_new.ndim == 1:
        X_new = X_new.reshape(1, -1)

    validate_feature_matrix(X_new)

    if len(X_new) > MAX_UPDATE_SAMPLES:
        append_audit({
            "event": "model_update_rejected",
            "reason": "batch_size_exceeded",
            "samples": int(len(X_new)),
            "max_update_samples": int(MAX_UPDATE_SAMPLES),
        })
        raise HTTPException(
            413,
            f"Too many samples in update batch: {len(X_new)} > {MAX_UPDATE_SAMPLES}"
        )

    labels = data.labels
    if labels is not None and len(labels) != len(X_new):
        raise HTTPException(400, "labels length must match samples length")

    # Online adaptation is allowed only from explicitly/implicitly benign samples.
    # Malicious or suspicious samples are rejected, not learned as normal.
    benign_label_mask = np.ones(len(X_new), dtype=bool)
    if labels is not None:
        benign_label_mask = np.array([str(x).lower() in ("normal", "benign", "0") for x in labels])

    benign_signal_mask = normal_adaptation_mask(X_new)
    accepted_mask = benign_label_mask & benign_signal_mask

    accepted = X_new[accepted_mask]
    rejected = X_new[~accepted_mask]

    if 0 < len(accepted) < MIN_ACCEPTED_UPDATE_SAMPLES:
        append_audit({
            "event": "model_update_rejected",
            "reason": "not_enough_accepted_samples",
            "accepted_samples": int(len(accepted)),
            "min_accepted_update_samples": int(MIN_ACCEPTED_UPDATE_SAMPLES),
            "rejected_samples": int(len(rejected)),
        })
        return {
            "message": "No model update performed",
            "accepted_samples": int(len(accepted)),
            "rejected_samples": int(len(rejected)),
            "reason": "not enough accepted samples",
        }

    if len(accepted) == 0:
        if len(rejected) > 0:
            try:
                old_rejected = np.load(REJECTED_SAMPLES_PATH)
            except Exception:
                old_rejected = np.empty((0, 17))
            atomic_npy_save(REJECTED_SAMPLES_PATH, np.vstack([old_rejected, rejected]))

        result = {
            "message": "No samples accepted for adaptation",
            "accepted_samples": 0,
            "rejected_samples": int(len(rejected)),
            "reason": "samples look suspicious or are not labeled benign",
        }

        append_audit({
            "event": "model_update_rejected",
            **result,
        })

        return result

    try:
        old_data = np.load(TRAINING_DATA_PATH)
    except Exception:
        old_data = np.empty((0, 17))

    combined = np.vstack([old_data, accepted])

    # Keep rejected samples for audit/quarantine, not for training.
    if len(rejected) > 0:
        try:
            old_rejected = np.load(REJECTED_SAMPLES_PATH)
        except Exception:
            old_rejected = np.empty((0, 17))
        atomic_npy_save(REJECTED_SAMPLES_PATH, np.vstack([old_rejected, rejected]))

    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest

    new_scaler = StandardScaler().fit(combined)
    combined_scaled = new_scaler.transform(combined)
    new_model = IsolationForest(
        n_estimators=200,
        contamination=0.005,
        random_state=42,
        n_jobs=-1
    ).fit(combined_scaled)

    update_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    model_backup = backup_file(MODEL_PATH, update_id)
    scaler_backup = backup_file(SCALER_PATH, update_id)

    atomic_npy_save(TRAINING_DATA_PATH, combined)
    atomic_joblib_dump(new_model, MODEL_PATH)
    atomic_joblib_dump(new_scaler, SCALER_PATH)
    model_hash = write_hash_file(MODEL_PATH)
    scaler_hash = write_hash_file(SCALER_PATH)

    model = new_model
    scaler = new_scaler

    result = {
        "message": f"Model updated with {len(accepted)} accepted samples",
        "accepted_samples": int(len(accepted)),
        "rejected_samples": int(len(rejected)),
        "total_samples": int(len(combined)),
        "model_backup": model_backup,
        "scaler_backup": scaler_backup,
        "model_hash": model_hash,
        "scaler_hash": scaler_hash,
    }

    append_audit({
        "event": "model_update",
        **result,
    })

    return result

@app.get("/model_stats")
async def model_stats():
    def npy_rows(path: str | Path) -> int:
        try:
            arr = np.load(path)
            if arr.ndim == 1:
                return 1
            return int(arr.shape[0])
        except Exception:
            return 0

    def file_size(path: str | Path) -> int:
        try:
            return int(Path(path).stat().st_size)
        except Exception:
            return 0

    def read_last_audit_event() -> dict | None:
        try:
            if not ADAPTATION_AUDIT_PATH.exists():
                return None
            last_line = None
            with ADAPTATION_AUDIT_PATH.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
            return json.loads(last_line) if last_line else None
        except Exception as exc:
            return {"error": f"failed_to_read_audit: {type(exc).__name__}"}

    def backup_pairs() -> list[dict]:
        model_prefix = "isolation_forest_final.joblib."
        scaler_prefix = "scaler.joblib."
        suffix = ".bak"

        model_backups = {}
        scaler_backups = {}

        for p in MODELS_DIR.glob(f"{model_prefix}*{suffix}"):
            ts = p.name[len(model_prefix):-len(suffix)]
            model_backups[ts] = str(p)

        for p in MODELS_DIR.glob(f"{scaler_prefix}*{suffix}"):
            ts = p.name[len(scaler_prefix):-len(suffix)]
            scaler_backups[ts] = str(p)

        pairs = []
        for ts in sorted(set(model_backups) | set(scaler_backups)):
            pairs.append({
                "timestamp": ts,
                "model_backup": model_backups.get(ts),
                "scaler_backup": scaler_backups.get(ts),
                "complete": ts in model_backups and ts in scaler_backups,
            })
        return pairs

    pairs = backup_pairs()
    complete_pairs = [p for p in pairs if p["complete"]]
    latest_backup_pair = complete_pairs[-1] if complete_pairs else (pairs[-1] if pairs else None)

    training_rows = npy_rows(TRAINING_DATA_PATH)
    rejected_rows = npy_rows(REJECTED_SAMPLES_PATH)

    return {
        "model_loaded": model is not None,
        "scaler_loaded": scaler is not None,
        "model_type": type(model).__name__ if model is not None else None,
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "training_samples": training_rows,
        "rejected_adaptation_samples": rejected_rows,
        "training_data_rows": training_rows,
        "rejected_rows": rejected_rows,
        "backup_count": len(complete_pairs),
        "backup_file_count": len(pairs),
        "latest_backup_pair": latest_backup_pair,
        "last_audit_event": read_last_audit_event(),
        "model_file_size": file_size(MODEL_PATH),
        "scaler_file_size": file_size(SCALER_PATH),
        "model_path": MODEL_PATH,
        "scaler_path": SCALER_PATH,
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
