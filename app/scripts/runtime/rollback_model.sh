#!/bin/bash
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

COMPOSE="docker compose -f infra/docker-compose.yml"
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
fi

MODEL_DIR="$(pwd)/artifacts/models"
MODEL_FILE="$MODEL_DIR/isolation_forest_final.joblib"
SCALER_FILE="$MODEL_DIR/scaler.joblib"
AUDIT_FILE="$MODEL_DIR/adaptation_audit.jsonl"

latest_model_backup="$(ls -t "$MODEL_DIR"/isolation_forest_final.joblib.*.bak 2>/dev/null | head -1 || true)"

if [ -z "$latest_model_backup" ]; then
  echo "ERROR: model backup was not found in $MODEL_DIR" >&2
  exit 1
fi

backup_stamp="$(basename "$latest_model_backup" | sed -E 's/^isolation_forest_final\.joblib\.([0-9TZ]+)\.bak$/\1/')"
latest_scaler_backup="$MODEL_DIR/scaler.joblib.${backup_stamp}.bak"

if [ ! -f "$latest_scaler_backup" ]; then
  echo "ERROR: matching scaler backup was not found: $latest_scaler_backup" >&2
  exit 1
fi

rollback_id="$(date -u +%Y%m%dT%H%M%SZ)"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "=== Model rollback dry run ==="
  echo "Would restore model: $latest_model_backup"
  echo "Would restore scaler: $latest_scaler_backup"
  echo "Would save current model as: $MODEL_FILE.before_rollback_${rollback_id}.bak"
  echo "Would save current scaler as: $SCALER_FILE.before_rollback_${rollback_id}.bak"
  exit 0
fi

cp "$MODEL_FILE" "$MODEL_FILE.before_rollback_${rollback_id}.bak"
cp "$SCALER_FILE" "$SCALER_FILE.before_rollback_${rollback_id}.bak"

cp "$latest_model_backup" "$MODEL_FILE"
cp "$latest_scaler_backup" "$SCALER_FILE"

python3 - <<PY
import json
from datetime import datetime, timezone
from pathlib import Path

audit = Path("$AUDIT_FILE")
event = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "event": "model_rollback",
    "restored_model_backup": "$latest_model_backup",
    "restored_scaler_backup": "$latest_scaler_backup",
    "previous_model_backup": "$MODEL_FILE.before_rollback_${rollback_id}.bak",
    "previous_scaler_backup": "$SCALER_FILE.before_rollback_${rollback_id}.bak",
}
with audit.open("a", encoding="utf-8") as f:
    f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\\n")
PY

$COMPOSE restart anomaly_detector >/dev/null

echo "=== Model rollback completed ==="
echo "Restored model: $latest_model_backup"
echo "Restored scaler: $latest_scaler_backup"
echo "--- model_stats ---"
curl -s http://localhost:8001/model_stats | python3 -m json.tool
