#!/usr/bin/env bash
set -euo pipefail

MODEL_DIR="${MODEL_DIR:-artifacts/models}"
KEEP="${KEEP:-5}"

cd "$MODEL_DIR"

mapfile -t timestamps < <(
  ls isolation_forest_final.joblib.*.bak 2>/dev/null \
    | sed -E 's/^isolation_forest_final\.joblib\.(.+)\.bak$/\1/' \
    | sort
)

count="${#timestamps[@]}"

if (( count <= KEEP )); then
  echo "Nothing to clean: backup pairs=$count, keep=$KEEP"
  exit 0
fi

delete_count=$((count - KEEP))

for ((i=0; i<delete_count; i++)); do
  ts="${timestamps[$i]}"

  rm -f "isolation_forest_final.joblib.${ts}.bak"
  rm -f "scaler.joblib.${ts}.bak"

  echo "Deleted backup pair timestamp=${ts}"
done

echo "Cleanup done: deleted=${delete_count}, kept=${KEEP}"
