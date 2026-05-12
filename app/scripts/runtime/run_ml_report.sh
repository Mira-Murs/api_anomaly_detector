#!/bin/bash
set -e

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

COMPOSE="docker compose -f infra/docker-compose.yml"
REPORTS_DIR="$(pwd)/artifacts/reports"
MODEL_DIR="$(pwd)/artifacts/models"

# --- Persistent active model storage ---
# infra/docker-compose.yml mounts artifacts/models to /app/models.
# update_model writes the adapted model directly to this directory through the volume.
mkdir -p "$MODEL_DIR"
MODEL_FILE="$MODEL_DIR/isolation_forest_final.joblib"
SCALER_FILE="$MODEL_DIR/scaler.joblib"

# --- Предварительная загрузка URL для адаптации модели ---
declare -a ADAPT_URLS=()
if [ -f "$(pwd)/artifacts/reports/api_endpoints.json" ]; then
  while IFS= read -r line; do
    ADAPT_URLS+=("$line")
  done < <(python3 -c "
import json
with open('$(pwd)/artifacts/reports/api_endpoints.json') as f:
    data = json.load(f)
for ep in data.get('endpoints', []):
    url = ep.get('url', '')
    if url:
        print(url)
" 2>/dev/null)
fi

if [ ${#ADAPT_URLS[@]} -eq 0 ]; then
  ADAPT_URLS=("/" "/healthcheck")
fi

if [ ! -f "$MODEL_FILE" ]; then
    # Отправляем легитимные запросы для сбора нормального профиля
    echo "  Sending legitimate requests for adaptation..."
    for url in "${ADAPT_URLS[@]}"; do
        curl -s -X POST http://localhost:8004/collect -H "Content-Type: application/json" \
          -d '{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","method":"GET","url":"'"$url"'","status_code":200,"body_length":80,"payload_preview":"{}","source":"adaptation"}' > /dev/null
    done
    sleep 2

    # Запускаем скрипт адаптации внутри контейнера, где есть redis
    docker cp "$(pwd)/app/adapt_model.py" vuln_context:/app/
    docker exec vuln_context python3 /app/adapt_model.py

    # update_model writes directly into artifacts/models via the /app/models volume.
    # Очищаем адаптационные ключи из Redis, чтобы не мешали
    docker exec api_redis redis-cli KEYS "raw:*" | xargs -r docker exec api_redis redis-cli DEL
    echo "=== Adaptation completed ==="
fi

echo "=== Waiting for services (max 10s)..."
for i in $(seq 1 10); do
  if curl -s http://localhost:8001/health >/dev/null; then
    echo "All services ready."
    break
  fi
  sleep 1
done

# --- Загрузка списка эндпоинтов из Noir, иначе из ZAP, иначе стандартные ---
ENDPOINT_PROCESSING_LOG="artifacts/reports/ml_endpoint_processing_latest.log"
: > "$ENDPOINT_PROCESSING_LOG"

echo "=== Resetting runtime Redis state for this report run ==="
docker exec api_redis sh -lc 'redis-cli DEL incidents >/dev/null; for pattern in "raw:*" "processed:raw:*" "session:*" "session_risk:*" "block:*" "mfa:*" "mfa_pending:*" "vuln_context:*" "risk_vuln_context:*" "vuln_weight:*" "vuln_details:*"; do redis-cli --scan --pattern "$pattern" | xargs -r redis-cli DEL >/dev/null; done' >/dev/null 2>&1 || true

echo "=== Reloading vulnerability context after Redis reset ==="
curl -s -X POST http://localhost:8006/reload >/dev/null || true

echo "=== Loading endpoints ==="
declare -a URLS=()

# Пробуем Noir-отчёт
if [ -f "$(pwd)/artifacts/reports/api_endpoints.json" ]; then
  while IFS= read -r line; do
    URLS+=("$line")
  done < <(python3 -c "
import json, sys
with open('$(pwd)/artifacts/reports/api_endpoints.json') as f:
    data = json.load(f)
for ep in data.get('endpoints', []):
    url = ep.get('url','')
    method = ep.get('method','GET')
    if url:
        print(f'{url}|{method}')
" 2>/dev/null)
fi

# Если Noir не дал результатов, пробуем ZAP
if [ ${#URLS[@]} -eq 0 ] && [ -f "$(pwd)/artifacts/reports/zap.json" ]; then
  while IFS= read -r line; do
    URLS+=("$line")
  done < <(python3 -c "
import json, sys
with open('$(pwd)/artifacts/reports/zap.json') as f:
    data = json.load(f)
sites = data.get('site', [])
for site in sites:
    for alert in site.get('alerts', []):
        url = alert.get('url','')
        if url:
            if url.startswith('http://localhost'):
                p = url[len('http://localhost'):]
                if p == '': p = '/'
                print(f'{p}|GET')
            else:
                print(f'{url}|GET')
" 2>/dev/null)
fi

# Совсем ничего – стандартный набор
if [ ${#URLS[@]} -eq 0 ]; then
  echo "  No endpoints discovered, using defaults"
  URLS=("/|GET" "/robots.txt|GET" "/favicon.ico|GET")
fi
if [ -n "${ENDPOINT_INCLUDE_REGEX:-}" ] || [ -n "${ENDPOINT_EXCLUDE_REGEX:-}" ]; then
  mapfile -t URLS < <(printf '%s\n' "${URLS[@]}" | python3 -c 'import os,re,sys
inc=os.getenv("ENDPOINT_INCLUDE_REGEX","")
exc=os.getenv("ENDPOINT_EXCLUDE_REGEX","")
for line in sys.stdin:
    line=line.rstrip("\n")
    path=line.split("|",1)[0]
    if inc and not re.search(inc,path):
        continue
    if exc and re.search(exc,path):
        continue
    print(line)')
fi
echo "  Found ${#URLS[@]} endpoints"
echo "Endpoint processing log: artifacts/reports/ml_endpoint_processing_latest.log"

# --- Функция обработки одного эндпоинта ---
process_endpoint() {
  local URL="$1"
  local METHOD="$2"
  local PAYLOAD="{}"
  local BODYLEN=80
  local STATUS=200

  echo "=== Processing $URL (method=$METHOD) ===" >> "$ENDPOINT_PROCESSING_LOG"

  # Skip framework regex routes discovered from backend internals.
  # They are not directly callable API paths and can break runtime feature extraction.
  if echo "$URL" | grep -Eq '\(\?P<|\[0-9\]|\\d|\[\^/\]|\+\)|\(\?'; then
    echo "  $URL skipped: framework regex route is not a directly callable API path" >> "$ENDPOINT_PROCESSING_LOG"
    return 0
  fi

  local EVENT_JSON
  EVENT_JSON=$(python3 - <<PYJSON
import json
from datetime import datetime, timezone
print(json.dumps({
    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "method": "$METHOD",
    "url": "$URL",
    "status_code": $STATUS,
    "body_length": $BODYLEN,
    "payload_preview": "$PAYLOAD",
    "source": "auto"
}))
PYJSON
)

  # Send a legitimate event to log_collector, but do not fail the whole run if it rejects one endpoint.
  curl -s -X POST http://localhost:8004/collect -H "Content-Type: application/json" -d "$EVENT_JSON" > /dev/null || true

  NORM=$(curl -s -X POST http://localhost:8002/normalize -H "Content-Type: application/json" -d "$EVENT_JSON")
  if ! echo "$NORM" | python3 -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
    echo "  $URL skipped: normalizer returned invalid JSON: ${NORM:0:200}" >> "$ENDPOINT_PROCESSING_LOG"
    return 0
  fi

  FEAT=$(curl -s -X POST http://localhost:8005/extract -H "Content-Type: application/json" -d "$NORM")
  VEC=$(echo "$FEAT" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('feature_vector'); assert isinstance(v, list), d; print(json.dumps({'features': v}))" 2>/dev/null || true)
  if [ -z "$VEC" ]; then
    echo "  $URL skipped: feature_extractor missing feature_vector: ${FEAT:0:300}" >> "$ENDPOINT_PROCESSING_LOG"
    return 0
  fi

  ANOM=$(curl -s -X POST http://localhost:8001/detect -H "Content-Type: application/json" -d "$VEC")
  SCORE=$(echo "$ANOM" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['anomaly_score'])" 2>/dev/null || true)
  if [ -z "$SCORE" ]; then
    echo "  $URL skipped: anomaly_detector missing anomaly_score: ${ANOM:0:300}" >> "$ENDPOINT_PROCESSING_LOG"
    return 0
  fi

  RISK=$(curl -s -X POST http://localhost:8003/compute -H "Content-Type: application/json" \
    -d '{"anomaly_score":'"$SCORE"',"endpoint_id":"'"$URL"'","user_id":"auto"}')
  FULL_RISK=$(echo "$RISK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['risk_score'], d['risk_zone'])" 2>/dev/null || true)
  if [ -z "$FULL_RISK" ]; then
    echo "  $URL skipped: risk_engine missing risk_score/risk_zone: ${RISK:0:300}" >> "$ENDPOINT_PROCESSING_LOG"
    return 0
  fi

  R=$(echo "$FULL_RISK" | cut -d" " -f1)
  ZONE=$(echo "$FULL_RISK" | cut -d" " -f2)

  DECISION=$(curl -s -X POST http://localhost:8007/decide -H "Content-Type: application/json" \
    -d '{"risk_score":'"$R"',"risk_zone":"'"$ZONE"'","endpoint_id":"'"$URL"'","user_id":"auto","payload_preview":"'"$PAYLOAD"'"}')
  ACTION=$(echo "$DECISION" | python3 -c "import sys,json; print(json.load(sys.stdin).get('action','missing'))" 2>/dev/null || echo "missing")
  echo "  $URL processed: score=$SCORE zone=$ZONE action=$ACTION" >> "$ENDPOINT_PROCESSING_LOG"
}

# --- Обрабатываем все эндпоинты ---
for entry in "${URLS[@]}"; do
  URL="${entry%|*}"
  METHOD="${entry#*|}"
  process_endpoint "$URL" "$METHOD"
done

echo ""
echo "=== Running runtime attack/evidence probes ==="
if ! REPORTS_DIR=artifacts/reports TARGET_API="${TARGET_API:-http://localhost:5002}" ATTACK_PROBE_MAX_ENDPOINTS="${ATTACK_PROBE_MAX_ENDPOINTS:-16}" \
  python3 app/scripts/runtime/attack_probe_runner.py > "artifacts/reports/attack_probe_latest.txt" 2>&1; then
    echo "Runtime probes failed. Last lines:"
    tail -n 80 artifacts/reports/attack_probe_latest.txt
    exit 1
fi
python3 - <<'PY_SUMMARY'
import json
from pathlib import Path

path = Path("artifacts/reports/evidence.json")
if path.exists():
    data = json.loads(path.read_text())
    summary = data.get("summary", data)
    print("Runtime evidence:")
    print(f"  probes_total: {summary.get('probes_total', '-')}")
    print(f"  blocked: {summary.get('blocked', '-')}")
    print(f"  challenge_mfa: {summary.get('challenge_mfa', '-')}")
    print(f"  allowed: {summary.get('allowed', '-')}")
    print(f"  errors: {summary.get('errors', '-')}")
print("Probe log: artifacts/reports/attack_probe_latest.txt")
PY_SUMMARY

echo ""
echo "=== Generating final security reports ==="

# Clean only generated report outputs inside vuln_context.
# /app/reports is a bind mount to artifacts/reports, so never remove the directory itself.
docker exec vuln_context sh -lc 'rm -f /app/reports/final_security_report.txt /app/reports/security_summary.txt /app/reports/recommended_fixes.yaml /app/reports/final_report_generation_latest.txt' >/dev/null 2>&1 || true
docker cp app/scripts/runtime/generate_report.py vuln_context:/app/generate_report.py >/dev/null
docker cp app/scripts/runtime/generate_final_reports.py vuln_context:/app/generate_final_reports.py >/dev/null
if [ -f artifacts/reports/evidence.json ]; then
    docker cp artifacts/reports/evidence.json vuln_context:/app/reports/evidence.json >/dev/null
fi
if ! docker exec vuln_context sh -lc 'cd /app && REPORTS_DIR=/app/reports PUBLIC_REPORTS_DIR=artifacts/reports python3 /app/generate_final_reports.py' > artifacts/reports/final_report_generation_latest.txt 2>&1; then
    echo "[ERROR] Final report generation failed. Last lines:"
    tail -n 80 artifacts/reports/final_report_generation_latest.txt
    exit 1
fi
echo "[OK] Final reports generated. Generator log: artifacts/reports/final_report_generation_latest.txt"

docker cp vuln_context:/app/reports/final_security_report.txt artifacts/reports/final_security_report.txt >/dev/null
docker cp vuln_context:/app/reports/security_summary.txt artifacts/reports/security_summary.txt >/dev/null
docker cp vuln_context:/app/reports/recommended_fixes.yaml artifacts/reports/recommended_fixes.yaml >/dev/null

echo ""
echo "=== Recommended fixes validation ==="
python3 app/scripts/validation/validate_recommended_fixes.py artifacts/reports/recommended_fixes.yaml
echo "Recommended fixes validation passed."

echo "=== Security summary ==="
cat artifacts/reports/security_summary.txt

echo ""
echo "=== Reports saved ==="
echo "Full report: artifacts/reports/final_security_report.txt"
echo "Short report: artifacts/reports/security_summary.txt"
echo "Machine-readable fixes: artifacts/reports/recommended_fixes.yaml"
