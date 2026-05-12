#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
COMPOSE="docker compose -f infra/docker-compose.yml"
REPORTS_DIR="artifacts/reports"
RULES_DIR="artifacts/rules"
DOCKER_UID="${HOST_UID:-$(id -u)}"
DOCKER_GID="${HOST_GID:-$(id -g)}"
DOCKER_USER="${DOCKER_UID}:${DOCKER_GID}"


CODE="$1"
API="$2"

if [ -z "$CODE" ] || [ -z "$API" ]; then
    echo "Usage: $0 /path/to/code http://api.url"
    exit 1
fi

if [ ! -e "$CODE" ]; then
    echo "Code path does not exist: $CODE"
    exit 1
fi

CODE="$(realpath "$CODE")"

SCAN_CODE="$ROOT_DIR/artifacts/tool_runtimes/scan_source"
echo "=== Preparing scanner source copy ==="
rm -rf "$SCAN_CODE"
mkdir -p "$SCAN_CODE"
cp -R "$CODE"/. "$SCAN_CODE"/
find "$SCAN_CODE" \( -type d -name "__pycache__" -o -type f -name "*.pyc" \) -exec rm -rf {} +
CODE="$SCAN_CODE"
echo "Scanner source prepared at $SCAN_CODE"


echo "=== Runtime contracts validation ==="
if python3 app/scripts/validation/validate_runtime_contracts.py; then
  echo "Runtime contracts validation passed."
else
  echo "Runtime contracts validation failed."
  exit 1
fi

echo "=== Labeled samples validation ==="
if compgen -G "artifacts/data/labeled_samples/*.jsonl" > /dev/null; then
  for labeled_file in artifacts/data/labeled_samples/*.jsonl; do
    python3 app/scripts/validation/validate_labeled_events.py "$labeled_file"
  done
  echo "Labeled samples validation passed."
else
  echo "No labeled samples found, skipping."
fi

echo "=== Cleaning previous runtime state ==="
mkdir -p "$REPORTS_DIR"

# Remove stale reports produced by previous full runs.
rm -f artifacts/reports/api_endpoints.json \
      artifacts/reports/noir_openapi.json \
      artifacts/reports/recommended_fixes.yaml \
      artifacts/reports/final_security_report.txt \
      artifacts/reports/security_summary.txt \
      artifacts/reports/evidence.json \
      artifacts/reports/semgrep*.json \
      artifacts/reports/trivy*.json \
      artifacts/reports/zap*.json \
      artifacts/reports/zap*.html

# Clear Redis runtime and vulnerability context if Redis is already running.
# This prevents old incidents, MFA/block states, session risk and old vuln context
# from leaking into the next demonstration report.
if $COMPOSE ps -q redis >/dev/null 2>&1 && [ -n "$($COMPOSE ps -q redis 2>/dev/null)" ]; then
    $COMPOSE exec -T redis sh -lc 'redis-cli DEL incidents >/dev/null; for p in "raw:*" "session_risk:*" "block:*" "mfa_pending:*" "vuln_weight:*" "vuln_details:*"; do redis-cli --scan --pattern "$p" | xargs -r redis-cli DEL >/dev/null; done; echo "Redis runtime and vulnerability state cleared"; redis-cli LLEN incidents'
else
    echo "Redis is not running yet; skipping Redis cleanup."
fi



# Автоматическое обновление офлайн-правил Semgrep.
# Existing offline rules are kept if network update fails.
# Test/fixed YAML files are removed because Semgrep treats every YAML in a
# config directory as a rule and those files can fail validation.
RULE_DIR="$RULES_DIR/rules_semgrep"
RULE_TMP="$RULES_DIR/rules_semgrep.tmp"
RULE_STAMP="$RULES_DIR/.rules_semgrep_updated"

clean_semgrep_rules() {
    if [ -d "$RULE_DIR" ]; then
        find "$RULE_DIR" -type f \( \
            -name "*.test.yaml" -o \
            -name "*.test.yml" -o \
            -name "*.fixed.test.yaml" -o \
            -name "*.fixed.test.yml" -o \
            -path "*/tests/*" -o \
            -path "*/test/*" \
        \) -delete

        # Remove repository metadata YAML files that are not Semgrep rule configs.
        # Semgrep expects YAML config files under --config directory to contain
        # a top-level "rules:" key.
        python3 - "$RULE_DIR" <<'PY_CLEAN_RULES'
from pathlib import Path
import sys

root = Path(sys.argv[1])
for p in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")):
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    if not any(line.startswith("rules:") for line in text.splitlines()):
        p.unlink()
PY_CLEAN_RULES

        rm -rf "$RULE_DIR/.git" "$RULE_DIR/.github"
        rm -f "$RULE_DIR/.gitignore" "$RULE_DIR/.codemapignore" "$RULE_DIR/.semgrepignore"
        find "$RULE_DIR" -type d -empty -delete
    fi
}

download_semgrep_rules() {
    rm -rf "$RULE_TMP"
    mkdir -p "$RULES_DIR"
    docker run --rm --user "$DOCKER_USER" -e HOME=/tmp -v "$(pwd)/$RULES_DIR":/work alpine/git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /work/rules_semgrep.tmp
}

if [ ! -d "$RULE_DIR" ]; then
    echo "Rules not found, cloning Semgrep rules repository..."
    if download_semgrep_rules; then
        rm -rf "$RULE_DIR"
        mv "$RULE_TMP" "$RULE_DIR"
        clean_semgrep_rules
        touch "$RULE_STAMP"
    else
        echo "Semgrep offline rules are missing and download failed."
        exit 1
    fi
elif [ ! -f "$RULE_STAMP" ] || [ -n "$(find "$RULE_STAMP" -mtime +7 2>/dev/null)" ]; then
    echo "Rules stamp is older than 7 days, trying update..."
    if download_semgrep_rules; then
        rm -rf "$RULE_DIR"
        mv "$RULE_TMP" "$RULE_DIR"
        clean_semgrep_rules
        touch "$RULE_STAMP"
        echo "Rules updated."
    else
        echo "[WARN] Rules update failed; using existing offline rules."
        rm -rf "$RULE_TMP"
        clean_semgrep_rules
    fi
else
    echo "Rules are up to date."
    clean_semgrep_rules
fi

# === Обнаружение API эндпоинтов (OWASP Noir) ===
echo "=== API Discovery: OWASP Noir ==="
NOIR_IMAGE="ghcr.io/owasp-noir/noir:latest"
NOIR_TAR="$(pwd)/noir.tar"
if ! docker image inspect "$NOIR_IMAGE" >/dev/null 2>&1; then
  echo "Noir image not found locally, trying docker pull..."
  if docker pull "$NOIR_IMAGE" >/dev/null 2>&1; then
    echo "Noir image pulled successfully."
  elif [ -f "$NOIR_TAR" ]; then
    echo "Docker pull failed; loading Noir image from offline archive..."
    docker load -i "$NOIR_TAR"
  else
    echo "[WARN] Noir image not available locally, docker pull failed, and no offline archive was found; skipping API discovery."
    NOIR_IMAGE=""
  fi
fi
if [ -n "$NOIR_IMAGE" ]; then
  echo "Running Noir..."
  NOIR_LOG="$REPORTS_DIR/noir_latest.log"
  docker run --rm --user "$DOCKER_USER" -e HOME=/tmp \
    -v "$CODE":/src \
    "$NOIR_IMAGE" \
    /usr/local/bin/noir -b /src -f json > "$REPORTS_DIR/api_endpoints.json" 2>"$NOIR_LOG" || true

  NOIR_ENDPOINT_COUNT="$(python3 -c 'import json, pathlib, sys; p=pathlib.Path(sys.argv[1]); print(len(json.loads(p.read_text() or "{}").get("endpoints", [])) if p.exists() and p.stat().st_size else 0)' "$REPORTS_DIR/api_endpoints.json" 2>/dev/null || echo 0)"

  if [ "$NOIR_ENDPOINT_COUNT" = "0" ] && grep -RqsE "from fastapi import|import fastapi|FastAPI\(" "$CODE"; then
    echo "Noir automatic discovery found no endpoints; retrying with technology python_fastapi. Log: $NOIR_LOG"
    docker run --rm --user "$DOCKER_USER" -e HOME=/tmp \
      -v "$CODE":/src \
      "$NOIR_IMAGE" \
      /usr/local/bin/noir -b /src -t python_fastapi -f json > "$REPORTS_DIR/api_endpoints.json" 2>>"$NOIR_LOG" || true
    NOIR_ENDPOINT_COUNT="$(python3 -c 'import json, pathlib, sys; p=pathlib.Path(sys.argv[1]); print(len(json.loads(p.read_text() or "{}").get("endpoints", [])) if p.exists() and p.stat().st_size else 0)' "$REPORTS_DIR/api_endpoints.json" 2>/dev/null || echo 0)"
  fi

  if [ "$NOIR_ENDPOINT_COUNT" != "0" ]; then
    echo "[OK] API endpoints discovered: $NOIR_ENDPOINT_COUNT. Saved to artifacts/reports/api_endpoints.json"
  else
    echo "[WARN] Noir produced no endpoints, continuing without. Log: $NOIR_LOG"
    rm -f "$REPORTS_DIR/api_endpoints.json"
  fi
else
  echo "[WARN] Noir not available, continuing without."
fi

echo "=== SAST: Semgrep (this step may take 2-15 minutes) ==="
SEMGREP_LOG="$REPORTS_DIR/semgrep_latest.log"

if docker run --rm --user "$DOCKER_USER" -e HOME=/tmp \
    -v "$CODE":/src \
    -v "$(pwd)/artifacts/reports":/reports \
    returntocorp/semgrep:latest \
    semgrep --config auto /src --json -o /reports/semgrep.json --timeout 60 > "$SEMGREP_LOG" 2>&1; then
    echo "Semgrep online scan completed. Log: $SEMGREP_LOG"
else
    echo "Semgrep online scan failed; falling back to offline rules. Log: $SEMGREP_LOG"
    if docker run --rm --user "$DOCKER_USER" -e HOME=/tmp \
        -v "$CODE":/src \
        -v "$(pwd)/artifacts/rules/rules_semgrep":/rules \
        -v "$(pwd)/artifacts/reports":/reports \
        returntocorp/semgrep:latest \
        semgrep --config /rules /src --json -o /reports/semgrep.json >> "$SEMGREP_LOG" 2>&1; then
        echo "Semgrep offline scan completed. Log: $SEMGREP_LOG"
    else
        echo "Semgrep scan failed. Last lines:"
        tail -n 80 "$SEMGREP_LOG"
        exit 1
    fi
fi

echo "=== CVE: Trivy (this step may take 2-15 minutes) ==="
mkdir -p artifacts/trivy-cache
TRIVY_LOG="$REPORTS_DIR/trivy_latest.log"

if docker run --rm --user "$DOCKER_USER" -e HOME=/tmp \
  -v "$CODE":/src \
  -v "$(pwd)/artifacts/reports":/reports \
  -v "$(pwd)/artifacts/trivy-cache":/tmp/trivy-cache \
  aquasec/trivy:latest fs --cache-dir /tmp/trivy-cache --format json --output /reports/trivy.json /src > "$TRIVY_LOG" 2>&1; then
  echo "Trivy scan completed. Log: $TRIVY_LOG"
else
  echo "[WARN] Trivy scan failed; continuing without CVE findings. Log: $TRIVY_LOG"
  echo "[WARN] Last Trivy log lines:"
  tail -n 80 "$TRIVY_LOG" || true
  python3 - <<'PYTRIVY'
import json
from pathlib import Path

Path("artifacts/reports/trivy.json").write_text(
    json.dumps({
        "Results": [],
        "trivy_status": "unavailable",
        "reason": "Trivy scan failed; see artifacts/reports/trivy_latest.log"
    }, indent=2),
    encoding="utf-8"
)
PYTRIVY
fi

echo "=== DAST: OWASP ZAP (this step may take 2-15 minutes) ==="
ZAP_LOG="$REPORTS_DIR/zap_latest.log"

if [ -f "$(pwd)/artifacts/reports/api_endpoints.json" ]; then
    echo "Generating OpenAPI spec from Noir-discovered endpoints..."
    python3 app/scripts/runtime/noir_to_openapi.py "$(pwd)/artifacts/reports/api_endpoints.json" "$(pwd)/artifacts/reports/noir_openapi.json" "$API" > "$REPORTS_DIR/noir_openapi_latest.log" 2>&1

    echo "Running ZAP API scan..."
    ZAP_EXIT=0
    docker run --rm --user "$DOCKER_USER" -e HOME=/tmp --network host \
        -v "$(pwd)/artifacts/reports":/zap/wrk \
        zaproxy/zap-stable:latest \
        zap-api-scan.py -t /zap/wrk/noir_openapi.json -f openapi -J /zap/wrk/zap.json -r /zap/wrk/zap.html > "$ZAP_LOG" 2>&1 || ZAP_EXIT=$?

    echo "ZAP API scan exit code: $ZAP_EXIT. Log: $ZAP_LOG"
else
    echo "Noir endpoint report not found; running ZAP full scan from root API URL."
    ZAP_EXIT=0
    docker run --rm --user "$DOCKER_USER" -e HOME=/tmp --network host \
        -v "$(pwd)/artifacts/reports":/zap/wrk \
        zaproxy/zap-stable:latest \
        zap-full-scan.py -t "$API" -j -J /zap/wrk/zap.json -r /zap/wrk/zap.html > "$ZAP_LOG" 2>&1 || ZAP_EXIT=$?

    echo "ZAP full scan exit code: $ZAP_EXIT. Log: $ZAP_LOG"
fi

if [ -f "$(pwd)/artifacts/reports/zap.json" ]; then
    echo "[OK] DAST scan completed, report saved."
else
    echo "[WARN] DAST scan finished but report not found."
fi

set -e

echo "=== Starting ML system (this step may take 2-15 minutes) ==="

# Remove stale containers from earlier compose project layouts.
# This prevents name conflicts after moving docker-compose.yml into infra/.
docker rm -f \
  llm_guard \
  session_metrics \
  log_collector \
  normalizer \
  feature_extractor \
  anomaly_detector \
  risk_engine \
  vuln_context \
  response_orchestrator \
  api_redis >/dev/null 2>&1 || true

if ! $COMPOSE up -d > "$REPORTS_DIR/docker_compose_up_latest.log" 2>&1; then
  echo "ML system failed to start. Last lines:"
  tail -n 80 "$REPORTS_DIR/docker_compose_up_latest.log"
  exit 1
fi
echo "ML system started. Log: $REPORTS_DIR/docker_compose_up_latest.log"

# === Автоматический прогон тестовых запросов и генерация ML-отчёта ===
echo "=== Waiting for vuln_context service ==="
VULN_READY=0
for i in $(seq 1 30); do
  if $COMPOSE exec -T vuln_context python3 - <<'PYWAIT' >/dev/null 2>&1
import socket
with socket.create_connection(("127.0.0.1", 8000), timeout=2):
    pass
PYWAIT
  then
    VULN_READY=1
    break
  fi
  sleep 1
done

if [ "$VULN_READY" != "1" ]; then
  echo "vuln_context did not become ready in time"
  $COMPOSE logs --tail=80 vuln_context
  exit 1
fi

echo "=== Reloading vulnerability context from fresh reports ==="
$COMPOSE exec -T vuln_context python3 - <<'PYRELOAD'
import json
import urllib.request

req = urllib.request.Request("http://127.0.0.1:8000/reload", method="POST")
with urllib.request.urlopen(req, timeout=10) as resp:
    data = json.loads(resp.read().decode())
print(json.dumps(data, ensure_ascii=False))
PYRELOAD
echo "[OK] Vulnerability context reloaded."



# === Автоматический прогон тестов и ML-отчёт ===
echo "=== Generating final ML report ==="
TARGET_API="$API" bash app/scripts/runtime/run_ml_report.sh

echo "=== Publishing security engineer deliverables ==="
mkdir -p reports/latest
cp artifacts/reports/final_security_report.txt reports/latest/SECURITY_REPORT.txt
cp artifacts/reports/security_summary.txt reports/latest/SECURITY_SUMMARY.txt
cp artifacts/reports/recommended_fixes.yaml reports/latest/recommended_fixes.yaml
if [ -f artifacts/reports/zap.html ]; then
  cp artifacts/reports/zap.html reports/latest/zap.html
fi

echo "Security engineer deliverables:"
echo "  reports/latest/SECURITY_REPORT.txt"
echo "  reports/latest/SECURITY_SUMMARY.txt"
echo "  reports/latest/recommended_fixes.yaml"
echo "  reports/latest/zap.html"

echo "=== System ready ==="
echo "Send requests to http://localhost:8004/collect"
