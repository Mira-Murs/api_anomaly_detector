#!/bin/bash
# Непрерывный воркер – обрабатывает весь входящий трафик в реальном времени
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

while true; do
  KEY=$(docker exec api_redis redis-cli --raw KEYS "raw:*" 2>/dev/null | head -n1)
  if [ -n "$KEY" ]; then
    EVENT=$(docker exec api_redis redis-cli --raw GET "$KEY" 2>/dev/null)
    if [ -n "$EVENT" ]; then
      TIMESTAMP=$(echo "$EVENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('timestamp',''))")
      METHOD=$(echo "$EVENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('method','GET'))")
      URL=$(echo "$EVENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url','/'))")
      STATUS=$(echo "$EVENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status_code',200))")
      BODYLEN=$(echo "$EVENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('body_length',0))")
      PAYLOAD=$(echo "$EVENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('payload_preview',''))")
      
      # Шаг 1: Нормализация – передаём JSON без вложенных кавычек
      NORM=$(curl -s -X POST http://localhost:8002/normalize -H "Content-Type: application/json" \
        -d "{\"timestamp\":\"$TIMESTAMP\",\"method\":\"$METHOD\",\"url\":\"$URL\",\"status_code\":$STATUS,\"body_length\":$BODYLEN,\"payload_preview\":\"$PAYLOAD\",\"source\":\"realtime\"}")
      
      # Шаг 2: Извлечение признаков – передаём результат нормализации как есть (он уже JSON)
      FEAT=$(curl -s -X POST http://localhost:8005/extract -H "Content-Type: application/json" -d "$NORM")
      # Извлекаем feature_vector (массив)
      VEC=$(echo "$FEAT" | python3 -c "import sys,json; print(json.dumps({'features':json.load(sys.stdin)['feature_vector']}))")
      
      # Шаг 3: Детекция аномалий
      ANOM=$(curl -s -X POST http://localhost:8001/detect -H "Content-Type: application/json" -d "$VEC")
      SCORE=$(echo "$ANOM" | python3 -c "import sys,json; print(json.load(sys.stdin)['anomaly_score'])")
      
      # Шаг 4: Оценка риска
      RISK=$(curl -s -X POST http://localhost:8003/compute -H "Content-Type: application/json" \
        -d "{\"anomaly_score\":$SCORE,\"endpoint_id\":\"$URL\",\"user_id\":\"realtime\"}")
      R=$(echo "$RISK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('risk_score',0.0))")
      ZONE=$(echo "$RISK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('risk_zone','normal'))")
      
      # Шаг 5: Принятие решения
      DECISION=$(curl -s -X POST http://localhost:8007/decide -H "Content-Type: application/json" \
        -d "{\"risk_score\":$R,\"risk_zone\":\"$ZONE\",\"endpoint_id\":\"$URL\",\"user_id\":\"realtime\",\"payload_preview\":\"$PAYLOAD\"}")
      
      echo "[$(date -u +%H:%M:%S)] Processed $URL -> $(echo "$DECISION" | python3 -c "import sys,json; print(json.load(sys.stdin)['action'])")"
    fi
    docker exec api_redis redis-cli DEL "$KEY" 2>/dev/null
  fi
  sleep 1
done
