# API Anomaly Detector
Прототип ML/DevSecOps-системы для анализа API и LLM-приложений. 
Система объединяет поведенческое обнаружение аномалий, результаты SAST/DAST/CVE-сканирования, проверки LLM-угроз и адаптивную маршрутизацию запросов.

## Возможности
- обнаружение API endpoints через OWASP Noir;
- SAST-анализ исходного кода через Semgrep;
- CVE-анализ зависимостей через Trivy;
- DAST-анализ работающего API через OWASP ZAP;
- ML-based anomaly detection на базе Isolation Forest;
- расчет risk score с учетом контекста уязвимостей;
- LLM Guard для prompt injection, prompt leakage, unsafe tool calls и SSRF-like сценариев;
- адаптивное решение по запросу: `allow`, `challenge_mfa`, `block`;
- controlled few-shot adaptation по валидированным benign-примерам;
- генерация отчетов для security engineer;
- machine-readable рекомендации в YAML;
- мониторинг через Prometheus и Grafana;
- запуск через Docker Compose;
- CI/CD-проверки через GitHub Actions.

## Архитектура
Основные сервисы находятся в `app/services`:

| Сервис | Назначение |
|---|---|
| `log_collector` | прием runtime-событий |
| `normalizer` | нормализация событий |
| `feature_extractor` | извлечение признаков |
| `anomaly_detector` | расчет anomaly score |
| `risk_engine` | расчет risk score |
| `vuln_context` | загрузка SAST/DAST/CVE-контекста |
| `response_orchestrator` | выбор действия `allow`, `challenge_mfa`, `block` |
| `llm_guard` | проверка LLM-угроз |
| `session_metrics` | runtime/session метрики |
| `redis` | runtime state |
| `prometheus` | сбор метрик |
| `grafana` | визуализация метрик |

## Структура проекта
```
api_anomaly_detector/
├── app/
│   ├── services/          # микросервисы ML/security pipeline
│   ├── scripts/           # runtime, security и validation scripts
│   ├── schemas/           # JSON-контракты
│   └── adapt_model.py     # controlled adaptation
├── artifacts/
│   ├── data/              # labeled samples и monitoring reference data
│   ├── models/            # ML-модель, scaler, feature names
│   ├── rules/             # offline Semgrep rules
│   └── thresholds/        # thresholds/config
├── datasets/              # демонстрационные datasets
├── infra/
│   ├── docker-compose.yml
│   └── monitoring/        # Prometheus/Grafana конфигурация
├── reports/
│   └── examples/          # примеры отчетов
├── .github/workflows/     # CI/CD checks
├── run.sh                 # полный pipeline запуска
└── README.md
```

## Требования
- Linux/Ubuntu;
- Docker;
- Docker Compose v2;
- Python 3.10+;
- доступ в интернет при первом запуске для загрузки Docker images и security databases.

Используемые инструменты:
- OWASP Noir;
- Semgrep;
- Trivy;
- OWASP ZAP;
- Prometheus;
- Grafana.

## Быстрый запуск
Сначала нужно поднять тестовое приложение, которое будет анализироваться.
После этого запустить полный pipeline:

```bash
cd ~/api_anomaly_detector
HOST_UID="$(id -u)" HOST_GID="$(id -g)" ./run.sh /path/to/code http://127.0.0.1:PORT
```

Где:
- `/path/to/code` — путь к исходному коду анализируемого приложения;
- `http://127.0.0.1:PORT` — URL запущенного API.

Пример:
```bash
HOST_UID="$(id -u)" HOST_GID="$(id -g)" ./run.sh /path/to/test_app http://127.0.0.1:5000
```

## Что делает `run.sh`
Pipeline выполняет:
1. копирование анализируемого кода во временную scanner-папку;
2. валидацию runtime contracts и labeled samples;
3. обнаружение endpoints через OWASP Noir;
4. SAST-анализ через Semgrep;
5. CVE/dependency scan через Trivy;
6. DAST-анализ через OWASP ZAP;
7. запуск ML-системы через Docker Compose;
8. загрузку vulnerability context;
9. запуск runtime attack/evidence probes;
10. расчет anomaly score и risk score;
11. выбор действия `allow`, `challenge_mfa` или `block`;
12. генерацию итоговых отчетов.

## Отчеты
Финальные отчеты создаются в:
```
reports/latest/
```

Основные файлы:
| Файл | Назначение |
|---|---|
| `SECURITY_REPORT.txt` | полный отчет для security engineer |
| `SECURITY_SUMMARY.txt` | краткая сводка |
| `recommended_fixes.yaml` | machine-readable рекомендации |
| `zap.html` | HTML-отчет OWASP ZAP |

Технические артефакты последнего запуска находятся в:
```
artifacts/reports/
```

## Machine-readable рекомендации

Файл:
```
reports/latest/recommended_fixes.yaml
```

может использоваться для:
- CI/CD gate;
- создания тикетов;
- автоматической обработки remediation targets;
- проверки структуры security findings.

Проверка файла:
```bash
python3 app/scripts/validation/validate_recommended_fixes.py reports/latest/recommended_fixes.yaml
```

## Monitoring
После запуска доступны:
| Сервис | URL |
|---|---|
| Prometheus | `http://127.0.0.1:9090` |
| Prometheus targets | `http://127.0.0.1:9090/targets` |
| Grafana | `http://127.0.0.1:3000` |

Grafana по умолчанию:
```
admin / admin
```

Dashboard:
```
API Anomaly Detector Overview
```

## Основные порты
| Порт | Сервис |
|---:|---|
| 8001 | anomaly_detector |
| 8002 | normalizer |
| 8003 | risk_engine |
| 8004 | log_collector |
| 8005 | feature_extractor |
| 8006 | vuln_context |
| 8007 | response_orchestrator |
| 8008 | llm_guard |
| 8009 | session_metrics |
| 9090 | Prometheus |
| 3000 | Grafana |

## Проверка проекта
Проверка shell scripts:

```bash
bash -n run.sh
find app -type f -name "*.sh" -print0 | xargs -0 -r -I{} bash -n "{}"
```

Проверка Python-синтаксиса:
```bash
python3 - <<'PY'
from pathlib import Path
import ast
import sys

bad = []
for p in sorted(Path(".").rglob("*.py")):
    if any(part in {".git", "rules_semgrep", "__pycache__"} for part in p.parts):
        continue
    try:
        ast.parse(p.read_text(encoding="utf-8"))
    except Exception as e:
        bad.append((str(p), str(e)))

if bad:
    print("PYTHON SYNTAX ERRORS:")
    for path, err in bad:
        print(f"{path}: {err}")
    sys.exit(1)

print("python syntax OK")
PY
```

Проверка Docker Compose:
```bash
docker compose -f infra/docker-compose.yml config >/tmp/api_anomaly_compose_config.txt
```

Проверка контрактов:
```bash
python3 app/scripts/validation/validate_runtime_contracts.py
python3 app/scripts/validation/validate_labeled_events.py artifacts/data/labeled_samples/runtime_labeled_sample.jsonl
```

## Остановка
```bash
cd ~/api_anomaly_detector
docker compose -f infra/docker-compose.yml down
```

## CI/CD
В `.github/workflows/ci.yml` настроены проверки:
- Python syntax;
- JSON contracts;
- labeled samples validation;
- Docker Compose validation;
- Semgrep;
- Trivy filesystem scan.

## Безопасность
Проект предназначен для учебных и исследовательских целей. Тестовые deliberately vulnerable приложения не следует запускать в публичной сети.
