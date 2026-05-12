#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path

    # Noir иногда даёт :username, ZAP/OpenAPI ожидает {username}
    path = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", path)
    return path


def operation_id(method: str, path: str) -> str:
    value = f"{method.lower()}_{path.strip('/') or 'root'}"
    value = re.sub(r"[{}:/\\.-]+", "_", value)
    value = re.sub(r"[^A-Za-z0-9_]", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or f"{method.lower()}_root"


def schema_for_json_params(params):
    properties = {}
    required = []

    for p in params:
        if p.get("param_type") != "json":
            continue

        name = p.get("name")
        if not name:
            continue

        properties[name] = {"type": "string"}
        required.append(name)

    if not properties:
        return None

    schema = {
        "type": "object",
        "properties": properties,
    }

    if required:
        schema["required"] = required

    return schema


def build_openapi(noir_data, server_url):
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Noir-discovered API",
            "version": "1.0.0",
            "description": "OpenAPI specification generated from OWASP Noir output for OWASP ZAP API scanning.",
        },
        "servers": [
            {
                "url": server_url.rstrip("/")
            }
        ],
        "paths": {},
    }

    endpoints = noir_data.get("endpoints", noir_data if isinstance(noir_data, list) else [])

    for ep in endpoints:
        raw_path = ep.get("url") or ep.get("path") or "/"
        path = normalize_path(raw_path)
        method = (ep.get("method") or "GET").lower()
        params = ep.get("params") or []

        if method not in {"get", "post", "put", "patch", "delete", "options", "head"}:
            method = "get"

        spec["paths"].setdefault(path, {})

        parameters = []

        for match in re.findall(r"{([^}]+)}", path):
            parameters.append({
                "name": match,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "example": "test",
            })

        for p in params:
            name = p.get("name")
            ptype = p.get("param_type")
            if not name:
                continue

            if ptype == "query":
                parameters.append({
                    "name": name,
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string"},
                    "example": p.get("value") or "test",
                })
            elif ptype == "header" and name.lower() not in {"accept", "content-type"}:
                parameters.append({
                    "name": name,
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                    "example": p.get("value") or "test",
                })

        operation = {
            "operationId": operation_id(method, path),
            "summary": f"{method.upper()} {path}",
            "parameters": parameters,
            "responses": {
                "200": {"description": "OK"},
                "400": {"description": "Bad request"},
                "401": {"description": "Unauthorized"},
                "404": {"description": "Not found"},
                "500": {"description": "Server error"},
            },
        }

        json_schema = schema_for_json_params(params)
        if json_schema and method in {"post", "put", "patch"}:
            operation["requestBody"] = {
                "required": False,
                "content": {
                    "application/json": {
                        "schema": json_schema,
                        "example": {
                            key: "test"
                            for key in json_schema.get("properties", {}).keys()
                        },
                    }
                },
            }

        spec["paths"][path][method] = operation

    return spec


def main():
    if len(sys.argv) != 4:
        print("Usage: noir_to_openapi.py artifacts/reports/api_endpoints.json artifacts/reports/noir_openapi.json http://localhost:5002", file=sys.stderr)
        sys.exit(2)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    server_url = sys.argv[3]

    noir_data = json.loads(input_path.read_text())
    spec = build_openapi(noir_data, server_url)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(spec, indent=2, ensure_ascii=False))

    paths_count = len(spec.get("paths", {}))
    operations_count = sum(len(methods) for methods in spec.get("paths", {}).values())

    print(f"Generated {output_path}")
    print(f"Paths: {paths_count}")
    print(f"Operations: {operations_count}")


if __name__ == "__main__":
    main()
