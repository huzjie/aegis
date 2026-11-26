#!/usr/bin/env bash
# 语法检查全部 Python 文件。
set -euo pipefail
cd "$(dirname "$0")/.."
python -m compileall -q aegis tests examples
echo "compileall OK"
