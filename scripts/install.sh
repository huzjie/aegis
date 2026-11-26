#!/usr/bin/env bash
# 安装 aegis（开发模式）。
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install -e .
python -m aegis doctor
echo "aegis 安装完成。用法见 README.md"
