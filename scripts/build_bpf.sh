#!/usr/bin/env bash
# 在目标 Linux 主机上编译 aegis 生成的 eBPF 程序。
# 用法: ./scripts/build_bpf.sh <name>
set -euo pipefail
NAME="${1:?usage: build_bpf.sh <name>}"
clang -O2 -g -target bpf -c "artifacts/${NAME}.bpf.c" -o "artifacts/${NAME}.bpf.o"
echo "built artifacts/${NAME}.bpf.o"
