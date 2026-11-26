.PHONY: help doctor lint test test-v bench examples clean install

PY ?= python3

help:
	@echo "aegis — 可用目标:"
	@echo "  make doctor     自检引擎"
	@echo "  make lint       compileall 语法检查"
	@echo "  make test       运行全部 unittest"
	@echo "  make bench      运行基准/扫掠"
	@echo "  make examples   运行示例脚本"
	@echo "  make install    pip 安装"
	@echo "  make clean      清理缓存"

doctor:
	$(PY) -m aegis doctor

lint:
	$(PY) -m compileall -q aegis tests examples && echo "compileall OK"

test:
	$(PY) -m unittest discover -s tests -v

bench:
	$(PY) examples/bench_skew_sweep.py

examples:
	$(PY) examples/01_compile_policy.py

install:
	pip install -e .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
