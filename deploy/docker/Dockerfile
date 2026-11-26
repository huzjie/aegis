# aegis — Linux runtime shielding engine (control plane)
# 默认以 audit 模式运行（只观察不强制）；真实内核强制需特权 + Linux 主机。
FROM python:3.11-slim

LABEL org.opencontainers.image.title="aegis" \
      org.opencontainers.image.description="Zero-dependency Linux runtime shielding engine" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 先装依赖（可选 PyYAML），再拷代码以利用层缓存
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt || true

COPY . .

RUN pip install --no-cache-dir . || true

EXPOSE 8700

# 默认跑控制平面；如需执行强制，需 --privileged 与相应 capabilities
ENTRYPOINT ["aegis"]
CMD ["serve", "--port", "8700"]
