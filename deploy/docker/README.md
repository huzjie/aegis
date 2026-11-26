# Docker 部署

```bash
docker build -t aegis -f deploy/docker/Dockerfile .
docker run --rm -it -p 8700:8700 aegis serve --port 8700

# 或 compose
docker compose -f deploy/docker/docker-compose.yml up --build
```

> 默认 `audit` dry-run 模式（安全）。真实内核强制需 `--privileged` + Linux 主机。
