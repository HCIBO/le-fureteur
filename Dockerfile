FROM node:20.18-bookworm-slim AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SCAKIT_DATA_DIR=/data SCAKIT_FRONTEND_DIR=/app/frontend/dist
RUN apt-get update && apt-get install -y --no-install-recommends 7zip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data scakit
WORKDIR /app
COPY pyproject.toml README.md ./
COPY scakit/ scakit/
RUN pip install --no-cache-dir ".[report,server]"
COPY --from=frontend /src/dist /app/frontend/dist
RUN rm -rf /data && mkdir -p /data/cache && chown -R scakit /data
ENV XDG_CACHE_HOME=/data/cache
USER scakit
VOLUME ["/data"]
EXPOSE 8800
CMD ["scakit", "server", "run", "--host", "0.0.0.0", "--port", "8800"]
