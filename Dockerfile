# AuthCanary — Dockerfile
# Multi-stage build: builder installs deps, final image is lean
#
# Usage:
#   docker build -t authcanary .
#   docker run --rm -v ~/.authcanary:/data \
#              -v /var/log/auth.log:/var/log/auth.log:ro \
#              authcanary

# ── Stage 1: dependency builder ────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime image ─────────────────────────────────────────
FROM python:3.13-slim

LABEL org.opencontainers.image.title="AuthCanary" \
      org.opencontainers.image.description="Auth-log anomaly detector with deterministic security invariants" \
      org.opencontainers.image.source="https://github.com/Bhoomikaxoxo/AuthCanary" \
      org.opencontainers.image.licenses="MIT"

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# App source
WORKDIR /app
COPY . .

# Storage directory for SQLite DB and cursor
RUN mkdir -p /data && \
    # Default config points to /data — override at runtime if needed
    sed -i 's|~/.authcanary|/data|g' config.yaml

VOLUME /data

# Expose the dashboard port
EXPOSE 8080

# Default: run one analysis pass
# Override with: docker run ... authcanary --serve --bind 0.0.0.0
ENTRYPOINT ["/usr/local/bin/python", "main.py"]
CMD ["--config", "config.yaml"]
