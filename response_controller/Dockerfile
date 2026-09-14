# ==============================================================================
# Stage 1: Build & Dependencies Layer
# ==============================================================================
FROM python:3.12-slim AS builder

WORKDIR /install

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ==============================================================================
# Stage 2: Hardened Runtime Container
# ==============================================================================
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Falco Incident Response Controller" \
      org.opencontainers.image.description="Automated pod quarantine and forensic acquisition engine" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="Cloud-Native Incident Response Platform" \
      org.opencontainers.image.licenses="MIT"

# Create non-root system user
RUN groupadd -g 10001 controller && \
    useradd -u 10001 -g controller -s /sbin/nologin -M controller

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Set up evidence vault directory with restricted permissions
RUN mkdir -p /evidence && chown -R controller:controller /evidence /app

# Copy application source
COPY . /app/response_controller
RUN chown -R controller:controller /app

USER 10001:10001

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    EVIDENCE_DIR=/evidence \
    PORT=8080

EXPOSE 8080

# Container liveness health check
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

CMD ["uvicorn", "response_controller.app:app", "--host", "0.0.0.0", "--port", "8080"]
