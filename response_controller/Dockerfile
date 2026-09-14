FROM python:3.12-slim

# Create unprivileged security user
RUN groupadd -g 10001 controller && \
    useradd -u 10001 -g controller -s /bin/bash -m controller

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create forensic evidence storage directory
RUN mkdir -p /evidence && chown -R controller:controller /evidence /app

# Copy application code
COPY . /app/response_controller

USER 10001

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV EVIDENCE_DIR=/evidence

EXPOSE 8080

CMD ["uvicorn", "response_controller.app:app", "--host", "0.0.0.0", "--port", "8080"]
