FROM python:3.9-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements from the repository root (relative to Docker build context)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directories for mounting volume and script access
RUN mkdir -p /var/ossec/logs/alerts /app/scripts /app/reports

# Run our AI anomaly detection daemon as the container entrypoint
CMD ["python", "-u", "/app/scripts/ai_detection/anomaly_engine.py"]
