# Multi-stage build for CT Monitor
# Stage 1: Builder stage for dependencies
FROM python:3.13-alpine AS builder

# Python build environment
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install build dependencies
RUN apk add --no-cache gcc musl-dev linux-headers

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Final lightweight image
FROM python:3.13-alpine

# Python runtime environment
ENV PYTHONUNBUFFERED=1

# Container metadata
LABEL maintainer="Jonas Lejon <jonas.github@triop.se>"
LABEL version="1.2.0"
LABEL description="Certificate Transparency Log Monitor"
LABEL org.opencontainers.image.source="https://github.com/jonaslejon/ct-monitor"

# Set the working directory in the container
WORKDIR /app

# Create a non-privileged user
RUN addgroup -S appuser && adduser -S -G appuser -s /bin/false -D appuser

# Copy installed dependencies from builder stage
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Ensure local bin is in PATH
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Copy the application files
COPY --chown=appuser:appuser ct-monitor.py .
COPY --chown=appuser:appuser .env.example .

# Make the script executable
RUN chmod +x ct-monitor.py

# Switch to the non-privileged user
USER appuser

# Health check for long-running containers
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:9200', timeout=5)" || exit 1

# Set the entrypoint for the container
ENTRYPOINT ["python3", "./ct-monitor.py"]

# Set default command to show help
CMD ["--help"]

# Volume for persistent data (if needed)
VOLUME ["/data"]
