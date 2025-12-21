# PentestAgent Dockerfile
# Multi-stage build for optimized image size

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip wheel --no-cache-dir --wheel-dir /wheels -e .

# Stage 2: Runtime
FROM python:3.11-slim as runtime

LABEL maintainer="PentestAgent Team"
LABEL description="MCP-Integrated Multi-Agent Penetration Testing Support System"
LABEL version="0.1.0"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for MCP servers
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY src/ /app/src/
COPY settings.json /app/
COPY .mcp.json /app/

# Create workspace directory
RUN mkdir -p /app/workspace/sessions /app/workspace/logs

# Create non-root user for security
RUN useradd -m -u 1000 pentest && \
    chown -R pentest:pentest /app

USER pentest

# Environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV WORKSPACE_ROOT=/app/workspace

# Expose ports (if needed for MCP servers)
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from src.orchestrator import Orchestrator; print('OK')" || exit 1

# Default command
CMD ["python", "-m", "src.cli.cli"]
