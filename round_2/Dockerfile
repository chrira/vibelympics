# 🐺 Maven Package Auditor - Chainguard-based Container
# Using Chainguard base image with Python for fast vulnerability scanning

FROM cgr.dev/chainguard/python:latest-dev

USER root

# Install Java, Maven, and other required tools
RUN apk update && apk add --no-cache --update-cache \
    openjdk-21 \
    maven

# Install Grype - Fast vulnerability scanner optimized for artifacts
# Download Grype binary directly from GitHub releases
RUN mkdir -p /tmp/grype && \
    cd /tmp/grype && \
    wget -q https://github.com/anchore/grype/releases/download/v0.104.2/grype_0.104.2_linux_amd64.tar.gz && \
    tar xzf grype_0.104.2_linux_amd64.tar.gz && \
    mv grype /usr/local/bin/ && \
    chmod +x /usr/local/bin/grype && \
    cd / && \
    rm -rf /tmp/grype

# Install TruffleHog - Secret and credential scanner
# Detects API keys, tokens, credentials, and other sensitive data
RUN pip install --no-cache-dir truffleHog3

USER nonroot

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH="$PATH:$JAVA_HOME/bin"


# Set working directory
WORKDIR /app

# Copy application files
COPY auditor.py .
COPY requirements.txt .

# Install Python dependencies (if any)
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# Set the entrypoint
ENTRYPOINT ["python", "auditor.py"]

# Default help message
CMD ["--help"]

# Labels for container metadata
LABEL org.opencontainers.image.title="Maven Package Auditor"
LABEL org.opencontainers.image.description="Security-focused CLI tool for auditing Maven packages with Grype vulnerability scanning"
LABEL org.opencontainers.image.vendor="Chainguard"
LABEL org.opencontainers.image.version="2.0.0"
