# 🐺 Maven Package Auditor - Alpine-based Container
# Using Alpine Linux for lightweight image with Java, Maven, and security tools

FROM alpine:latest

USER root

# Install Python, Java, Maven, and other required tools
RUN apk add --no-cache \
    python3 \
    py3-pip \
    openjdk17-jdk \
    maven \
    wget \
    tar \
    gzip

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

# Create non-root user for security
RUN addgroup -S auditor && adduser -S auditor -G auditor

USER auditor

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
