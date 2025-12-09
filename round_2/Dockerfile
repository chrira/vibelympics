# 🐺 Maven Package Auditor - Chainguard-based Container
# Using Chainguard base image with Java and Maven for dependency analysis

FROM cgr.dev/chainguard/python:latest-dev

USER root

# Install OWASP Dependency-Check
# Download and install dependency-check CLI
RUN mkdir -p /opt/dependency-check && \
    cd /opt/dependency-check && \
    wget -q https://github.com/dependency-check/DependencyCheck/releases/download/v12.1.9/dependency-check-12.1.9-release.zip && \
    unzip -q dependency-check-12.1.9-release.zip && \
    rm dependency-check-12.1.9-release.zip && \
    chmod +x dependency-check/bin/dependency-check.sh && \
    mkdir -p /usr/local/bin/ && \
    ln -s /opt/dependency-check/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

USER nonroot

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
LABEL org.opencontainers.image.description="Security-focused CLI tool for auditing Maven packages with OWASP Dependency-Check"
LABEL org.opencontainers.image.vendor="Chainguard"
LABEL org.opencontainers.image.version="2.0.0"
