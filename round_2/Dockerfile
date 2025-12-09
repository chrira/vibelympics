# 🐺 Maven Package Auditor - Chainguard-based Container
# Using distroless Chainguard Python image for security

FROM cgr.dev/chainguard/python:latest

# Set working directory
WORKDIR /app

# Copy application files
COPY auditor.py .

# Set the entrypoint
ENTRYPOINT ["python", "auditor.py"]

# Default help message
CMD ["--help"]

# Labels for container metadata
LABEL org.opencontainers.image.title="Maven Package Auditor"
LABEL org.opencontainers.image.description="Security-focused CLI tool for auditing Maven packages"
LABEL org.opencontainers.image.vendor="Chainguard"
LABEL org.opencontainers.image.version="1.0.0"
