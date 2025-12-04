# Round 1 – Go Web App (Chainguard Images)

This is a small web application written in Go, located in the `round_1` directory.

## Features:
- Serves a simple UI on port `8080`
- The HTML file is embedded in the binary (using Go 1.22 `embed`)
- Multi-stage Dockerfile using Chainguard images

## GitHub workflow

Build Image and scan it for vulnerabilities.

## Test

Execute the commands from the round_1 directory.

Build & Run:
```bash
# Build image
docker build -t vibelympics:round1 .

# Run container (expose 8080)
docker run --rm -p 8080:8080 vibelympics:round1
```
