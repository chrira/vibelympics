###
# Multi-stage Dockerfile using Chainguard images
# Stage 1: build with Chainguard's go builder
# Stage 2: runtime with Chainguard's static base image (small, secure)
###

## Build stage
FROM cgr.dev/chainguard/go:latest AS builder
WORKDIR /src

# Copy module files first for better caching
COPY go.mod .
COPY main.go .
COPY assets/ assets/

# Build a static linux binary
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
RUN go build -ldflags "-s -w" -o /out/vibelympics

## Runtime stage
# Using Chainguard 'go' image as a runtime base per request; this keeps everything in the
# cgr.dev namespace. This is larger than a static minimal image but works reliably.
FROM cgr.dev/chainguard/go:latest
COPY --from=builder /out/vibelympics /vibelympics

# Use a non-root user for safety if needed
USER 1000
EXPOSE 8080
ENTRYPOINT ["/vibelympics"]
