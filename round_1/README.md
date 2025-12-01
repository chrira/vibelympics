# Round 1 – Go Web App (Chainguard images)

Dies ist eine kleine, in Go geschriebene Web-Anwendung im Ordner `round_1`.

Funktionalität:
- Stellt eine einfache UI auf Port `8080` zur Verfügung
- Die HTML-Datei wird in das Binary eingebettet (Go 1.22 `embed`)
- Multi-stage Dockerfile verwendet Chainguard-Images

### Build lokal
Voraussetzungen: Go >= 1.22

```bash
# Bauen
go build -o bin/vibelympics

# Ausführen
PORT=8080 ./bin/vibelympics
```

### Docker – Chainguard Images
 Der Dockerfile verwendet Chainguard-Images für Builder und Runtime. Der Build- und Runtime-Base ist `cgr.dev/chainguard/go:latest` (Chainguard registry).

Build & Run:
```bash
# Build image
docker build -t vibelympics:round1 .

# Run container (expose 8080)
docker run --rm -p 8080:8080 vibelympics:round1
```

### Alternative / Makefile
Falls gewünscht, kann ein `Makefile` verwendet werden. Die Nutzung von Container-Scan-Tools (z. B. Trivy, or Chainguard's tools) ist empfohlen, da die Images minimal gehalten sind.
# Challenge 1

The guidelines for this mysterious challenge will be revealed when Round 1 opens.

