# Challenge 2: Maven Package Auditor 🐺

A security-focused CLI tool for auditing Maven packages from Maven Central Repository.

## Quick Start

### Build the Container
```bash
docker build -t maven-auditor .
```

### Get Help
```bash
# Show help message
docker run maven-auditor --help
```

### Run an Audit
```bash
# Audit apache maven (specific version)
# https://mvnrepository.com/artifact/org.apache.maven/maven-core/3.0.4
docker run maven-auditor org.apache.maven:maven-core:3.0.4

# Basic usage (saves report to current directory)
docker run -v $(pwd):/app maven-auditor org.springframework:spring-core:6.1.4

# Specify output directory for the report
docker run -v $(pwd)/reports:/app/reports maven-auditor org.apache:commons-lang3:3.14.0 -o /app/reports

# Audit latest version (version can be omitted)
docker run -v $(pwd):/app maven-auditor junit:junit
```

### Command Line Options
```
Usage: auditor.py <groupId:artifactId[:version]> [options]

Arguments:
  <groupId:artifactId[:version]>  Maven package coordinates (version is optional)

Options:
  -h, --help     Show this help message and exit
  -o, --output   Output directory for the report (default: current directory)

Examples:
  auditor.py org.springframework.boot:spring-boot-starter:4.0.0
  auditor.py org.springframework:spring-core:6.1.4 -o ./reports
  auditor.py org.apache:commons-lang3:3.14.0 --output /tmp
  auditor.py junit:junit
```

## Features

✅ **Security Checks**:
- **OWASP Dependency-Check** integration for comprehensive vulnerability scanning
- **Dependency tree analysis** showing all transitive dependencies
- Known CVEs detection
- Hardcoded secrets scanning
- Dependency vulnerability analysis
- Package signature verification
- Maintainer verification
- Repository activity analysis
- Code quality assessment
- Metadata integrity validation

✅ **Output**:
- Beautiful markdown reports with emojis
- Risk scoring (0-100)
- Detailed findings and recommendations
- Timestamped audit metadata
- Version information and age analysis
- Newer version availability

✅ **Security**:
- Chainguard Python base image (minimal, distroless)
- Trivy vulnerability scanner (fast, efficient)
- SLSA provenance and Sigstore signatures
- Direct JAR download from Maven Central

## Trivy Vulnerability Scanning

The auditor uses **Trivy**, a fast and efficient vulnerability scanner that:

- Downloads JAR files directly from Maven Central Repository
- Scans dependencies against the NVD (National Vulnerability Database)
- Identifies known vulnerable components and CVEs
- Provides detailed vulnerability reports with severity levels
- Runs 10-20x faster than traditional SCA tools
- Detects vulnerabilities like CVE-2021-26291 (Apache Commons Text RCE)

### Dependency Tree Analysis

The auditor generates a complete dependency tree showing:
- Direct dependencies
- Transitive dependencies
- Dependency versions
- Dependency hierarchy

Example output:
```
org.springframework.boot:spring-boot-starter:4.0.0
├─ org.springframework.boot:spring-boot:4.0.0
│  ├─ org.springframework:spring-core:6.0.0
│  └─ org.springframework:spring-jcl:6.0.0
└─ org.springframework.boot:spring-boot-autoconfigure:4.0.0
```

## Documentation

- **VIBE_CONTEXT.md** - Challenge context and judging criteria
- **VIBE_PROMPT.md** - Detailed implementation prompt
- **SECURITY_CHECKS.md** - Comprehensive security check reference
- **OUTPUT_FORMAT.md** - Report format specification
- **IMPLEMENTATION.md** - Complete implementation guide
