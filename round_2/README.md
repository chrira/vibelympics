# Challenge 2: Maven Package Auditor 🐺

A security-focused CLI tool for auditing Maven packages from Maven Central Repository.

## Quick Start

### Build the Container
```bash
docker build -t maven-auditor .
```

### Run an Audit
```bash
# Audit Spring Boot Starter (specific version)
docker run maven-auditor org.springframework.boot:spring-boot-starter:4.0.0

# Audit Spring Framework Core
docker run maven-auditor org.springframework:spring-core:6.1.4

# Audit Apache Commons Lang
docker run maven-auditor org.apache:commons-lang3:3.14.0

# Audit JUnit (latest version)
docker run maven-auditor junit:junit

# Audit apache maven (specific version)
docker run maven-auditor org.apache.maven:maven:3.0.4
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

✅ **Security**:
- Chainguard Maven base image with Java runtime
- OWASP Dependency-Check v8.4.2 integrated
- SLSA provenance and Sigstore signatures
- Maven for dependency tree analysis

## OWASP Dependency-Check Integration

The auditor includes **OWASP Dependency-Check**, an industry-standard SCA (Software Composition Analysis) tool that:

- Scans dependencies against the NVD (National Vulnerability Database)
- Identifies known vulnerable components
- Analyzes evidence to identify CPE (Common Platform Enumeration)
- Maps to CVE entries
- Generates detailed vulnerability reports

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
