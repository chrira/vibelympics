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

## 🔍 Comprehensive Security Checks

### 🛡️ Vulnerability Analysis
- **CVE Detection**: Scans for known vulnerabilities in dependencies using Grype
- **Dependency Analysis**: Deep inspection of all transitive dependencies for security issues
- **Version Auditing**: Identifies outdated or deprecated package versions
- **Vulnerability Severity Scoring**: Prioritizes findings based on CVSS scores

### 🔐 Secrets & Credentials
- **Hardcoded Secrets**: Detects API keys, passwords, and sensitive data using TruffleHog
- **Credential Patterns**: Identifies common credential patterns and hashes
- **Environment Variables**: Checks for exposed sensitive configuration

### 📦 Package Integrity
- **Signature Verification**: Validates JAR signing and certificates
- **Checksum Validation**: Ensures package integrity with SHA-1/SHA-256 hashes
- **Metadata Verification**: Validates POM metadata and project information
- **Provenance**: Tracks package origin and build information

### 🔄 Maintenance & Activity
- **Version History**: Analyzes release frequency and version patterns
- **Maintainer Activity**: Checks project maintenance status and responsiveness
- **Community Health**: Evaluates project popularity and community support
- **Deprecation Status**: Identifies deprecated or archived projects

## 🚀 Chainguard Integration

### 🐺 Why Chainguard?
- **Minimal Attack Surface**: Uses Chainguard's distroless Python base image
- **Supply Chain Security**: Built with SLSA Level 3 compliance
- **Vulnerability Scanning**: Integrated Grype for comprehensive CVE detection
- **Immutable Containers**: Ensures reproducible and verifiable builds
- **SBOM Generation**: Automatic Software Bill of Materials for transparency

### 🔒 Security Benefits
- **Reduced Bloat**: Minimal container size (~50MB) with only essential components
- **No Shell Access**: Eliminates common attack vectors
- **Immutable Filesystem**: Prevents runtime modifications
- **Distroless**: No package manager or shell for attackers to exploit
- **FIPS Compliance**: Meets strict security standards

### 🛠️ Built with Security in Mind
- **Secrets Detection**: TruffleHog integration for finding exposed credentials
- **Dependency Analysis**: Complete dependency tree visualization
- **Version Auditing**: Identifies outdated or vulnerable dependencies
- **Comprehensive Reporting**: Detailed markdown reports with actionable insights

## 📊 Output Features

### 📝 Report Includes:
- **Executive Summary**: Quick overview of findings
- **Risk Assessment**: Overall security score (0-100)
- **Vulnerability Details**: CVE information and remediation steps
- **Dependency Analysis**: Complete dependency tree with version information
- **Version Insights**: Package age, latest version, and update recommendations
- **Maintenance Status**: Project activity and maintenance indicators
- **Actionable Recommendations**: Clear steps to improve security

### 📂 Report Formats
- **Markdown**: Human-readable format with emojis and formatting
- **Console Output**: Real-time feedback during execution
- **File Export**: Save reports for documentation and compliance

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
