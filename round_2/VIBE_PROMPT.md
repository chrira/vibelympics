# Vibe Coding Prompt: Package Ecosystem Auditor

## Your Mission
Create a security-focused package auditor that analyzes packages from a public ecosystem and generates audit reports. You have until Thursday, December 11th, 11:59 PM Eastern.

## The Vibe
- **Speed over perfection**: Get something working fast
- **Weird is good**: Unique output formats and creative approaches are encouraged
- **Security mindset**: Think like someone trying to detect supply chain attacks
- **Easy to run**: Docker is your friend
- **Personality**: Make it yours

## Starting Point

### Step 1: Choose Your Ecosystem
**TARGET: Maven Central (Java)**

You're building an auditor for Maven Central packages. Maven is the enterprise Java package manager with a mature ecosystem, comprehensive metadata, and good APIs for analysis.

### Step 2: Define Security Signals
What makes a package suspicious? Implement comprehensive security checks:

#### Vulnerability & Dependency Analysis
- **Known CVEs**: Check against NVD (National Vulnerability Database) for published vulnerabilities
- **Dependency depth**: Analyze transitive dependencies and dependency chains
- **Outdated components**: Identify packages using known vulnerable versions
- **Dependency count**: Excessive dependencies increase attack surface
- **Dependency freshness**: Are dependencies regularly updated?

#### Supply Chain & Provenance
- **Package age**: Very new packages are higher risk
- **Maintenance status**: Last update date, active development indicators
- **Author/maintainer changes**: Sudden ownership transfers are red flags
- **Repository activity**: Commit frequency, contributor count, issue response time
- **Typosquatting risk**: Similar names to popular packages
- **License information**: Unusual or missing licenses

#### Code Quality & Static Analysis
- **Code complexity**: High cyclomatic complexity indicates harder-to-audit code
- **Test coverage**: Packages with minimal tests are riskier
- **Documentation quality**: Well-documented packages are more trustworthy
- **Build reproducibility**: Can the package be reliably rebuilt?

#### Secrets & Suspicious Content
- **Hardcoded credentials**: Scan for passwords, API keys, tokens in source
- **Embedded secrets**: AWS keys, database passwords, private keys
- **Suspicious patterns**: Base64-encoded payloads, obfuscated code
- **Outgoing network connections**: Unexpected external calls (C2, exfiltration)

#### Metadata Anomalies
- **Metadata inconsistencies**: Mismatched version info, corrupted manifests
- **POM file analysis**: Check for suspicious dependencies or plugins
- **JAR signatures**: Verify package signatures and checksums
- **Download patterns**: Sudden spikes or unusual distribution patterns

### Step 3: Design Output Format
**CLI Tool (Python)**: Your tool runs inside a container and accepts a package URL as input.

Input format: `docker run auditor <package-url>`
Example: `docker run auditor org.springframework:spring-core`

Output options (be creative):
- JSON report with risk scores
- Color-coded terminal output
- ASCII art visualization
- Markdown report
- Custom format (get weird!)

### Step 4: Build the MVP
Minimum viable product:
1. Accept package name as input
2. Fetch package metadata from ecosystem API
3. Analyze against your security signals
4. Generate report
5. Containerize it

### Step 5: Test & Iterate
Test with real Maven packages:
- **Legitimate packages**: `org.springframework:spring-core`, `org.apache:commons-lang3`, `junit:junit`
- **Suspicious candidates**: typosquats, abandoned projects, new packages
- **Edge cases**: packages with few versions, single maintainer, no recent updates

## Industry Best Practices & Tools Reference

### Vulnerability Scanning Standards
**OWASP Dependency-Check** (SCA - Software Composition Analysis)
- Identifies known vulnerable components using NVD data feeds
- Checks against CVE database for published vulnerabilities
- Analyzes evidence (package names, versions, hashes) to identify CPE (Common Platform Enumeration)
- Automatically updates vulnerability data from NIST NVD

**Trivy** (Aqua Security)
- Comprehensive scanner for vulnerabilities, misconfigurations, secrets, and licenses
- Scans at multiple stages: code repos, binaries, container images, Kubernetes
- Supports SBOM (Software Bill of Materials) generation
- Fast, no database dependencies, easy CI/CD integration

**Chainguard Libraries Verification**
- Verifies package legitimacy using checksums and provenance information
- Checks for supply chain integrity
- Validates package signatures and authenticity

### Secrets Detection Best Practices
- **Patterns to detect**: API keys, AWS credentials, database passwords, private keys, tokens
- **Tools**: Gitleaks, TruffleHog, GitGuardian patterns
- **Scanning scope**: Source code, POM files, configuration files, embedded resources
- **False positive reduction**: Use contextual analysis and machine learning
- **Detection methods**: Regex patterns, entropy analysis, format-specific signatures

### Static Code Analysis (SAST) for Java
- **SpotBugs**: Detects bug patterns in Java bytecode (null pointers, resource leaks, etc.)
- **Checkstyle**: Enforces coding standards and style violations
- **PMD**: Identifies code smells, potential bugs, and suboptimal code
- **SonarQube**: Comprehensive code quality analysis with security focus
- **Focus areas**: Code complexity, test coverage, security vulnerabilities

### Supply Chain Security Checks
- **Provenance verification**: Validate package signatures and checksums
- **Maintainer verification**: Check author identity and history
- **Repository analysis**: GitHub/GitLab activity, commit history, contributor diversity
- **Dependency analysis**: Transitive dependencies, outdated components, license compliance
- **Metadata validation**: POM file integrity, version consistency

### Scanning Stages (from Chainguard)
- **Before libraries enter organization**: Scan as dependencies are added
- **During development**: Scan on developer machines early
- **At build time**: Scan application binaries and artifacts
- **During container creation**: Scan images as they're built
- **In registries**: Scan before deployment to production
- **During deployment**: Scan running applications in production

## Technical Considerations

### API Access - Maven Central
Maven Central provides free APIs for package data:
- **Search API**: `https://central.sonatype.com/api/v1/search?q=<groupId>:<artifactId>`
- **Repository API**: `https://repo1.maven.org/maven2/<groupId>/<artifactId>/maven-metadata.xml`
- **POM Files**: `https://repo1.maven.org/maven2/<groupId>/<artifactId>/<version>/<artifactId>-<version>.pom`

Example for `org.springframework:spring-core`:
- Search: `https://central.sonatype.com/api/v1/search?q=org.springframework:spring-core`
- Metadata: `https://repo1.maven.org/maven2/org/springframework/spring-core/maven-metadata.xml`

### Containerization - CLI Tool
Minimal Dockerfile template for CLI:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "auditor.py"]
CMD ["--help"]
```

Usage:
```bash
docker build -t maven-auditor .
docker run maven-auditor org.springframework:spring-core
docker run maven-auditor org.apache:commons-lang3
```

### Implementation Guide: What to Check

#### Phase 1: Basic Package Info (Essential)
```
1. Fetch package metadata from Maven Central API
2. Extract: version history, release dates, maintainer info
3. Calculate: package age, update frequency
4. Check: license information, repository URL
```

#### Phase 2: Vulnerability Analysis (High Priority)
```
1. Check CVE databases for known vulnerabilities
2. Analyze POM file for dependency versions
3. Identify outdated/vulnerable dependencies
4. Calculate dependency depth and complexity
5. Flag packages with unpatched known CVEs
```

#### Phase 3: Secrets & Suspicious Content (High Priority)
```
1. Download source code or JAR file
2. Scan for hardcoded credentials (regex patterns):
   - AWS keys: AKIA[0-9A-Z]{16}
   - API keys: api[_-]?key[_-]?[a-zA-Z0-9]{20,}
   - Passwords: password[_-]?[=:]\s*['\"][^'\"]+['\"]
   - Tokens: token[_-]?[=:]\s*['\"][^'\"]+['\"]
3. Check for suspicious patterns:
   - Base64 encoded payloads
   - Obfuscated code
   - Unusual string patterns
4. Analyze for network calls:
   - External URLs in code
   - Unexpected remote connections
```

#### Phase 4: Supply Chain Integrity (Medium Priority)
```
1. Verify package signatures and checksums
2. Check maintainer history and changes
3. Analyze repository activity (if available):
   - Commit frequency
   - Contributor count
   - Last commit date
4. Check for typosquatting risks
5. Validate metadata consistency
```

#### Phase 5: Code Quality (Medium Priority)
```
1. Analyze POM file structure
2. Check test coverage indicators
3. Evaluate code complexity
4. Look for suspicious build plugins
5. Check for unusual dependencies
```

### Recommended Python Libraries
- `requests`: HTTP client for API calls
- `xml.etree.ElementTree`: Parse POM files
- `re`: Regex for secrets detection
- `json`: Handle JSON responses
- `datetime`: Date calculations
- `hashlib`: Checksum verification
- No need for heavy dependencies - keep it lightweight

### Risk Scoring Suggestion
Create a composite risk score:
- **Critical** (90-100): Known CVEs, hardcoded secrets, suspicious network calls
- **High** (70-89): Outdated dependencies, new package, maintainer changes
- **Medium** (50-69): Limited test coverage, high complexity, few contributors
- **Low** (0-49): Well-maintained, recent updates, good documentation

## Evaluation Criteria (Inferred)
- Does it work? (Can we run it?)
- Is it useful? (Do the findings make sense?)
- Is it interesting? (Does it have personality?)
- Is it secure-focused? (Does it actually audit?)
- Is it easy to use? (Can we figure it out quickly?)

## Timeline Suggestion
- **Today**: Choose ecosystem, define signals, sketch design
- **Tomorrow**: Build MVP, get basic API working
- **Day 3-4**: Refine analysis, improve output, test thoroughly
- **Day 5**: Polish, document, containerize, final testing

## Remember
- The antirequirements say "feel free to get weird" - this is permission to be creative
- Supply chain security is serious, but your tool can be fun
- Unique output formats and creative approaches are features, not bugs
- Done is better than perfect
- Containerization is non-negotiable (make it easy to run)

## Questions to Keep in Mind
1. What would make YOU suspicious of a package?
2. What information would help someone decide if a package is safe?
3. How can you make the audit results immediately useful?
4. What's one weird thing you could do with the output?

---

**Now go build something cool. The vibe is: security auditor with personality. 🚀**
