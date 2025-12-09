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
Pick ONE package ecosystem to focus on:
- **PyPI** (Python) - mature, lots of data, good APIs
- **npm** (JavaScript) - large ecosystem, active community
- **Maven Central** (Java) - enterprise packages
- **crates.io** (Rust) - smaller but growing
- **Other**: Go, Ruby, PHP, etc.

### Step 2: Define Security Signals
What makes a package suspicious? Choose 3-5 signals to check:

**Examples:**
- Download count trends (sudden spike or drop?)
- Package age and maintenance status
- Author/maintainer changes
- Dependency count and depth
- Version history patterns
- License information
- Repository activity
- Typosquatting risk (similar names)
- Metadata anomalies

### Step 3: Design Output Format
How will you present findings? Be creative:
- JSON report with risk scores
- HTML dashboard
- ASCII art visualization
- Color-coded terminal output
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
Test with real packages:
- **Legitimate packages**: numpy, lodash, spring-core
- **Suspicious candidates**: typosquats, abandoned projects, new packages
- **Edge cases**: private packages, deleted packages, very old packages

## Technical Considerations

### API Access
Most ecosystems have free APIs:
- **PyPI**: https://pypi.org/pypi/{package}/json
- **npm**: https://registry.npmjs.org/{package}
- **Maven Central**: https://central.sonatype.com/api/v1/search
- **crates.io**: https://crates.io/api/v1/crates/{crate}

### Containerization
Minimal Dockerfile template:
```dockerfile
FROM python:3.11-slim  # or node:20, etc.
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt  # or npm install
EXPOSE 8080
CMD ["python", "app.py"]  # or your entry point
```

### No External Dependencies Needed
- Standard library HTTP clients work fine
- Don't over-engineer the analysis
- Focus on signal quality, not quantity

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
