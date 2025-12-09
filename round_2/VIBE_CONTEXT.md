# Vibe Coding Context: Challenge 2 - Package Ecosystem Auditor

## Challenge Overview
Build a tool that audits packages in an ecosystem of your choice (PyPI, npm, Maven, etc.). Given a package name, generate a security-focused audit report.

## Theme
Software supply chain security

## Core Requirements
1. **Analyze legitimacy, security, and/or supply chain risk** of a target package
2. **Provide information on findings** - what did you discover?
3. **Make it relatively easy to run**:
   - For web apps: build container and run on port
   - For CLI apps: pass argument to container

## Antirequirements (You Have Freedom Here)
- Target any public package index or repository (PyPI, npm, Maven Central, etc)
- Information on results can be in any format (feel free to get weird)

## Deadline
11:59 Eastern on Thursday, December 11th, 2025

## Vibe Coding Rules

### 1. **Rapid Iteration Over Perfection**
- Build a working MVP first
- Iterate based on what you learn
- Don't over-engineer early

### 2. **Embrace Constraints as Features**
- Limited time = focus on core value
- Limited scope = cleaner solution
- Use what you know well

### 3. **Make It Weird (In a Good Way)**
- The antirequirements explicitly say "feel free to get weird"
- Unique output formats are encouraged
- Personality in the tool is a feature

### 4. **Security Focus**
- This is about supply chain security
- Look for red flags: suspicious metadata, unusual patterns, risk indicators
- Think like an auditor, not just a data fetcher

### 5. **Containerization is Non-Negotiable**
- Build a Dockerfile
- Make it easy to run: `docker build . && docker run -p <port>:<port>`
- Or: `docker run <image> <package-name>` for CLI

### 6. **Testing Your Own Work**
- Test with real packages (both legit and suspicious ones)
- Document what you tested
- Make sure the output is actually useful

## Potential Approaches

### Web App
- Interactive dashboard showing package audit results
- Search bar for package names
- Visual risk indicators
- Timeline of package history

### CLI Tool
- Simple: `tool audit <package-name>`
- Output in JSON, YAML, or custom format
- Could be containerized for easy distribution

### Hybrid
- CLI that generates reports
- Web interface to browse reports
- Database of audited packages

## Key Questions to Answer
1. Which package ecosystem will you target?
2. What security signals matter most?
3. How will you visualize/present findings?
4. What makes your tool unique?

## Getting Started Checklist
- [ ] Choose target ecosystem (PyPI, npm, Maven, etc.)
- [ ] Identify 3-5 security signals to check
- [ ] Sketch the output format
- [ ] Set up basic project structure
- [ ] Write Dockerfile
- [ ] Build MVP with 1-2 packages
- [ ] Test and iterate
