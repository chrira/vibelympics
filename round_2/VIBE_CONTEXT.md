# Vibe Coding Context: Challenge 2 - Package Ecosystem Auditor

## 🏅 Vibelympics Tournament Overview

**Welcome to Chainguard's Vibelympics** - A vibe coding tournament where the only rule is: **don't look at the code!**

This is a unique competition where you write code without looking at the code itself. The AI (me) can see the code, but you shouldn't. This is about vibes, creativity, and letting the AI guide the implementation while you focus on the vision and requirements.

### Event Information
- **Official Website**: https://vibelympics.splashthat.com/
- **GitHub Repository**: https://github.com/chainguard-demo/vibelympics
- **Tournament Name**: Chainguard Vibelympics
- **Tagline**: "Tournament where the only rule is: don't look at the code"
- **Registration**: Via Splash event page (link above)
- **Hashtag**: #vibelympics

### Tournament Philosophy
- **Vibe over perfection**: It's about the energy and creativity, not pixel-perfect execution
- **AI-assisted development**: You describe what you want, I implement it
- **No code reading**: You shouldn't look at the actual code being generated
- **Personality matters**: Unique approaches and creative solutions are valued
- **Done is better than perfect**: Ship it and iterate

### How to Register
1. Visit https://vibelympics.splashthat.com/
2. Fill out the registration form
3. Provide your GitHub repository URL (created from the template)
4. Receive challenge details via email when round opens
5. Start vibing!

---

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
4. **Use Chainguard Images** 🐺
   - Base Docker image MUST be from Chainguard (e.g., `cgr.dev/chainguard/python:latest`)
   - No other base images (Alpine, Ubuntu, Debian, etc.)
   - Demonstrates commitment to supply chain security
   - Aligns with Chainguard's security-first philosophy

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

---

## 🎯 Vibelympics Judging Criteria

### What Judges Are Looking For

#### 1. **Does It Work?** (Essential)
- Can we run it? (Docker build and run successfully)
- Does it produce output?
- Does it handle the input correctly?
- No crashes or errors on legitimate packages

#### 2. **Is It Useful?** (High Priority)
- Do the findings make sense?
- Are the security checks meaningful?
- Would someone actually use this?
- Does the output provide actionable information?

#### 3. **Is It Interesting?** (High Priority)
- Does it have personality?
- Is the output format creative?
- Does it stand out from other submissions?
- Is there a unique angle or approach?

#### 4. **Is It Security-Focused?** (High Priority)
- Does it actually audit packages for security?
- Are the checks relevant to supply chain security?
- Does it detect real security issues?
- Does it follow security best practices?

#### 5. **Is It Easy to Use?** (Medium Priority)
- Can we figure it out quickly?
- Is the interface intuitive?
- Is documentation clear?
- Does it work as expected?

#### 6. **Vibes & Creativity** (Medium Priority)
- Does it have personality and charm?
- Is it fun to use?
- Does it incorporate Chainguard references (Linky, wolfy, etc.)?
- Does it feel like a "vibe" project?

### Bonus Points
- ✨ Incorporates Chainguard products/concepts (Sigstore, SLSA, K8s, Tekton, Kaniko)
- 🐺 Uses Chainguard mascot references (Linky the octopus, wolfy)
- 🎨 Creative output format (ASCII art, emojis, unique visualizations)
- 🚀 Goes beyond requirements in interesting ways
- 📦 Excellent containerization and deployment
- 🔐 Deep security analysis with novel checks

### What Judges DON'T Care About
- ❌ Perfect code style (vibes > perfection)
- ❌ Comprehensive feature coverage (MVP is fine)
- ❌ Enterprise-grade scalability (this is a vibe project)
- ❌ Following every requirement to the letter (be creative!)

### Evaluation Philosophy
> "Don't you ever get tired of asking questions? You do you. 👈(❛ ᗜ ❛👈)"

The judges want to see:
- Your unique take on the problem
- Creative solutions
- Personality in your work
- Security thinking
- Fun and engagement

---

## 🎪 Vibelympics Hints & Easter Eggs

From the official FAQ, judges love:
- 🐙 **Linky** - Chainguard's beloved octopus friend
- 🐺 **Wolfy** - Chainguard's wolf mascot
- 🌯 Burrito bowls
- 🎩 Hats of all kinds
- ⭐ Uber ratings as a judge of character
- 🔗 **Sigstore** - Code signing and verification
- 📦 **SLSA** - Supply chain levels for software artifacts
- 🐳 **Kubernetes** - Container orchestration
- 🏗️ **Tekton** - CI/CD pipelines
- 🔨 **Kaniko** - Container image building
- 🛡️ **Chainguard Containers** - Secure base images
- 📚 **Chainguard Libraries** - Secure language libraries
- 💻 **Chainguard VMs** - Secure virtual machines

### How to Pander (Optional)
You don't have to, but you *can* incorporate these elements:
- Reference Linky or wolfy in your output
- Use Sigstore/SLSA concepts in your auditor
- Mention Chainguard products
- Add fun Easter eggs
- Use creative emojis and formatting

**But remember**: Do what feels right for your project. Authenticity > pandering.

---

## 🏆 Winning Strategy

### The Vibes Approach
1. **Build something that works** - Get the MVP running first
2. **Make it useful** - Ensure the security checks are real and meaningful
3. **Add personality** - Make it fun and interesting to use
4. **Polish the output** - Beautiful, formatted, easy to read
5. **Ship it** - Don't overthink, just deliver
6. **Iterate** - Get feedback and improve

### Key Success Factors
- ✅ **Functionality**: Works reliably
- ✅ **Security focus**: Real security value
- ✅ **Personality**: Unique and interesting
- ✅ **Polish**: Nice output and UX
- ✅ **Vibes**: Fun and engaging
- ✅ **Creativity**: Goes beyond the basic requirements

### Timeline Reality
- **Deadline**: Thursday, December 11th, 11:59 PM Eastern
- **Time to build**: ~3-4 days
- **Strategy**: MVP first, iterate second, polish third

---

## 🚀 Your Competitive Advantage

As a Maven Package Auditor with:
- 🔐 Comprehensive security checks (CVEs, secrets, supply chain)
- 📊 Beautiful markdown reports with emojis
- 🐺 Chainguard references (wolfy, Linky)
- 🔗 Sigstore/SLSA concepts
- 💻 Easy-to-use CLI interface
- 🎨 Creative output format

You have a strong foundation for a winning entry!
