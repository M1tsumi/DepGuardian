# DepGuardian

[![npm version](https://badge.fury.io/js/depguardian-cli.svg)](https://badge.fury.io/js/depguardian-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

DepGuardian is a small CLI I built to keep npm projects from quietly drifting into dependency trouble. It scans your dependencies with OSV (and optionally Snyk), flags a few obvious supply-chain red flags, and can generate an HTML report you can drop into a pull request or share with your team.

## 🚀 Quick Start

```bash
# Install DepGuardian
npm install -g depguardian-cli

# Scan your project
depguardian scan

# Check a specific package
depguardian check lodash

# Initialize configuration
depguardian init

# Generate HTML report
depguardian scan . --html

# Watch mode for continuous monitoring
depguardian watch
```

## 📋 Commands

- `scan [path]` - Scan project for vulnerabilities
- `check <package>` - Check specific package for vulnerabilities  
- `init` - Initialize configuration file
- `watch [path]` - Watch mode for continuous monitoring

### HTML Report Generation
```bash
# Generate interactive HTML report
depguardian scan . --html

# Output: depguardian-report.html
```

### CI/CD Integration
```bash
# Copy GitHub Actions template
cp templates/github-actions.yml .github/workflows/depguardian.yml

# Copy GitLab CI template  
cp templates/gitlab-ci.yml .gitlab-ci.yml
```

### Snyk Integration
```json
{
  "snyk": {
    "enabled": true,
    "token": "${SNYK_TOKEN}",
    "organization": "your-org",
    "endpoint": "https://api.snyk.io"
  }
}
```

## What DepGuardian does today

DepGuardian is still young, but it already does a few useful things:

- Scans your `package.json` and lockfile (npm, pnpm, yarn) to figure out which packages you actually depend on.
- Looks up known vulnerabilities via the OSV API, and can also talk to Snyk if you give it a token.
- Runs a simple supply-chain check over your dependency list (typosquatting-style names, suspicious install scripts, unusual publish patterns, single-maintainer packages).
- Generates an HTML report you can drop into a pull request or share with your team.
- Lets you run quick, one-off checks for a single package from the CLI.

There are also a couple of integrations that exist in the codebase but are still settling:

- A `SafeUpgradeCalculator` that tries to suggest a reasonable target version and gives you a rough risk/confidence score.
- A GitHub helper that can open security PRs based on those upgrade paths.
  - The CLI flags `--pr` and `--fix` are currently placeholders and just print a warning; the underlying code is there if you want to wire it up yourself.

## 🚨 Supply Chain Security

DepGuardian now includes advanced supply chain threat detection:

### Threat Types Detected:
- **Typosquatting**: Packages with names similar to popular packages (e.g., `loda.sh` vs `lodash`)
- **Malicious Scripts**: Suspicious patterns in install scripts (curl, exec, rm, etc.)
- **Suspicious Activity**: Rapid version releases, very new packages
- **Compromised Maintainers**: Suspicious emails, single maintainer packages

### Example Output:
```
🚨 Supply Chain Threats:
Total threats: 3

HIGH (2):
  • loda.sh - typosquatting
  • malicious-pkg - malicious-script

LOW (1):
  • single-maintainer - compromised-maintainer
```

## 📦 Dependencies

- Node.js 18+
- TypeScript 5.3+
- Commander.js for CLI
- Chalk for terminal styling
- Ora for spinners
- OSV API for vulnerability data

## 🧪 Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage

# Build project
npm run build

# Lint code
npm run lint

# Format code
npm run format
```

## 📄 License

MIT License - see LICENSE file for details.

---

**DepGuardian** - Your npm dependency security guardian. Protecting your projects from vulnerabilities and supply chain attacks. 
