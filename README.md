# DepGuardian

[![npm version](https://badge.fury.io/js/@depguardian/cli.svg)](https://badge.fury.io/js/@depguardian/cli)
[![Build Status](https://github.com/your-org/depguardian/workflows/CI/badge.svg)](https://github.com/your-org/depguardian/actions)
[![Coverage Status](https://coveralls.io/repos/github/your-org/depguardian/badge.svg?branch=main)](https://coveralls.io/github/your-org/depguardian?branch=main)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust, real-time vulnerability scanner for npm dependencies that safeguards your projects against supply chain attacks. It automatically detects security issues, suggests safe upgrade paths, and creates pull requests for seamless patching. Empowering developers to maintain secure, up-to-date codebases with minimal effort.

## 🚀 Quick Start

```bash
# Install DepGuardian
npm install -g @depguardian/cli

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

## 🔧 Features Implemented

✅ **Phase 1 Complete:**
- TypeScript project setup with ESM support
- Package.json and lock file parsing (npm, pnpm, yarn)
- OSV API integration for vulnerability data
- Basic CLI with scan, check, init, and watch commands
- Unit tests for core functionality
- Configuration file generation

✅ **Phase 2 Complete:**
- **Supply Chain Attack Detection**
  - Typosquatting detection (identifies packages with names similar to popular ones)
  - Malicious script detection (analyzes install scripts for suspicious patterns)
  - Suspicious activity detection (unusual publishing patterns, rapid releases)
  - Compromised maintainer detection (suspicious emails, single maintainer risk)
- **Safe Upgrade Calculator**
  - Calculates upgrade paths that fix vulnerabilities
  - Breaking change detection and risk assessment
  - Confidence scoring for upgrade recommendations
  - Safe version finding within constraints
- **GitHub API Integration**
  - Automatic PR creation for security updates
  - Batch and individual upgrade PRs
  - Supply chain alert reports
  - Custom PR templates and labeling

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

✅ **Phase 3 Complete:**
- **Snyk API Integration**
  - Multiple vulnerability source aggregation (OSV + Snyk)
  - Rate limiting and error handling
  - Vulnerability deduplication and severity merging
  - CVSS score and vector support
- **CI/CD Pipeline Integration**
  - GitHub Actions workflow template
  - GitLab CI/CD pipeline template
  - Automated security scanning in CI/CD
  - Slack notifications for threats
  - License compliance checking
  - Automated dependency updates
- **Advanced Reporting**
  - Interactive HTML reports with modern UI
  - Click-to-copy package names
  - Expandable threat details
  - Mobile-responsive design
  - Export to JSON and Markdown formats

## 🔜 Coming Soon (Future Enhancements)

- Dependency graph visualization
- PDF report generation
- Integration with more security sources (GitHub Advisory, npm audit)
- Custom policy engine for enterprise rules
- Team collaboration features
- Real-time monitoring dashboard
- API for programmatic access

## 📄 License

MIT License - see LICENSE file for details.

---

**DepGuardian** - Your npm dependency security guardian. Protecting your projects from vulnerabilities and supply chain attacks. 
