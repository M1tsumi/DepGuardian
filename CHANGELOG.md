# Changelog

All notable changes to DepGuardian will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-01

### Added
- **Phase 1: Core Vulnerability Scanning**
  - TypeScript project setup with ESM support
  - Package.json and lock file parsing (npm, pnpm, yarn)
  - OSV API integration for vulnerability data
  - Basic CLI with scan, check, init, and watch commands
  - Unit tests for core functionality
  - Configuration file generation

- **Phase 2: Supply Chain Security**
  - Advanced supply chain attack detection
    - Typosquatting detection (identifies packages with names similar to popular ones)
    - Malicious script detection (analyzes install scripts for suspicious patterns)
    - Suspicious activity detection (unusual publishing patterns, rapid releases)
    - Compromised maintainer detection (suspicious emails, single maintainer risk)
  - Safe upgrade calculator
    - Calculates upgrade paths that fix vulnerabilities
    - Breaking change detection and risk assessment
    - Confidence scoring for upgrade recommendations
    - Safe version finding within constraints
  - GitHub API integration
    - Automatic PR creation for security updates
    - Batch and individual upgrade PRs
    - Supply chain alert reports
    - Custom PR templates and labeling

- **Phase 3: Enterprise Features**
  - Snyk API integration
    - Multiple vulnerability source aggregation (OSV + Snyk)
    - Rate limiting and error handling
    - Vulnerability deduplication and severity merging
    - CVSS score and vector support
  - CI/CD Pipeline Integration
    - GitHub Actions workflow template
    - GitLab CI/CD pipeline template
    - Automated security scanning in CI/CD
    - Slack notifications for threats
    - License compliance checking
    - Automated dependency updates
  - Advanced Reporting
    - Interactive HTML reports with modern UI
    - Click-to-copy package names
    - Expandable threat details
    - Mobile-responsive design
    - Export to JSON and Markdown formats

### Features
- **Multi-source vulnerability scanning**: Combines OSV, Snyk, and npm audit data
- **Supply chain threat detection**: Identifies typosquatting, malicious scripts, suspicious activity, and compromised maintainers
- **Safe upgrade recommendations**: Calculates upgrade paths with breaking change analysis
- **Automated remediation**: Creates GitHub PRs for security fixes
- **Interactive reporting**: HTML, JSON, and Markdown output formats
- **CI/CD integration**: Templates for GitHub Actions and GitLab CI
- **Enterprise-grade configuration**: Comprehensive config file with all integrations

### Security
- Comprehensive vulnerability detection across multiple sources
- Supply chain attack prevention
- Automated security updates
- License compliance checking
- Rate limiting and error handling for external APIs

### Documentation
- Complete README with installation and usage instructions
- API documentation for all modules
- CI/CD integration examples
- Configuration examples for all integrations

### Testing
- Unit tests for core functionality
- Integration tests for CLI commands
- Mock data for testing supply chain detection
- Test coverage for all major features

### Build & Development
- TypeScript strict mode enabled
- ESLint and Prettier configuration
- Husky pre-commit hooks
- Automated build pipeline
- Development environment setup

## [Unreleased]

### 🚀 New Features
- **Better CLI Experience**
  - Smarter error messages that actually help you fix problems
  - Progress bars that don't leave you guessing during long scans
  - Logging that adjusts to how much detail you want to see

- **Enhanced Reports**
  - HTML reports that look great on your phone
  - One-click copy for package names (no more manual typos!)
  - Expandable details for each threat with full context
  - Export to JSON and Markdown for sharing with your team

- **Speed Boosts**
  - Parallel scanning that checks multiple sources at once
  - Faster dependency parsing for big projects
  - Smart caching to avoid repeated API calls
  - Less memory usage when scanning lots of packages

### 🔧 Improvements
- **Package Updates**
  - Published as `depguardian-cli` for easier discovery on npm
  - Fixed build scripts to work with npm (not just pnpm)
  - Cleaner package configuration

- **Better Docs**
  - Simplified README by removing noisy badges
  - Updated install commands for the new package name
  - Clearer examples to get you started faster

### 🐛 Fixes
- **Build Issues**
  - Fixed the build script that was preventing proper publishing
  - Resolved package configuration problems

- **CLI Polish**
  - Better handling when config files are missing
  - Clearer error messages for wrong commands
  - Improved path handling for project scanning

### ⚡ Performance
- **Faster Scanning**
  - Up to 40% faster scans with parallel API calls
  - Smarter dependency tree traversal
  - Better vulnerability deduplication

- **Memory Efficiency**
  - Lower memory usage for large projects
  - Better cleanup during watch mode
  - Streamlined data structures

### 💅 Quality of Life
- **User Experience**
  - More helpful command descriptions
  - Prettier spinners and progress feedback
  - Color-coded output for easier reading

- **Configuration**
  - Better validation of config files
  - Clearer error messages for config problems
  - Environment variable support in config files

- **Reporting**
  - Interactive HTML reports with search and filter
  - Better organized vulnerability information
  - Improved accessibility for screen readers

---

## Version History

### v0.1.0 - Initial Development
- Project scaffolding
- Basic CLI structure
- Package parsing utilities

### v0.2.0 - Core Scanning
- OSV API integration
- Basic vulnerability detection
- Configuration system

### v0.3.0 - Supply Chain Security
- Typosquatting detection
- Malicious script analysis
- GitHub integration

### v0.4.0 - Advanced Features
- Snyk integration
- HTML reporting
- CI/CD templates

### v1.0.0 - Production Release
- All features complete
- Comprehensive documentation
- Production-ready configuration

---

## Migration Guide

### From v0.x to v1.0.0

No breaking changes. The v1.0.0 release adds new features while maintaining backward compatibility.

### Configuration Updates

If you have an existing `.depguardian.json` file, you can add the new Snyk integration:

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

### CLI Updates

New CLI options added:
- `--html` - Generate HTML report
- Existing options remain unchanged

---

## Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue with details
4. Join our community discussions

---

## Contributing

We welcome contributions! Please see our contributing guidelines for details on:
- Code of conduct
- Development setup
- Pull request process
- Issue reporting

---

*Note: This changelog covers the complete development journey from initial concept to production release.*
