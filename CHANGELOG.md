# Changelog

All notable changes to DepGuardian will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-01

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

### Planned Features
- Dependency graph visualization
- PDF report generation
- Integration with more security sources (GitHub Advisory, npm audit)
- Custom policy engine for enterprise rules
- Team collaboration features
- Real-time monitoring dashboard
- API for programmatic access

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
