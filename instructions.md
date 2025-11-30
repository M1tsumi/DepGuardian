# dependency-firewall - Project Instructions

## Package Overview
**Name:** dependency-firewall  
**Description:** Real-time npm package vulnerability scanning with automatic PR creation for security patches and supply chain attack detection. Monitors new vulnerabilities and creates PRs with safe upgrade paths.  
**Category:** Security  
**Version:** 1.0.0

---

## Project Goals

Build a CLI tool and GitHub Action that:
1. Scans npm dependencies for known vulnerabilities in real-time
2. Detects supply chain attacks (malicious packages, typosquatting, suspicious install scripts)
3. Automatically creates Pull Requests with safe dependency upgrades
4. Provides detailed vulnerability reports with severity levels and remediation steps
5. Integrates with CI/CD pipelines
6. Monitors for new vulnerabilities continuously

---

## Technology Stack

### Core
- **Runtime:** Node.js 18+ (with ESM support)
- **Language:** TypeScript (for type safety)
- **Package Manager:** pnpm (for efficient dependency management)

### Dependencies
- `commander` - CLI framework
- `chalk` - Terminal styling
- `ora` - Terminal spinners
- `@octokit/rest` - GitHub API client
- `semver` - Semantic versioning utilities
- `node-fetch` - HTTP requests
- `zod` - Schema validation
- `dotenv` - Environment variable management

### Security Data Sources
- OSV (Open Source Vulnerabilities) API: `https://osv.dev`
- Snyk Vulnerability Database API
- npm audit (built-in)
- GitHub Security Advisories API

### Dev Dependencies
- `vitest` - Testing framework
- `eslint` - Linting
- `prettier` - Code formatting
- `tsx` - TypeScript execution
- `@types/node` - Node.js types
- `husky` - Git hooks
- `lint-staged` - Pre-commit linting

---

## Project Structure

```
dependency-firewall/
├── src/
│   ├── index.ts                    # Main entry point
│   ├── cli.ts                      # CLI interface
│   ├── core/
│   │   ├── scanner.ts              # Vulnerability scanner
│   │   ├── analyzer.ts             # Dependency analyzer
│   │   ├── detector.ts             # Supply chain attack detector
│   │   └── updater.ts              # Safe upgrade path calculator
│   ├── integrations/
│   │   ├── github.ts               # GitHub PR creation
│   │   ├── osv.ts                  # OSV API client
│   │   ├── snyk.ts                 # Snyk API client
│   │   └── npm-audit.ts            # npm audit wrapper
│   ├── reporters/
│   │   ├── console.ts              # Terminal reporter
│   │   ├── json.ts                 # JSON output
│   │   └── markdown.ts             # Markdown reports
│   ├── utils/
│   │   ├── package-parser.ts      # package.json/lock parser
│   │   ├── semver-utils.ts        # Version utilities
│   │   └── logger.ts              # Logging utilities
│   └── types/
│       ├── vulnerability.ts        # Type definitions
│       └── config.ts              # Configuration types
├── .github/
│   └── workflows/
│       └── action.yml              # GitHub Action definition
├── tests/
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   └── fixtures/                   # Test data
├── docs/
│   ├── README.md                   # Main documentation
│   ├── USAGE.md                    # Usage guide
│   └── API.md                      # API documentation
├── examples/
│   ├── basic-scan/                 # Example projects
│   └── github-action/
├── .env.example                    # Environment variables template
├── .eslintrc.json                  # ESLint configuration
├── .prettierrc                     # Prettier configuration
├── tsconfig.json                   # TypeScript configuration
├── vitest.config.ts                # Vitest configuration
├── package.json                    # Package manifest
└── LICENSE                         # MIT License
```

---

## Core Features Implementation

### 1. Vulnerability Scanner (`src/core/scanner.ts`)

**Requirements:**
- Parse `package.json` and `package-lock.json` (or `pnpm-lock.yaml`, `yarn.lock`)
- Extract all dependencies (direct and transitive)
- Query multiple vulnerability databases (OSV, Snyk, npm audit)
- Aggregate and deduplicate results
- Calculate severity scores (CVSS)
- Generate comprehensive vulnerability report

**Key Functions:**
```typescript
interface ScanResult {
  vulnerabilities: Vulnerability[];
  totalPackages: number;
  vulnerablePackages: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scanDuration: number;
}

async function scanProject(projectPath: string): Promise<ScanResult>
async function scanPackage(packageName: string, version: string): Promise<Vulnerability[]>
async function scanLockFile(lockFilePath: string): Promise<ScanResult>
```

### 2. Supply Chain Attack Detector (`src/core/detector.ts`)

**Requirements:**
- Detect typosquatting attempts (similar package names)
- Identify packages with suspicious install scripts
- Check for recently published packages with high download spikes
- Verify package maintainer authenticity
- Detect packages with malicious code patterns
- Monitor for compromised maintainer accounts

**Detection Patterns:**
```typescript
interface SupplyChainThreat {
  type: 'typosquatting' | 'malicious-script' | 'compromised-maintainer' | 'suspicious-activity';
  packageName: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence: string[];
  recommendations: string[];
}

async function detectThreats(dependencies: Dependency[]): Promise<SupplyChainThreat[]>
async function checkTyposquatting(packageName: string): Promise<boolean>
async function analyzeInstallScripts(packageName: string): Promise<SecurityIssue[]>
```

### 3. Safe Upgrade Calculator (`src/core/updater.ts`)

**Requirements:**
- Find safe upgrade paths that fix vulnerabilities
- Check for breaking changes between versions
- Verify that upgrades don't introduce new vulnerabilities
- Suggest alternative packages if no safe upgrade exists
- Generate upgrade instructions

**Key Functions:**
```typescript
interface UpgradePath {
  packageName: string;
  currentVersion: string;
  targetVersion: string;
  isBreaking: boolean;
  fixedVulnerabilities: string[];
  changelogUrl: string;
  confidence: 'high' | 'medium' | 'low';
}

async function calculateUpgradePath(
  packageName: string, 
  currentVersion: string, 
  vulnerabilities: Vulnerability[]
): Promise<UpgradePath>

async function findSafeVersion(
  packageName: string, 
  constraint: string
): Promise<string | null>
```

### 4. GitHub PR Creation (`src/integrations/github.ts`)

**Requirements:**
- Authenticate with GitHub API (personal token or GitHub Actions token)
- Create branches for dependency updates
- Generate detailed PR descriptions with vulnerability info
- Add labels (security, dependencies, automated)
- Request reviews from code owners
- Support multiple PRs for different severity levels

**PR Template:**
```markdown
## 🔒 Security Update: [Package Name]

### Vulnerability Summary
- **Severity:** [Critical/High/Medium/Low]
- **CVE ID:** [CVE-2024-XXXXX]
- **Affected Versions:** [1.0.0 - 1.5.0]
- **Fixed Version:** [1.5.1]

### Description
[Detailed vulnerability description]

### Changes
- Update `[package-name]` from `[old-version]` to `[new-version]`

### Breaking Changes
[None / List of breaking changes]

### Testing Recommendations
- [ ] Run full test suite
- [ ] Manual testing of affected features
- [ ] Security verification

---
*This PR was automatically created by [dependency-firewall](https://github.com/yourusername/dependency-firewall)*
```

### 5. CLI Interface (`src/cli.ts`)

**Commands:**
```bash
# Basic scan
dependency-firewall scan [path]

# Scan and create PR
dependency-firewall scan --fix --pr

# Watch mode (continuous monitoring)
dependency-firewall watch

# Generate report
dependency-firewall report --format json|markdown

# Check specific package
dependency-firewall check <package-name>

# Configure
dependency-firewall init
dependency-firewall config set <key> <value>

# Audit supply chain
dependency-firewall audit-supply-chain
```

**Options:**
```
--severity <level>       Only report vulnerabilities of specified severity
--ignore <packages>      Comma-separated list of packages to ignore
--pr                     Create GitHub PR for fixes
--fix                    Automatically update dependencies
--json                   Output results as JSON
--markdown               Generate Markdown report
--config <path>          Path to config file
--watch                  Continuous monitoring mode
```

---

## Configuration File

**`.dependency-firewall.json`:**
```json
{
  "scan": {
    "paths": [".", "./packages/*"],
    "exclude": ["node_modules", "dist", "build"],
    "severity": "medium",
    "ignoredPackages": [],
    "ignoredVulnerabilities": []
  },
  "github": {
    "enabled": true,
    "token": "${GITHUB_TOKEN}",
    "repository": "owner/repo",
    "baseBranch": "main",
    "labels": ["security", "dependencies", "automated"],
    "reviewers": ["@team/security"],
    "separatePRs": true,
    "prTitle": "🔒 Security: Update [package] to fix [vulnerability]"
  },
  "notifications": {
    "slack": {
      "enabled": false,
      "webhookUrl": "${SLACK_WEBHOOK}"
    },
    "email": {
      "enabled": false,
      "recipients": []
    }
  },
  "ci": {
    "failOnVulnerabilities": true,
    "failOnSeverity": "high",
    "failOnSupplyChainThreats": true
  }
}
```

---

## GitHub Action

**`.github/workflows/dependency-firewall.yml`:**
```yaml
name: Dependency Firewall

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  push:
    branches: [main]
    paths:
      - 'package.json'
      - 'package-lock.json'
      - 'pnpm-lock.yaml'
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      issues: write
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
      
      - name: Run Dependency Firewall
        uses: yourusername/dependency-firewall@v1
        with:
          severity: 'high'
          create-pr: true
          fail-on-vulnerabilities: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: dependency-firewall-report.json
```

---

## Testing Strategy

### Unit Tests
- Test individual functions (scanner, detector, updater)
- Mock external API calls
- Test edge cases and error handling
- Verify vulnerability severity calculations

### Integration Tests
- Test full scan workflow
- Test GitHub PR creation (using test repository)
- Test with real package.json files
- Test multiple lock file formats

### Test Data
- Create fixtures with known vulnerabilities
- Mock OSV/Snyk API responses
- Sample package.json files with various dependency trees

**Example Test:**
```typescript
import { describe, it, expect, vi } from 'vitest';
import { scanProject } from '../src/core/scanner';

describe('Scanner', () => {
  it('should detect critical vulnerabilities', async () => {
    const result = await scanProject('./tests/fixtures/vulnerable-project');
    
    expect(result.criticalCount).toBeGreaterThan(0);
    expect(result.vulnerabilities).toHaveLength(3);
    expect(result.vulnerabilities[0].severity).toBe('critical');
  });

  it('should handle missing package.json gracefully', async () => {
    await expect(
      scanProject('./non-existent')
    ).rejects.toThrow('package.json not found');
  });
});
```

---

## API Integration Details

### OSV (Open Source Vulnerabilities)
**Endpoint:** `https://osv.dev/v1/query`

```typescript
interface OSVQuery {
  package: {
    name: string;
    ecosystem: 'npm';
  };
  version?: string;
}

interface OSVResponse {
  vulns: Array<{
    id: string;
    summary: string;
    details: string;
    severity: Array<{
      type: 'CVSS_V3';
      score: string;
    }>;
    affected: Array<{
      package: { name: string; ecosystem: string };
      ranges: Array<{ type: string; events: Array<any> }>;
    }>;
    references: Array<{ type: string; url: string }>;
  }>;
}
```

### GitHub API (for PR Creation)
```typescript
import { Octokit } from '@octokit/rest';

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

// Create branch
await octokit.git.createRef({
  owner,
  repo,
  ref: `refs/heads/security-update-${packageName}`,
  sha: baseSha
});

// Update package.json
await octokit.repos.createOrUpdateFileContents({
  owner,
  repo,
  path: 'package.json',
  message: 'chore: update dependencies for security',
  content: Buffer.from(updatedPackageJson).toString('base64'),
  branch: branchName
});

// Create PR
await octokit.pulls.create({
  owner,
  repo,
  title: prTitle,
  head: branchName,
  base: 'main',
  body: prDescription
});
```

---

## package.json Configuration

```json
{
  "name": "dependency-firewall",
  "version": "1.0.0",
  "description": "Real-time npm vulnerability scanning with automatic PR creation for security patches and supply chain attack detection",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "bin": {
    "dependency-firewall": "./dist/cli.js"
  },
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  },
  "files": [
    "dist",
    "README.md",
    "LICENSE"
  ],
  "scripts": {
    "build": "tsc",
    "dev": "tsx watch src/cli.ts",
    "test": "vitest",
    "test:coverage": "vitest --coverage",
    "lint": "eslint src --ext .ts",
    "format": "prettier --write \"src/**/*.ts\"",
    "prepare": "husky install",
    "prepublishOnly": "pnpm build && pnpm test"
  },
  "keywords": [
    "security",
    "vulnerability",
    "npm",
    "dependencies",
    "supply-chain",
    "audit",
    "scanner",
    "github-action",
    "cli"
  ],
  "author": "Your Name <[email protected]>",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/yourusername/dependency-firewall.git"
  },
  "bugs": {
    "url": "https://github.com/yourusername/dependency-firewall/issues"
  },
  "homepage": "https://github.com/yourusername/dependency-firewall#readme",
  "engines": {
    "node": ">=18.0.0"
  },
  "dependencies": {
    "commander": "^12.0.0",
    "chalk": "^5.3.0",
    "ora": "^8.0.1",
    "@octokit/rest": "^20.0.2",
    "semver": "^7.5.4",
    "node-fetch": "^3.3.2",
    "zod": "^3.22.4",
    "dotenv": "^16.4.5"
  },
  "devDependencies": {
    "@types/node": "^20.11.0",
    "@types/semver": "^7.5.6",
    "vitest": "^1.2.0",
    "@vitest/coverage-v8": "^1.2.0",
    "eslint": "^8.56.0",
    "@typescript-eslint/eslint-plugin": "^6.19.0",
    "@typescript-eslint/parser": "^6.19.0",
    "prettier": "^3.2.4",
    "tsx": "^4.7.0",
    "typescript": "^5.3.3",
    "husky": "^9.0.0",
    "lint-staged": "^15.2.0"
  }
}
```

---

## tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "lib": ["ES2022"],
    "moduleResolution": "node",
    "rootDir": "./src",
    "outDir": "./dist",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "allowSyntheticDefaultImports": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

---

## Implementation Phases

### Phase 1: Core Scanning (Week 1)
- [ ] Project setup (TypeScript, package.json, configs)
- [ ] Implement package.json parser
- [ ] Implement lock file parser (npm, pnpm, yarn)
- [ ] Build OSV API client
- [ ] Build npm audit wrapper
- [ ] Create vulnerability aggregator
- [ ] Implement basic CLI
- [ ] Write unit tests

### Phase 2: Advanced Detection (Week 2)
- [ ] Implement supply chain attack detector
- [ ] Add typosquatting detection
- [ ] Add malicious script detection
- [ ] Integrate Snyk API (optional)
- [ ] Implement severity scoring
- [ ] Create console reporter
- [ ] Add integration tests

### Phase 3: Auto-fixing (Week 3)
- [ ] Implement safe upgrade calculator
- [ ] Add breaking change detection
- [ ] Build GitHub API integration
- [ ] Implement PR creation logic
- [ ] Create PR templates
- [ ] Add configuration file support
- [ ] Test GitHub integration

### Phase 4: CI/CD & Polish (Week 4)
- [ ] Create GitHub Action
- [ ] Add watch mode for continuous monitoring
- [ ] Implement JSON/Markdown reporters
- [ ] Add Slack notifications (optional)
- [ ] Write comprehensive documentation
- [ ] Create usage examples
- [ ] Final testing and bug fixes
- [ ] Publish to npm

---

## Success Criteria

### Functional Requirements
- ✅ Successfully scan projects and detect known vulnerabilities
- ✅ Identify supply chain threats (typosquatting, malicious packages)
- ✅ Calculate safe upgrade paths
- ✅ Create GitHub PRs automatically
- ✅ Work as both CLI and GitHub Action
- ✅ Support multiple lock file formats

### Performance Requirements
- Scan 500 dependencies in under 30 seconds
- Memory usage under 200MB
- Support projects with 10,000+ transitive dependencies

### Quality Requirements
- 80%+ test coverage
- Zero critical bugs
- Clear error messages
- Comprehensive documentation
- TypeScript with strict mode

---

## Documentation Requirements

### README.md
- Overview and features
- Installation instructions
- Quick start guide
- CLI usage examples
- GitHub Action setup
- Configuration options
- Screenshots/GIFs of CLI output

### USAGE.md
- Detailed command reference
- Configuration file format
- Integration guides (CI/CD)
- Troubleshooting
- FAQ

### API.md
- Programmatic usage
- TypeScript types
- Function references
- Code examples

---

## Publishing Checklist

Before publishing to npm:
- [ ] All tests passing
- [ ] Documentation complete
- [ ] Examples working
- [ ] Version bumped (following semver)
- [ ] CHANGELOG.md updated
- [ ] GitHub repo created with README
- [ ] GitHub Action tested
- [ ] npm account verified
- [ ] License file included
- [ ] Security contact in package.json

---

## Future Enhancements (v2.0)

- **Automatic dependency updates** in watch mode
- **Machine learning** for detecting zero-day vulnerabilities
- **Integration with Dependabot** for coordinated updates
- **Slack/Discord notifications**
- **GitLab/Bitbucket support**
- **Custom vulnerability database** support
- **Policy enforcement** (block packages based on rules)
- **Audit logs and reports** dashboard
- **Team collaboration features**

---

## Additional Resources

### References
- OSV API Documentation: https://osv.dev/docs/
- GitHub API Documentation: https://docs.github.com/rest
- npm audit Documentation: https://docs.npmjs.com/cli/audit
- Snyk Vulnerability Database: https://security.snyk.io/

### Similar Tools (for inspiration)
- Snyk CLI
- npm-check-updates
- Dependabot
- Renovate Bot

### Community
- Report issues: GitHub Issues
- Discussions: GitHub Discussions
- Security reports: [email protected]

---

**Let's build something that makes the JavaScript ecosystem safer! 🔒**