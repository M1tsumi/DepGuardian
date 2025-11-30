import { Octokit } from '@octokit/rest';
import { Vulnerability, UpgradePath, SupplyChainThreat } from '../types/vulnerability.js';
import { logger } from '../utils/logger.js';
import { readFile } from 'fs/promises';
import { join } from 'path';

export interface GitHubConfig {
  token: string;
  repository: string;
  baseBranch: string;
  labels: string[];
  reviewers: string[];
  separatePRs: boolean;
  prTitle: string;
}

export interface PRCreationResult {
  success: boolean;
  prUrl?: string;
  error?: string;
  branchName?: string;
}

export class GitHubIntegration {
  private octokit: Octokit;
  private config: GitHubConfig;

  constructor(config: GitHubConfig) {
    this.config = config;
    this.octokit = new Octokit({ auth: config.token });
  }

  async createSecurityPRs(
    vulnerabilities: Vulnerability[],
    upgradePaths: UpgradePath[],
    supplyChainThreats: SupplyChainThreat[],
    projectPath: string
  ): Promise<PRCreationResult[]> {
    logger.info(`Creating GitHub PRs for ${vulnerabilities.length} vulnerabilities`);
    
    const results: PRCreationResult[] = [];
    
    if (this.config.separatePRs) {
      // Create separate PR for each vulnerability/upgrade
      for (const upgradePath of upgradePaths) {
        const result = await this.createSingleUpgradePR(upgradePath, projectPath);
        results.push(result);
      }
    } else {
      // Create one PR for all upgrades
      const result = await this.createBatchUpgradePR(upgradePaths, projectPath);
      results.push(result);
    }
    
    // Create PR for supply chain threats if any
    if (supplyChainThreats.length > 0) {
      const result = await this.createSupplyChainPR(supplyChainThreats, projectPath);
      results.push(result);
    }
    
    return results;
  }

  private async createSingleUpgradePR(upgradePath: UpgradePath, projectPath: string): Promise<PRCreationResult> {
    try {
      const [owner, repo] = this.config.repository.split('/');
      const branchName = `security-update-${upgradePath.packageName}-${upgradePath.targetVersion}`;
      
      logger.info(`Creating PR for ${upgradePath.packageName}: ${upgradePath.currentVersion} -> ${upgradePath.targetVersion}`);
      
      // Get base branch SHA
      const { data: baseBranch } = await this.octokit.git.getRef({
        owner,
        repo,
        ref: `heads/${this.config.baseBranch}`,
      });
      
      // Create new branch
      await this.octokit.git.createRef({
        owner,
        repo,
        ref: `refs/heads/${branchName}`,
        sha: baseBranch.object.sha,
      });
      
      // Update package.json
      const packageJsonPath = join(projectPath, 'package.json');
      const packageJsonContent = await readFile(packageJsonPath, 'utf-8');
      const packageJson = JSON.parse(packageJsonContent);
      
      // Update the dependency version
      this.updateDependencyVersion(packageJson, upgradePath.packageName, upgradePath.targetVersion);
      
      const updatedPackageJson = JSON.stringify(packageJson, null, 2);
      
      // Commit the changes
      await this.octokit.repos.createOrUpdateFileContents({
        owner,
        repo,
        path: 'package.json',
        message: `chore: update ${upgradePath.packageName} to ${upgradePath.targetVersion}`,
        content: Buffer.from(updatedPackageJson).toString('base64'),
        branch: branchName,
        sha: await this.getFileSha(owner, repo, 'package.json', this.config.baseBranch),
      });
      
      // Generate PR description
      const prTitle = this.config.prTitle
        .replace('[package]', upgradePath.packageName)
        .replace('[vulnerability]', upgradePath.fixedVulnerabilities.join(', '));
      
      const prDescription = this.generatePRDescription(upgradePath, []);
      
      // Create PR
      const { data: pr } = await this.octokit.pulls.create({
        owner,
        repo,
        title: prTitle,
        head: branchName,
        base: this.config.baseBranch,
        body: prDescription,
      });
      
      // Add labels
      if (this.config.labels.length > 0) {
        await this.octokit.issues.addLabels({
          owner,
          repo,
          issue_number: pr.number,
          labels: this.config.labels,
        });
      }
      
      // Request reviewers
      if (this.config.reviewers.length > 0) {
        await this.octokit.pulls.requestReviewers({
          owner,
          repo,
          pull_number: pr.number,
          reviewers: this.config.reviewers,
        });
      }
      
      logger.info(`PR created: ${pr.html_url}`);
      
      return {
        success: true,
        prUrl: pr.html_url,
        branchName,
      };
      
    } catch (error) {
      logger.error(`Failed to create PR for ${upgradePath.packageName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async createBatchUpgradePR(upgradePaths: UpgradePath[], projectPath: string): Promise<PRCreationResult> {
    try {
      const [owner, repo] = this.config.repository.split('/');
      const branchName = `security-updates-batch-${Date.now()}`;
      
      logger.info(`Creating batch PR for ${upgradePaths.length} updates`);
      
      // Get base branch SHA
      const { data: baseBranch } = await this.octokit.git.getRef({
        owner,
        repo,
        ref: `heads/${this.config.baseBranch}`,
      });
      
      // Create new branch
      await this.octokit.git.createRef({
        owner,
        repo,
        ref: `refs/heads/${branchName}`,
        sha: baseBranch.object.sha,
      });
      
      // Update package.json
      const packageJsonPath = join(projectPath, 'package.json');
      const packageJsonContent = await readFile(packageJsonPath, 'utf-8');
      const packageJson = JSON.parse(packageJsonContent);
      
      // Update all dependencies
      for (const upgradePath of upgradePaths) {
        this.updateDependencyVersion(packageJson, upgradePath.packageName, upgradePath.targetVersion);
      }
      
      const updatedPackageJson = JSON.stringify(packageJson, null, 2);
      
      // Commit the changes
      await this.octokit.repos.createOrUpdateFileContents({
        owner,
        repo,
        path: 'package.json',
        message: `chore: security updates for ${upgradePaths.length} packages`,
        content: Buffer.from(updatedPackageJson).toString('base64'),
        branch: branchName,
        sha: await this.getFileSha(owner, repo, 'package.json', this.config.baseBranch),
      });
      
      // Generate PR description
      const prTitle = `🔒 Security: Update ${upgradePaths.length} packages to fix vulnerabilities`;
      const prDescription = this.generateBatchPRDescription(upgradePaths);
      
      // Create PR
      const { data: pr } = await this.octokit.pulls.create({
        owner,
        repo,
        title: prTitle,
        head: branchName,
        base: this.config.baseBranch,
        body: prDescription,
      });
      
      // Add labels
      if (this.config.labels.length > 0) {
        await this.octokit.issues.addLabels({
          owner,
          repo,
          issue_number: pr.number,
          labels: this.config.labels,
        });
      }
      
      // Request reviewers
      if (this.config.reviewers.length > 0) {
        await this.octokit.pulls.requestReviewers({
          owner,
          repo,
          pull_number: pr.number,
          reviewers: this.config.reviewers,
        });
      }
      
      logger.info(`Batch PR created: ${pr.html_url}`);
      
      return {
        success: true,
        prUrl: pr.html_url,
        branchName,
      };
      
    } catch (error) {
      logger.error(`Failed to create batch PR: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async createSupplyChainPR(threats: SupplyChainThreat[], projectPath: string): Promise<PRCreationResult> {
    try {
      const [owner, repo] = this.config.repository.split('/');
      const branchName = `supply-chain-alert-${Date.now()}`;
      
      logger.info(`Creating supply chain alert PR for ${threats.length} threats`);
      
      // Get base branch SHA
      const { data: baseBranch } = await this.octokit.git.getRef({
        owner,
        repo,
        ref: `heads/${this.config.baseBranch}`,
      });
      
      // Create new branch
      await this.octokit.git.createRef({
        owner,
        repo,
        ref: `refs/heads/${branchName}`,
        sha: baseBranch.object.sha,
      });
      
      // Create a report file
      const reportContent = this.generateSupplyChainReport(threats);
      
      await this.octokit.repos.createOrUpdateFileContents({
        owner,
        repo,
        path: 'SUPPLY_CHAIN_ALERT.md',
        message: 'docs: add supply chain security alert report',
        content: Buffer.from(reportContent).toString('base64'),
        branch: branchName,
      });
      
      // Generate PR description
      const prTitle = '🚨 Supply Chain Security Alert';
      const prDescription = this.generateSupplyChainPRDescription(threats);
      
      // Create PR
      const { data: pr } = await this.octokit.pulls.create({
        owner,
        repo,
        title: prTitle,
        head: branchName,
        base: this.config.baseBranch,
        body: prDescription,
      });
      
      // Add labels
      await this.octokit.issues.addLabels({
        owner,
        repo,
        issue_number: pr.number,
        labels: ['security', 'supply-chain', 'alert'],
      });
      
      logger.info(`Supply chain alert PR created: ${pr.html_url}`);
      
      return {
        success: true,
        prUrl: pr.html_url,
        branchName,
      };
      
    } catch (error) {
      logger.error(`Failed to create supply chain PR: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private updateDependencyVersion(packageJson: any, packageName: string, newVersion: string): void {
    // Update dependencies
    if (packageJson.dependencies && packageJson.dependencies[packageName]) {
      packageJson.dependencies[packageName] = newVersion;
    }
    
    // Update devDependencies
    if (packageJson.devDependencies && packageJson.devDependencies[packageName]) {
      packageJson.devDependencies[packageName] = newVersion;
    }
    
    // Update peerDependencies
    if (packageJson.peerDependencies && packageJson.peerDependencies[packageName]) {
      packageJson.peerDependencies[packageName] = newVersion;
    }
    
    // Update optionalDependencies
    if (packageJson.optionalDependencies && packageJson.optionalDependencies[packageName]) {
      packageJson.optionalDependencies[packageName] = newVersion;
    }
  }

  private async getFileSha(owner: string, repo: string, path: string, branch: string): Promise<string> {
    try {
      const { data: file } = await this.octokit.repos.getContent({
        owner,
        repo,
        path,
        ref: branch,
      });
      
      return (file as any).sha;
    } catch (error) {
      // File might not exist, return empty string
      return '';
    }
  }

  private generatePRDescription(upgradePath: UpgradePath, additionalThreats: SupplyChainThreat[]): string {
    const vulnerability = upgradePath.fixedVulnerabilities.length > 0 ? upgradePath.fixedVulnerabilities[0] : '';
    
    let description = `## 🔒 Security Update: ${upgradePath.packageName}

### Vulnerability Summary
- **Severity:** High
- **CVE ID:** ${vulnerability}
- **Affected Versions:** ${upgradePath.currentVersion}
- **Fixed Version:** ${upgradePath.targetVersion}

### Description
This update fixes security vulnerabilities found in the \`${upgradePath.packageName}\` package.

### Changes
- Update \`${upgradePath.packageName}\` from \`${upgradePath.currentVersion}\` to \`${upgradePath.targetVersion}\`

### Breaking Changes
${upgradePath.isBreaking ? '⚠️ **This is a breaking change.** Please review your code for compatibility issues.' : 'None'}

### Risk Assessment
- **Confidence:** ${upgradePath.confidence}
- **Risk Score:** ${upgradePath.riskScore}
`;

    if (upgradePath.changelogUrl) {
      description += `\n### Changelog
- [View changelog](${upgradePath.changelogUrl})
`;
    }

    description += `
### Testing Recommendations
- [ ] Run full test suite
- [ ] Manual testing of affected features
- [ ] Security verification

---

*This PR was automatically created by [DepGuardian](https://github.com/M1tsumi/DepGuardian)*
`;

    return description;
  }

  private generateBatchPRDescription(upgradePaths: UpgradePath[]): string {
    let description = `## 🔒 Security Updates: Multiple Packages

### Summary
This PR addresses security vulnerabilities in ${upgradePaths.length} packages.

### Changes
`;

    for (const upgradePath of upgradePaths) {
      const breakingIndicator = upgradePath.isBreaking ? ' ⚠️' : '';
      description += `- Update \`${upgradePath.packageName}\` from \`${upgradePath.currentVersion}\` to \`${upgradePath.targetVersion}\`${breakingIndicator}\n`;
    }

    description += `
### Breaking Changes
${upgradePaths.some(p => p.isBreaking) ? '⚠️ **Some updates include breaking changes.** Please review your code for compatibility issues.' : 'None'}

### Testing Recommendations
- [ ] Run full test suite
- [ ] Manual testing of affected features
- [ ] Security verification

---

*This PR was automatically created by [DepGuardian](https://github.com/M1tsumi/DepGuardian)*
`;

    return description;
  }

  private generateSupplyChainReport(threats: SupplyChainThreat[]): string {
    let report = `# Supply Chain Security Alert

**Generated:** ${new Date().toISOString()}

## Summary
Found ${threats.length} potential supply chain threats in your dependencies.

## Threats by Severity
`;

    const groupedThreats = threats.reduce((acc, threat) => {
      if (!acc[threat.severity]) acc[threat.severity] = [];
      acc[threat.severity].push(threat);
      return acc;
    }, {} as Record<string, SupplyChainThreat[]>);

    const severityOrder = ['critical', 'high', 'medium', 'low'];

    for (const severity of severityOrder) {
      const severityThreats = groupedThreats[severity];
      if (severityThreats && severityThreats.length > 0) {
        report += `### ${severity.toUpperCase()} (${severityThreats.length})\n\n`;
        
        for (const threat of severityThreats) {
          report += `#### ${threat.packageName} - ${threat.type}\n\n`;
          report += `**Description:** ${threat.description}\n\n`;
          report += `**Evidence:**\n`;
          threat.evidence.forEach(evidence => {
            report += `- ${evidence}\n`;
          });
          report += `\n**Recommendations:**\n`;
          threat.recommendations.forEach(rec => {
            report += `- ${rec}\n`;
          });
          report += `\n---\n\n`;
        }
      }
    }

    report += `## Recommended Actions
1. Review all critical and high severity threats immediately
2. Remove or replace suspicious packages
3. Audit your dependency tree for similar issues
4. Implement stricter dependency review processes

## About This Report
This report was generated by [DepGuardian](https://github.com/M1tsumi/DepGuardian), a security tool that detects supply chain threats in npm dependencies.
`;

    return report;
  }

  private generateSupplyChainPRDescription(threats: SupplyChainThreat[]): string {
    const criticalCount = threats.filter(t => t.severity === 'critical').length;
    const highCount = threats.filter(t => t.severity === 'high').length;
    
    let description = `## 🚨 Supply Chain Security Alert

### Summary
Found ${threats.length} potential supply chain threats in your dependencies, including:
- ${criticalCount} critical threats
- ${highCount} high threats

### Details
This PR adds a comprehensive security report (SUPPLY_CHAIN_ALERT.md) with detailed information about all detected threats, including:
- Typosquatting attacks
- Malicious install scripts  
- Suspicious publishing activity
- Compromised maintainer accounts

### Immediate Action Required
1. Review the SUPPLY_CHAIN_ALERT.md file
2. Address all critical and high severity threats
3. Remove or replace suspicious packages
4. Audit your dependency tree

### Next Steps
- Implement stricter dependency review processes
- Consider using a lockfile to prevent package substitution attacks
- Set up automated security scanning in your CI/CD pipeline

---

*This alert was generated by [DepGuardian](https://github.com/M1tsumi/DepGuardian)*
`;

    return description;
  }
}
