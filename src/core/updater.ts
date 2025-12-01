import { Vulnerability, UpgradePath, Dependency } from '../types/vulnerability.js';
import { readFile } from 'fs/promises';
import { SemverUtils } from '../utils/semver-utils.js';
import { OSVClient } from '../integrations/osv.js';
import { logger } from '../utils/logger.js';
import fetch from 'node-fetch';

export class SafeUpgradeCalculator {
  private semverUtils: SemverUtils;
  private osvClient: OSVClient;

  constructor() {
    this.semverUtils = new SemverUtils();
    this.osvClient = new OSVClient();
  }

  async calculateUpgradePath(
    packageName: string, 
    currentVersion: string, 
    vulnerabilities: Vulnerability[]
  ): Promise<UpgradePath | null> {
    logger.info(`Calculating safe upgrade path for ${packageName}@${currentVersion}`);
    
    try {
      // Get all available versions from npm registry
      const availableVersions = await this.getAvailableVersions(packageName);
      
      if (availableVersions.length === 0) {
        logger.warn(`No available versions found for ${packageName}`);
        return null;
      }

      // Find versions that fix the vulnerabilities
      const fixedVersions = this.findFixedVersions(vulnerabilities, availableVersions);
      
      if (fixedVersions.length === 0) {
        logger.warn(`No versions found that fix vulnerabilities for ${packageName}`);
        return null;
      }

      // Find the safest upgrade path
      const targetVersion = this.findSafestUpgrade(currentVersion, fixedVersions, availableVersions);
      
      if (!targetVersion) {
        logger.warn(`No safe upgrade path found for ${packageName}`);
        return null;
      }

      // Verify the target version doesn't introduce new vulnerabilities
      const newVulnerabilities = await this.osvClient.queryVulnerabilities(packageName, targetVersion);
      
      const upgradePath: UpgradePath = {
        packageName,
        currentVersion,
        targetVersion,
        isBreaking: this.semverUtils.isBreakingUpgrade(currentVersion, targetVersion),
        fixedVulnerabilities: vulnerabilities.map(v => v.id),
        changelogUrl: await this.getChangelogUrl(packageName, currentVersion, targetVersion),
        confidence: this.calculateConfidence(currentVersion, targetVersion, fixedVersions),
        riskScore: this.calculateRiskScore(vulnerabilities, newVulnerabilities, currentVersion, targetVersion),
      };

      logger.info(`Safe upgrade path found: ${currentVersion} -> ${targetVersion}`);
      return upgradePath;
      
    } catch (error) {
      logger.error(`Failed to calculate upgrade path for ${packageName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return null;
    }
  }

  async findSafeVersion(
    packageName: string, 
    constraint: string
  ): Promise<string | null> {
    try {
      const availableVersions = await this.getAvailableVersions(packageName);
      const satisfyingVersions = this.semverUtils.versionsInRange(availableVersions, constraint);
      
      if (satisfyingVersions.length === 0) {
        return null;
      }

      // Get the latest satisfying version that doesn't have vulnerabilities
      const sortedVersions = satisfyingVersions.sort((a, b) => this.semverUtils.greaterThan(a, b) ? -1 : 1);
      const latestVersion = sortedVersions[0];
      
      if (!latestVersion) {
        return null;
      }

      // Check for vulnerabilities in the latest version
      const vulnerabilities = await this.osvClient.queryVulnerabilities(packageName, latestVersion);
      
      // If there are critical vulnerabilities, try the next version
      if (vulnerabilities.some(v => v.severity === 'critical')) {
        for (const version of sortedVersions) {
          const vulns = await this.osvClient.queryVulnerabilities(packageName, version);
          if (!vulns.some(v => v.severity === 'critical')) {
            return version;
          }
        }
        
        return null; // No safe version found
      }

      return latestVersion;
      
    } catch (error) {
      logger.error(`Failed to find safe version for ${packageName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return null;
    }
  }

  private async getAvailableVersions(packageName: string): Promise<string[]> {
    try {
      const response = await fetch(`https://registry.npmjs.org/${packageName}`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch package info: ${response.status}`);
      }
      
      const packageInfo = await response.json() as any;
      
      if (!packageInfo.versions) {
        return [];
      }
      
      return Object.keys(packageInfo.versions);
      
    } catch (error) {
      logger.warn(`Failed to get available versions for ${packageName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  private findFixedVersions(vulnerabilities: Vulnerability[], availableVersions: string[]): string[] {
    const fixedVersions: string[] = [];
    
    for (const vulnerability of vulnerabilities) {
      if (vulnerability.patchedVersions) {
        for (const patchedVersion of vulnerability.patchedVersions) {
          if (availableVersions.includes(patchedVersion)) {
            fixedVersions.push(patchedVersion);
          }
        }
      }
      
      // Also check if firstPatchedVersion is available
      if (vulnerability.firstPatchedVersion && availableVersions.includes(vulnerability.firstPatchedVersion)) {
        fixedVersions.push(vulnerability.firstPatchedVersion);
      }
    }
    
    // Remove duplicates and sort
    return [...new Set(fixedVersions)].sort((a, b) => this.semverUtils.greaterThan(a, b) ? -1 : 1);
  }

  private findSafestUpgrade(
    currentVersion: string, 
    fixedVersions: string[], 
    availableVersions: string[]
  ): string | null {
    // Prefer non-breaking upgrades first
    const nonBreakingUpgrades = fixedVersions.filter(version => 
      !this.semverUtils.isBreakingUpgrade(currentVersion, version)
    );
    
    if (nonBreakingUpgrades.length > 0) {
      // Return the highest non-breaking version that fixes issues
      return this.semverUtils.maxVersion(nonBreakingUpgrades);
    }
    
    // If only breaking upgrades are available, return the lowest one that fixes issues
    const sortedBreakingUpgrades = fixedVersions
      .filter(version => this.semverUtils.isBreakingUpgrade(currentVersion, version))
      .sort((a, b) => this.semverUtils.greaterThan(a, b) ? -1 : 1); // Sort descending, then take lowest
    
    return sortedBreakingUpgrades[sortedBreakingUpgrades.length - 1] || null;
  }

  private calculateConfidence(
    currentVersion: string, 
    targetVersion: string, 
    fixedVersions: string[]
  ): UpgradePath['confidence'] {
    // High confidence: direct upgrade to a patched version
    if (fixedVersions.includes(targetVersion)) {
      return 'high';
    }
    
    // Medium confidence: minor version increase
    if (this.semverUtils.sameMajorVersion(currentVersion, targetVersion)) {
      return 'medium';
    }
    
    // Low confidence: major version increase or unusual version jump
    return 'low';
  }

  private calculateRiskScore(
    currentVulnerabilities: Vulnerability[],
    newVulnerabilities: Vulnerability[],
    currentVersion: string,
    targetVersion: string
  ): number {
    let riskScore = 0;
    
    // Add risk based on current vulnerabilities
    for (const vuln of currentVulnerabilities) {
      switch (vuln.severity) {
        case 'critical':
          riskScore += 10;
          break;
        case 'high':
          riskScore += 5;
          break;
        case 'medium':
          riskScore += 2;
          break;
        case 'low':
          riskScore += 1;
          break;
      }
    }
    
    // Subtract benefit from fixing vulnerabilities
    riskScore -= currentVulnerabilities.length * 3;
    
    // Add risk for new vulnerabilities introduced
    for (const vuln of newVulnerabilities) {
      switch (vuln.severity) {
        case 'critical':
          riskScore += 8;
          break;
        case 'high':
          riskScore += 4;
          break;
        case 'medium':
          riskScore += 2;
          break;
        case 'low':
          riskScore += 1;
          break;
      }
    }
    
    // Add risk for breaking changes
    if (this.semverUtils.isBreakingUpgrade(currentVersion, targetVersion)) {
      riskScore += 3;
    }
    
    // Ensure score is non-negative
    return Math.max(0, riskScore);
  }

  private async getChangelogUrl(packageName: string, fromVersion: string, toVersion: string): Promise<string | undefined> {
    try {
      // Try to construct GitHub changelog URL
      const response = await fetch(`https://registry.npmjs.org/${packageName}`);
      
      if (!response.ok) {
        return undefined;
      }
      
      const packageInfo = await response.json() as any;
      const repository = packageInfo.repository;
      
      if (repository && repository.url) {
        // Extract GitHub repo from URL
        const githubMatch = repository.url.match(/github\.com\/([^\/]+\/[^\/]+)/);
        if (githubMatch) {
          const repo = githubMatch[1].replace('.git', '');
          return `https://github.com/${repo}/compare/v${fromVersion}...v${toVersion}`;
        }
      }
      
      return undefined;
      
    } catch (error) {
      logger.debug(`Failed to get changelog URL for ${packageName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return undefined;
    }
  }

  async calculateAllUpgradePaths(dependencies: Dependency[], vulnerabilities: Vulnerability[]): Promise<UpgradePath[]> {
    logger.info(`Calculating upgrade paths for ${dependencies.length} dependencies`);
    
    const upgradePaths: UpgradePath[] = [];
    
    // Group vulnerabilities by package
    const vulnsByPackage = vulnerabilities.reduce((acc, vuln) => {
      if (!acc[vuln.packageName]) {
        acc[vuln.packageName] = [];
      }
      acc[vuln.packageName].push(vuln);
      return acc;
    }, {} as Record<string, Vulnerability[]>);
    
    // Calculate upgrade paths for packages with vulnerabilities
    for (const [packageName, packageVulns] of Object.entries(vulnsByPackage)) {
      const dependency = dependencies.find(dep => dep.name === packageName);
      
      if (dependency) {
        const upgradePath = await this.calculateUpgradePath(
          packageName,
          dependency.version,
          packageVulns
        );
        
        if (upgradePath) {
          upgradePaths.push(upgradePath);
        }
      }
    }
    
    logger.info(`Found ${upgradePaths.length} safe upgrade paths`);
    return upgradePaths;
  }

  private async getAvailableVersions(packageName: string): Promise<string[]> {
    try {
      const response = await fetch(`https://registry.npmjs.org/${packageName}`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch package info for ${packageName}: ${response.status}`);
      }
      
      const packageInfo = await response.json() as any;
      const versions = Object.keys(packageInfo.versions || {});
      
      // Sort versions in descending order
      return versions.sort((a: string, b: string) => {
        try {
          return this.semverUtils.greaterThan(a, b) ? -1 : 1;
        } catch {
          return b.localeCompare(a);
        }
      });
    } catch (error) {
      logger.error(`Failed to get available versions for ${packageName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  private findFixedVersions(vulnerabilities: Vulnerability[], availableVersions: string[]): string[] {
    const fixedVersions = new Set<string>();
    
    for (const vuln of vulnerabilities) {
      if (vuln.patchedVersions) {
        for (const patchedVersion of vuln.patchedVersions) {
          if (availableVersions.includes(patchedVersion)) {
            fixedVersions.add(patchedVersion);
          }
        }
      }
    }
    
    return Array.from(fixedVersions);
  }

  private findSafestUpgrade(
    currentVersion: string, 
    fixedVersions: string[], 
    availableVersions: string[]
  ): string | null {
    // Filter fixed versions that are greater than current version
    const validUpgrades = fixedVersions.filter(version => {
      try {
        return this.semverUtils.greaterThan(version, currentVersion);
      } catch {
        return false;
      }
    });
    
    if (validUpgrades.length === 0) {
      return null;
    }
    
    // Prefer non-breaking upgrades
    const nonBreakingUpgrades = validUpgrades.filter(version => 
      !this.semverUtils.isBreakingUpgrade(currentVersion, version)
    );
    
    if (nonBreakingUpgrades.length > 0) {
      // Return the latest non-breaking upgrade
      return this.semverUtils.maxVersion(nonBreakingUpgrades);
    }
    
    // If no non-breaking upgrades, return the latest breaking upgrade
    return this.semverUtils.maxVersion(validUpgrades);
  }

  private calculateConfidence(
    currentVersion: string,
    targetVersion: string,
    fixedVersions: string[]
  ): 'high' | 'medium' | 'low' {
    let confidence = 0.2; // Lower base confidence
    
    // Higher confidence for direct patched versions
    if (fixedVersions.includes(targetVersion)) {
      confidence += 0.2;
    }
    
    // Check version difference for confidence levels
    const currentMajor = this.semverUtils.major(currentVersion);
    const targetMajor = this.semverUtils.major(targetVersion);
    const currentMinor = this.semverUtils.minor(currentVersion);
    const targetMinor = this.semverUtils.minor(targetVersion);
    
    if (currentMajor === targetMajor) {
      if (currentMinor === targetMinor) {
        // Patch version upgrade (1.0.0 -> 1.0.1)
        confidence += 0.6;
      } else {
        // Minor version upgrade (1.0.0 -> 1.5.0)
        confidence += 0.3;
      }
    } else {
      // Major version upgrade (1.0.0 -> 2.0.0)
      confidence -= 0.1; // Reduce confidence for major changes
    }
    
    confidence = Math.max(0, Math.min(1, confidence));
    
    // Convert to string levels
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.5) return 'medium';
    return 'low';
  }
}
