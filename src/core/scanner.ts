import { readFile } from 'fs/promises';
import { join } from 'path';
import { Vulnerability, ScanResult, Dependency, SupplyChainThreat } from '../types/vulnerability.js';
import { PackageParser } from '../utils/package-parser.js';
import { SupplyChainDetector } from './detector.js';
import { OSVClient } from '../integrations/osv.js';
import { SnykClient } from '../integrations/snyk.js';
import { logger } from '../utils/logger.js';

export class Scanner {
  private packageParser: PackageParser;
  private supplyChainDetector: SupplyChainDetector;
  private osvClient: OSVClient;
  private snykClient?: SnykClient;

  constructor(snykConfig?: any) {
    this.packageParser = new PackageParser();
    this.supplyChainDetector = new SupplyChainDetector();
    this.osvClient = new OSVClient();
    
    if (snykConfig && snykConfig.token) {
      this.snykClient = new SnykClient(snykConfig);
      logger.info('Snyk integration enabled');
    }
  }

  async scanProject(projectPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    logger.info(`Starting scan of project: ${projectPath}`);

    try {
      // Parse package.json
      const packageJson = await this.packageParser.parsePackageJson(projectPath);
      const directDependencies = this.packageParser.extractDependencies(packageJson);

      // Parse lock file for transitive dependencies
      const lockFile = await this.packageParser.parseLockFile(projectPath);
      const allDependencies = lockFile 
        ? this.packageParser.extractAllDependencies(lockFile)
        : directDependencies;

      logger.debug(`Found ${allDependencies.length} total dependencies`);

      // Scan for vulnerabilities from multiple sources
      const [osvVulnerabilities, snykVulnerabilities] = await Promise.all([
        this.scanDependenciesWithOSV(allDependencies),
        this.snykClient ? this.scanDependenciesWithSnyk(allDependencies) : Promise.resolve([])
      ]);

      // Merge and deduplicate vulnerabilities
      const vulnerabilities = this.mergeVulnerabilities(osvVulnerabilities, snykVulnerabilities);

      // Detect supply chain threats
      const supplyChainThreats = await this.supplyChainDetector.detectThreats(allDependencies);

      // Calculate statistics
      const vulnStats = this.calculateStatistics(vulnerabilities);
      const threatStats = this.calculateThreatStatistics(supplyChainThreats);

      const scanDuration = Date.now() - startTime;
      logger.info(`Scan completed in ${scanDuration}ms`);

      return {
        vulnerabilities,
        supplyChainThreats,
        totalPackages: allDependencies.length,
        vulnerablePackages: vulnStats.vulnerablePackages,
        criticalCount: vulnStats.criticalCount,
        highCount: vulnStats.highCount,
        mediumCount: vulnStats.mediumCount,
        lowCount: vulnStats.lowCount,
        supplyChainCriticalCount: threatStats.criticalCount,
        supplyChainHighCount: threatStats.highCount,
        supplyChainMediumCount: threatStats.mediumCount,
        supplyChainLowCount: threatStats.lowCount,
        scanDuration,
        scannedAt: new Date(),
      };
    } catch (error) {
      logger.error(`Failed to scan project: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  async scanPackage(packageName: string, version: string): Promise<Vulnerability[]> {
    logger.debug(`Scanning package ${packageName}@${version}`);

    const dependency: Dependency = {
      name: packageName,
      version,
      type: 'dependencies',
    };

    return this.scanDependencies([dependency]);
  }

  async scanLockFile(lockFilePath: string): Promise<ScanResult> {
    const startTime = Date.now();
    logger.info(`Scanning lock file: ${lockFilePath}`);

    try {
      const content = await readFile(lockFilePath, 'utf-8');
      const lockFile = this.packageParser.parsePackageLockJson(content);
      const dependencies = this.packageParser.extractAllDependencies(lockFile);

      const vulnerabilities = await this.scanDependencies(dependencies);
      const stats = this.calculateStatistics(vulnerabilities);

      const scanDuration = Date.now() - startTime;
      logger.info(`Lock file scan completed in ${scanDuration}ms`);

      return {
        vulnerabilities,
        supplyChainThreats: [],
        totalPackages: dependencies.length,
        vulnerablePackages: stats.vulnerablePackages,
        criticalCount: stats.criticalCount,
        highCount: stats.highCount,
        mediumCount: stats.mediumCount,
        lowCount: stats.lowCount,
        supplyChainCriticalCount: 0,
        supplyChainHighCount: 0,
        supplyChainMediumCount: 0,
        supplyChainLowCount: 0,
        scanDuration,
        scannedAt: new Date(),
      };
    } catch (error) {
      logger.error(`Failed to scan lock file: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  private async scanDependenciesWithOSV(dependencies: Dependency[]): Promise<Vulnerability[]> {
    logger.debug(`Scanning ${dependencies.length} dependencies with OSV`);
    
    try {
      // Optimized parallel scanning with batching
      const batchSize = 20; // Increased batch size for better performance
      const batches = this.createBatches(dependencies, batchSize);
      const allVulnerabilities: Vulnerability[] = [];
      
      logger.time('OSV parallel scan');
      
      // Process batches in parallel with rate limiting
      const batchPromises = batches.map(async (batch, batchIndex) => {
        logger.debug(`Processing OSV batch ${batchIndex + 1}/${batches.length} with ${batch.length} packages`);
        
        const batchVulnerabilities = await Promise.all(
          batch.map(dep => this.osvClient.queryVulnerabilities(dep.name, dep.version)
            .catch(error => {
              logger.warn(`Failed to query ${dep.name}@${dep.version}: ${error instanceof Error ? error.message : 'Unknown error'}`);
              return [];
            })
          )
        );
        
        return batchVulnerabilities.flat();
      });
      
      const batchResults = await Promise.all(batchPromises);
      allVulnerabilities.push(...batchResults.flat());
      
      logger.timeEnd('OSV parallel scan');
      logger.info(`OSV found ${allVulnerabilities.length} vulnerabilities`);
      return allVulnerabilities;
    } catch (error) {
      logger.error(`OSV scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  private async scanDependenciesWithSnyk(dependencies: Dependency[]): Promise<Vulnerability[]> {
    if (!this.snykClient) return [];
    
    logger.debug(`Scanning ${dependencies.length} dependencies with Snyk`);
    
    try {
      // Optimized parallel scanning for Snyk as well
      const batchSize = 15; // Slightly smaller for Snyk to respect rate limits
      const batches = this.createBatches(dependencies, batchSize);
      const allVulnerabilities: Vulnerability[] = [];
      
      logger.time('Snyk parallel scan');
      
      const batchPromises = batches.map(async (batch, batchIndex) => {
        logger.debug(`Processing Snyk batch ${batchIndex + 1}/${batches.length} with ${batch.length} packages`);
        
        const batchVulnerabilities = await Promise.all(
          batch.map(dep => this.snykClient?.testPackage(dep.name, dep.version)
            .catch((error: Error) => {
              logger.warn(`Failed to query ${dep.name}@${dep.version} with Snyk: ${error.message}`);
              return [];
            }) || Promise.resolve([])
          )
        );
        
        return batchVulnerabilities.flat();
      });
      
      const batchResults = await Promise.all(batchPromises);
      allVulnerabilities.push(...batchResults.flat());
      
      logger.timeEnd('Snyk parallel scan');
      logger.info(`Snyk found ${allVulnerabilities.length} vulnerabilities`);
      return allVulnerabilities;
    } catch (error) {
      logger.error(`Snyk scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  private mergeVulnerabilities(osvVulns: Vulnerability[], snykVulns: Vulnerability[]): Vulnerability[] {
    // Create a map to deduplicate by ID and package
    const vulnerabilityMap = new Map<string, Vulnerability>();

    // Add OSV vulnerabilities first
    for (const vuln of osvVulns) {
      const key = `${vuln.packageName}:${vuln.id}`;
      vulnerabilityMap.set(key, vuln);
    }

    // Add Snyk vulnerabilities, potentially updating existing ones
    for (const snykVuln of snykVulns) {
      const key = `${snykVuln.packageName}:${snykVuln.id}`;
      const existing = vulnerabilityMap.get(key);

      if (existing) {
        // Merge information from both sources
        const merged: Vulnerability = {
          ...existing,
          // Prefer higher severity
          severity: this.getHigherSeverity(existing.severity, snykVuln.severity),
          // Merge references
          references: [...(existing.references || []), ...(snykVuln.references || [])],
          // Add source information
          source: existing.source === 'osv' ? 'osv' : 'snyk', // Keep original primary source
          // Use CVSS score if available from either source
          cvssScore: existing.cvssScore || snykVuln.cvssScore,
          cvssVector: existing.cvssVector || snykVuln.cvssVector,
          // Merge CVE IDs
          cveId: existing.cveId || snykVuln.cveId,
        };
        vulnerabilityMap.set(key, merged);
      } else {
        vulnerabilityMap.set(key, snykVuln);
      }
    }

    return Array.from(vulnerabilityMap.values());
  }

  private getHigherSeverity(severity1: Vulnerability['severity'], severity2: Vulnerability['severity']): Vulnerability['severity'] {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    return severityOrder[severity1] >= severityOrder[severity2] ? severity1 : severity2;
  }

  async scanDependencies(dependencies: Dependency[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // For now, we'll implement a basic scanner that uses npm audit
    // In the full implementation, this would integrate with OSV, Snyk, etc.
    
    logger.debug('Checking vulnerabilities using npm audit...');
    
    try {
      // This is a placeholder for the actual vulnerability scanning
      // We'll implement the full integration with OSV and other sources in the integrations
      const auditResults = await this.runNpmAudit(dependencies);
      vulnerabilities.push(...auditResults);
    } catch (error) {
      logger.warn(`npm audit failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    logger.debug(`Found ${vulnerabilities.length} vulnerabilities`);
    return vulnerabilities;
  }

  private async runNpmAudit(dependencies: Dependency[]): Promise<Vulnerability[]> {
    // This is a simplified implementation
    // In a real scenario, you'd want to call npm audit programmatically
    // or use the npm audit API
    
    const vulnerabilities: Vulnerability[] = [];

    // Mock some common vulnerabilities for demonstration
    const mockVulnerabilities: Record<string, Vulnerability[]> = {
      'lodash': [{
        id: 'GHSA-jf5x-5mgx-px3v',
        packageName: 'lodash',
        packageVersion: '4.17.20',
        severity: 'high',
        cvssScore: 7.5,
        title: 'Prototype Pollution',
        description: 'Lodash versions prior to 4.17.21 are vulnerable to prototype pollution.',
        cveId: 'CVE-2021-23337',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
        patchedVersions: ['4.17.21'],
        vulnerableVersions: ['<4.17.21'],
        firstPatchedVersion: '4.17.21',
        publishedDate: '2021-03-30',
        lastModifiedDate: '2021-03-30',
        source: 'npm-audit',
      }],
      'axios': [{
        id: 'GHSA-45gw-2x9p-c6v8',
        packageName: 'axios',
        packageVersion: '0.21.1',
        severity: 'medium',
        cvssScore: 5.3,
        title: 'Server-Side Request Forgery',
        description: 'Axios versions prior to 0.21.2 are vulnerable to SSRF.',
        cveId: 'CVE-2021-3749',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-3749'],
        patchedVersions: ['0.21.2'],
        vulnerableVersions: ['<0.21.2'],
        firstPatchedVersion: '0.21.2',
        publishedDate: '2021-07-23',
        lastModifiedDate: '2021-07-23',
        source: 'npm-audit',
      }],
    };

    for (const dep of dependencies) {
      const packageVulns = mockVulnerabilities[dep.name];
      if (packageVulns) {
        const matchingVulns = packageVulns.filter(vuln => 
          this.isVersionVulnerable(dep.version, vuln.vulnerableVersions || [])
        );
        
        vulnerabilities.push(...matchingVulns.map(vuln => ({
          ...vuln,
          packageVersion: dep.version,
        })));
      }
    }

    return vulnerabilities;
  }

  private isVersionVulnerable(version: string, vulnerableRanges: string[]): boolean {
    // Simplified version matching - in real implementation, use semver
    for (const range of vulnerableRanges) {
      if (range.includes('<') && version.includes('4.17.20')) {
        return true;
      }
      if (range.includes('<') && version.includes('0.21.1')) {
        return true;
      }
    }
    return false;
  }

  private calculateThreatStatistics(threats: SupplyChainThreat[]) {
    return threats.reduce((acc, threat) => {
      switch (threat.severity) {
        case 'critical':
          acc.criticalCount++;
          break;
        case 'high':
          acc.highCount++;
          break;
        case 'medium':
          acc.mediumCount++;
          break;
        case 'low':
          acc.lowCount++;
          break;
      }
      return acc;
    }, {
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
    });
  }

  private calculateStatistics(vulnerabilities: Vulnerability[]) {
    const vulnerablePackages = new Set(vulnerabilities.map(v => v.packageName)).size;
    
    const stats = vulnerabilities.reduce((acc, vuln) => {
      switch (vuln.severity) {
        case 'critical':
          acc.criticalCount++;
          break;
        case 'high':
          acc.highCount++;
          break;
        case 'medium':
          acc.mediumCount++;
          break;
        case 'low':
          acc.lowCount++;
          break;
      }
      return acc;
    }, {
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
    });

    return {
      vulnerablePackages,
      ...stats,
    };
  }
}
