import { Vulnerability } from '../types/vulnerability.js';
import { logger } from '../utils/logger.js';
import fetch from 'node-fetch';

export interface SnykConfig {
  token: string;
  organization?: string;
  endpoint?: string;
}

export interface SnykVulnerability {
  id: string;
  package: string;
  version: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  cve?: string[];
  cvssScore?: number;
  cvssVector?: string;
  patchedVersions?: string[];
  vulnerableVersions?: string[];
  references?: string[];
  publicationTime?: string;
  disclosureTime?: string;
  credit?: string[];
}

export interface SnykTestResponse {
  ok: boolean;
  vulnerabilities: SnykVulnerability[];
  dependencies: Array<{
    name: string;
    version: string;
    vulnerabilities: string[];
  }>;
}

export class SnykClient {
  private config: SnykConfig;
  private baseUrl: string;

  constructor(config: SnykConfig) {
    this.config = config;
    this.baseUrl = config.endpoint || 'https://api.snyk.io';
  }

  async testPackage(packageName: string, version: string): Promise<Vulnerability[]> {
    logger.debug(`Testing ${packageName}@${version} with Snyk API`);
    
    try {
      const url = `${this.baseUrl}/v1/test/npm/${packageName}/${version}`;
      const headers = {
        'Authorization': `token ${this.config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'DepGuardian/1.0.0',
      };

      if (this.config.organization) {
        headers['Authorization'] = `token ${this.config.token}`;
      }

      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          test: {
            dependencies: [
              {
                name: packageName,
                version: version,
                type: 'npm',
              }
            ]
          }
        })
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Snyk API authentication failed. Check your token.');
        } else if (response.status === 429) {
          logger.warn('Snyk API rate limit reached');
          return [];
        } else {
          logger.warn(`Snyk API error: ${response.status} - ${response.statusText}`);
          return [];
        }
      }

      const data = await response.json() as SnykTestResponse;
      
      return this.transformSnykVulnerabilities(data.vulnerabilities, packageName, version);
      
    } catch (error) {
      logger.error(`Failed to test ${packageName}@${version} with Snyk: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  async testBatch(packages: Array<{ name: string; version: string }>): Promise<Vulnerability[]> {
    logger.debug(`Testing ${packages.length} packages with Snyk API`);
    
    try {
      const url = `${this.baseUrl}/v1/test/npm`;
      const headers = {
        'Authorization': `token ${this.config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'DepGuardian/1.0.0',
      };

      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          test: {
            dependencies: packages.map(pkg => ({
              name: pkg.name,
              version: pkg.version,
              type: 'npm',
            }))
          }
        })
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Snyk API authentication failed. Check your token.');
        } else if (response.status === 429) {
          logger.warn('Snyk API rate limit reached');
          return [];
        } else {
          logger.warn(`Snyk API error: ${response.status} - ${response.statusText}`);
          return [];
        }
      }

      const data = await response.json() as SnykTestResponse;
      
      const allVulnerabilities: Vulnerability[] = [];
      
      for (const pkg of packages) {
        const pkgVulns = data.dependencies.find(dep => dep.name === pkg.name && dep.version === pkg.version);
        if (pkgVulns) {
          const snykVulns = data.vulnerabilities.filter(vuln => pkgVulns.vulnerabilities.includes(vuln.id));
          allVulnerabilities.push(...this.transformSnykVulnerabilities(snykVulns, pkg.name, pkg.version));
        }
      }
      
      return allVulnerabilities;
      
    } catch (error) {
      logger.error(`Failed to test batch with Snyk: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  async getPackageVulnerabilities(packageName: string): Promise<Vulnerability[]> {
    logger.debug(`Getting all vulnerabilities for ${packageName} from Snyk`);
    
    try {
      const url = `${this.baseUrl}/v1/vuln/npm/${packageName}`;
      const headers = {
        'Authorization': `token ${this.config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'DepGuardian/1.0.0',
      };

      const response = await fetch(url, { headers });

      if (!response.ok) {
        if (response.status === 404) {
          logger.debug(`No vulnerabilities found for ${packageName} in Snyk`);
          return [];
        } else if (response.status === 401) {
          throw new Error('Snyk API authentication failed. Check your token.');
        } else {
          logger.warn(`Snyk API error: ${response.status} - ${response.statusText}`);
          return [];
        }
      }

      const data = await response.json() as { vulnerabilities: SnykVulnerability[] };
      
      return this.transformSnykVulnerabilities(data.vulnerabilities, packageName);
      
    } catch (error) {
      logger.error(`Failed to get vulnerabilities for ${packageName} from Snyk: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  private transformSnykVulnerabilities(snykVulns: SnykVulnerability[], packageName: string, version?: string): Vulnerability[] {
    return snykVulns.map(snykVuln => {
      // Map Snyk severity to our severity levels
      let severity: Vulnerability['severity'] = 'low';
      switch (snykVuln.severity) {
        case 'critical':
          severity = 'critical';
          break;
        case 'high':
          severity = 'high';
          break;
        case 'medium':
          severity = 'medium';
          break;
        case 'low':
          severity = 'low';
          break;
      }

      // Extract CVE ID if available
      let cveId: string | undefined;
      if (snykVuln.cve && snykVuln.cve.length > 0) {
        cveId = snykVuln.cve[0];
      }

      return {
        id: snykVuln.id,
        packageName,
        packageVersion: version || '*',
        severity,
        title: snykVuln.title,
        description: snykVuln.description,
        cveId,
        cvssScore: snykVuln.cvssScore,
        cvssVector: snykVuln.cvssVector,
        patchedVersions: snykVuln.patchedVersions,
        vulnerableVersions: snykVuln.vulnerableVersions,
        firstPatchedVersion: snykVuln.patchedVersions?.[0],
        publishedDate: snykVuln.publicationTime,
        lastModifiedDate: snykVuln.disclosureTime,
        source: 'snyk',
        references: snykVuln.references || [],
      };
    });
  }

  async getOrganizationInfo(): Promise<any> {
    if (!this.config.organization) {
      return null;
    }

    try {
      const url = `${this.baseUrl}/v1/org/${this.config.organization}`;
      const headers = {
        'Authorization': `token ${this.config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'DepGuardian/1.0.0',
      };

      const response = await fetch(url, { headers });

      if (!response.ok) {
        logger.warn(`Failed to get organization info: ${response.status}`);
        return null;
      }

      return await response.json();
      
    } catch (error) {
      logger.error(`Failed to get organization info: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return null;
    }
  }

  async getLicenseInfo(packageName: string, version: string): Promise<any> {
    try {
      const url = `${this.baseUrl}/v1/licenses/npm/${packageName}/${version}`;
      const headers = {
        'Authorization': `token ${this.config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'DepGuardian/1.0.0',
      };

      const response = await fetch(url, { headers });

      if (!response.ok) {
        if (response.status === 404) {
          logger.debug(`No license info found for ${packageName}@${version}`);
          return null;
        } else {
          logger.warn(`Failed to get license info: ${response.status}`);
          return null;
        }
      }

      return await response.json();
      
    } catch (error) {
      logger.error(`Failed to get license info: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return null;
    }
  }

  async checkRateLimit(): Promise<{ remaining: number; reset: number }> {
    try {
      const url = `${this.baseUrl}/v1/user/me`;
      const headers = {
        'Authorization': `token ${this.config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'DepGuardian/1.0.0',
      };

      const response = await fetch(url, { headers });

      if (!response.ok) {
        return { remaining: 0, reset: 0 };
      }

      const rateLimit = response.headers.get('x-ratelimit-remaining');
      const reset = response.headers.get('x-ratelimit-reset');

      return {
        remaining: rateLimit ? parseInt(rateLimit, 10) : 0,
        reset: reset ? parseInt(reset, 10) : 0,
      };
      
    } catch (error) {
      logger.debug(`Failed to check rate limit: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { remaining: 0, reset: 0 };
    }
  }
}
