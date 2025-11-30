import fetch from 'node-fetch';
import { Vulnerability } from '../types/vulnerability.js';
import { logger } from '../utils/logger.js';

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
    severity?: Array<{
      type: 'CVSS_V3';
      score: string;
    }>;
    affected: Array<{
      package: { name: string; ecosystem: string };
      ranges: Array<{ type: string; events: Array<any> }>;
    }>;
    references: Array<{ type: string; url: string }>;
    published?: string;
    modified?: string;
  }>;
}

export class OSVClient {
  private readonly baseUrl = 'https://osv.dev/v1';

  async queryVulnerabilities(packageName: string, version?: string): Promise<Vulnerability[]> {
    logger.debug(`Querying OSV for ${packageName}@${version || 'latest'}`);

    try {
      const query: OSVQuery = {
        package: {
          name: packageName,
          ecosystem: 'npm',
        },
      };

      if (version) {
        query.version = version;
      }

      const response = await fetch(`${this.baseUrl}/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(query),
      });

      if (!response.ok) {
        throw new Error(`OSV API error: ${response.status} ${response.statusText}`);
      }

      const data = (await response.json()) as OSVResponse;
      return this.transformOSVResponse(data, packageName, version);
    } catch (error) {
      logger.error(`Failed to query OSV for ${packageName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
    }
  }

  private transformOSVResponse(response: OSVResponse, packageName: string, version?: string): Vulnerability[] {
    return response.vulns.map(vuln => {
      const severity = this.extractSeverity(vuln);
      const score = this.extractScore(vuln);
      const affectedVersions = this.extractAffectedVersions(vuln);
      const patchedVersions = this.extractPatchedVersions(vuln);

      return {
        id: vuln.id,
        packageName,
        packageVersion: version || '*',
        severity,
        score,
        title: vuln.summary,
        description: vuln.details,
        cveId: this.extractCVEId(vuln.id),
        cwes: [], // OSV doesn't provide CWEs directly
        references: vuln.references.map(ref => ref.url),
        patchedVersions,
        vulnerableVersions: affectedVersions,
        firstPatchedVersion: patchedVersions[0],
        publishedDate: vuln.published,
        lastModifiedDate: vuln.modified,
        source: 'osv',
      };
    });
  }

  private extractSeverity(vuln: OSVResponse['vulns'][0]): Vulnerability['severity'] {
    if (!vuln.severity || vuln.severity.length === 0) {
      return 'medium'; // Default severity
    }

    const cvssScore = parseFloat(vuln.severity[0].score);
    
    if (cvssScore >= 9.0) return 'critical';
    if (cvssScore >= 7.0) return 'high';
    if (cvssScore >= 4.0) return 'medium';
    return 'low';
  }

  private extractScore(vuln: OSVResponse['vulns'][0]): number | undefined {
    if (!vuln.severity || vuln.severity.length === 0) {
      return undefined;
    }

    return parseFloat(vuln.severity[0].score);
  }

  private extractAffectedVersions(vuln: OSVResponse['vulns'][0]): string[] {
    const versions: string[] = [];

    for (const affected of vuln.affected) {
      for (const range of affected.ranges) {
        if (range.type === 'SEMVER' && range.events) {
          for (const event of range.events) {
            if (event.introduced) {
              versions.push(`>=${event.introduced}`);
            }
            if (event.fixed) {
              versions.push(`<${event.fixed}`);
            }
            if (event.limit) {
              versions.push(`<=${event.limit}`);
            }
          }
        }
      }
    }

    return versions;
  }

  private extractPatchedVersions(vuln: OSVResponse['vulns'][0]): string[] {
    const versions: string[] = [];

    for (const affected of vuln.affected) {
      for (const range of affected.ranges) {
        if (range.type === 'SEMVER' && range.events) {
          for (const event of range.events) {
            if (event.fixed) {
              versions.push(event.fixed);
            }
          }
        }
      }
    }

    return versions;
  }

  private extractCVEId(vulnId: string): string | undefined {
    // OSV IDs might be CVE IDs or other formats
    if (vulnId.startsWith('CVE-')) {
      return vulnId;
    }

    // Check if the ID contains a CVE reference
    const cveMatch = vulnId.match(/CVE-\d{4}-\d{4,}/);
    return cveMatch ? cveMatch[0] : undefined;
  }

  async batchQuery(queries: Array<{ packageName: string; version?: string }>): Promise<Vulnerability[]> {
    logger.debug(`Batch querying OSV for ${queries.length} packages`);

    // OSV supports batch queries
    try {
      const response = await fetch(`${this.baseUrl}/querybatch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          queries: queries.map(q => ({
            package: {
              name: q.packageName,
              ecosystem: 'npm',
            },
            version: q.version,
          })),
        }),
      });

      if (!response.ok) {
        throw new Error(`OSV batch query error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as any;
      const allVulnerabilities: Vulnerability[] = [];

      for (let i = 0; i < data.results.length; i++) {
        const result = data.results[i];
        const query = queries[i];
        
        if (result.vulns) {
          const vulnerabilities = this.transformOSVResponse(result, query.packageName, query.version);
          allVulnerabilities.push(...vulnerabilities);
        }
      }

      return allVulnerabilities;
    } catch (error) {
      logger.error(`Failed to batch query OSV: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      // Fallback to individual queries
      const vulnerabilities: Vulnerability[] = [];
      for (const query of queries) {
        const vulns = await this.queryVulnerabilities(query.packageName, query.version);
        vulnerabilities.push(...vulns);
      }
      
      return vulnerabilities;
    }
  }
}
