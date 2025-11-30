import fetch from 'node-fetch';
import { Dependency, SupplyChainThreat } from '../types/vulnerability.js';
import { logger } from '../utils/logger.js';

interface NPMRegistryResponse {
  'dist-tags': {
    latest: string;
  };
  versions: Record<string, {
    version: string;
    description?: string;
    maintainers?: Array<{ name: string; email: string }>;
    publishTime?: number;
    deprecated?: string;
    scripts?: Record<string, string>;
  }>;
  maintainers?: Array<{ name: string; email: string }>;
  time?: Record<string, string>;
}

export class SupplyChainDetector {
  private readonly npmRegistry = 'https://registry.npmjs.org';
  private readonly popularPackages = new Set([
    'lodash', 'express', 'react', 'vue', 'angular', 'axios', 'moment', 'request', 'underscore',
    'chalk', 'commander', 'webpack', 'babel', 'eslint', 'prettier', 'jest', 'mocha', 'typescript',
    'react-dom', 'prop-types', 'redux', 'react-router', 'next', 'nuxt', 'gatsby', 'vue-router',
    'vuex', 'styled-components', 'emotion', 'material-ui', 'ant-design', 'bootstrap', 'tailwindcss'
  ]);

  async detectThreats(dependencies: Dependency[]): Promise<SupplyChainThreat[]> {
    logger.info(`Analyzing ${dependencies.length} dependencies for supply chain threats`);
    
    const threats: SupplyChainThreat[] = [];
    
    // Check for typosquatting
    const typosquattingThreats = await this.detectTyposquatting(dependencies);
    threats.push(...typosquattingThreats);
    
    // Check for malicious install scripts
    const scriptThreats = await this.detectMaliciousScripts(dependencies);
    threats.push(...scriptThreats);
    
    // Check for suspicious activity
    const activityThreats = await this.detectSuspiciousActivity(dependencies);
    threats.push(...activityThreats);
    
    // Check for compromised maintainers
    const maintainerThreats = await this.detectCompromisedMaintainers(dependencies);
    threats.push(...maintainerThreats);
    
    logger.info(`Found ${threats.length} supply chain threats`);
    return threats;
  }

  async detectTyposquatting(dependencies: Dependency[]): Promise<SupplyChainThreat[]> {
    logger.debug('Checking for typosquatting attacks');
    
    const threats: SupplyChainThreat[] = [];
    
    for (const dep of dependencies) {
      const isTyposquat = this.isTyposquattingPackage(dep.name);
      
      if (isTyposquat) {
        threats.push({
          type: 'typosquatting',
          packageName: dep.name,
          severity: 'high',
          description: `Package name "${dep.name}" appears to be a typosquatting attempt targeting a popular package`,
          evidence: [
            `Package name is similar to popular npm packages`,
            `One character difference from known popular packages`,
            `Unusual naming pattern detected`
          ],
          recommendations: [
            'Verify this is the intended package',
            'Check package maintainer and download counts',
            'Consider using the official package instead'
          ],
          detectedAt: new Date(),
        });
      }
    }
    
    return threats;
  }

  async detectMaliciousScripts(dependencies: Dependency[]): Promise<SupplyChainThreat[]> {
    logger.debug('Analyzing install scripts for malicious patterns');
    
    const threats: SupplyChainThreat[] = [];
    const suspiciousPatterns = [
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /child_process/gi,
      /exec\s*\(/gi,
      /spawn\s*\(/gi,
      /curl\s+/gi,
      /wget\s+/gi,
      /rm\s+-rf/gi,
      /\.bashrc/gi,
      /\.profile/gi,
      /\/etc\//gi,
      /sudo/gi,
      /chmod\s+777/gi,
      /base64/gi,
      /crypto/gi,
    ];
    
    for (const dep of dependencies) {
      try {
        const packageInfo = await this.fetchPackageInfo(dep.name);
        
        if (!packageInfo.versions) continue;
        
        for (const [version, versionInfo] of Object.entries(packageInfo.versions)) {
          const scripts = versionInfo.scripts || {};
          const scriptContent = Object.values(scripts).join(' ');
          
          const matchedPatterns = suspiciousPatterns.filter(pattern => 
            pattern.test(scriptContent)
          );
          
          if (matchedPatterns.length > 0) {
            threats.push({
              type: 'malicious-script',
              packageName: dep.name,
              severity: 'critical',
              description: `Package "${dep.name}" contains suspicious install scripts`,
              evidence: [
                `Found suspicious patterns in install scripts`,
                ...matchedPatterns.map(p => `Pattern: ${p.source}`),
                `Version: ${version}`
              ],
              recommendations: [
                'Review package source code immediately',
                'Check package maintainer reputation',
                'Consider alternative packages',
                'Audit all dependencies that use this package'
              ],
              detectedAt: new Date(),
            });
          }
        }
      } catch (error) {
        logger.warn(`Failed to analyze scripts for ${dep.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    
    return threats;
  }

  async detectSuspiciousActivity(dependencies: Dependency[]): Promise<SupplyChainThreat[]> {
    logger.debug('Analyzing package publishing patterns for suspicious activity');
    
    const threats: SupplyChainThreat[] = [];
    
    for (const dep of dependencies) {
      try {
        const packageInfo = await this.fetchPackageInfo(dep.name);
        
        if (!packageInfo.time) continue;
        
        const versions = Object.keys(packageInfo.time);
        const publishTimes = versions.map(v => new Date(packageInfo.time![v]).getTime());
        
        // Check for rapid version releases (potential version bumping attack)
        if (versions.length > 1) {
          const sortedTimes = publishTimes.sort((a, b) => a - b);
          const recentReleases = sortedTimes.filter(time => 
            Date.now() - time < 24 * 60 * 60 * 1000 // Last 24 hours
          );
          
          if (recentReleases.length > 5) {
            threats.push({
              type: 'suspicious-activity',
              packageName: dep.name,
              severity: 'medium',
              description: `Package "${dep.name}" has unusually high release activity`,
              evidence: [
                `${recentReleases.length} releases in the last 24 hours`,
                'Total versions: ' + versions.length,
                'This pattern may indicate version bumping attacks'
              ],
              recommendations: [
                'Investigate recent version changes',
                'Check changelog for suspicious modifications',
                'Monitor package for further unusual activity'
              ],
              detectedAt: new Date(),
            });
          }
        }
        
        // Check for very recent package with no history
        const oldestPublish = Math.min(...publishTimes);
        const daysSinceFirstPublish = (Date.now() - oldestPublish) / (24 * 60 * 60 * 1000);
        
        if (daysSinceFirstPublish < 7 && versions.length === 1) {
          threats.push({
            type: 'suspicious-activity',
            packageName: dep.name,
            severity: 'medium',
            description: `Package "${dep.name}" is very recently published with no version history`,
            evidence: [
              `First published ${Math.floor(daysSinceFirstPublish)} days ago`,
              'Only one version available',
              'New packages may be untrusted'
            ],
            recommendations: [
              'Exercise caution with new packages',
              'Check maintainer history and other packages',
              'Wait for broader adoption before use'
            ],
            detectedAt: new Date(),
          });
        }
        
      } catch (error) {
        logger.warn(`Failed to analyze activity for ${dep.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    
    return threats;
  }

  async detectCompromisedMaintainers(dependencies: Dependency[]): Promise<SupplyChainThreat[]> {
    logger.debug('Checking for compromised maintainer accounts');
    
    const threats: SupplyChainThreat[] = [];
    
    for (const dep of dependencies) {
      try {
        const packageInfo = await this.fetchPackageInfo(dep.name);
        
        if (!packageInfo.maintainers) continue;
        
        // Check for suspicious maintainer patterns
        const suspiciousMaintainers = packageInfo.maintainers.filter(maintainer => {
          const email = maintainer.email.toLowerCase();
          
          // Suspicious email patterns
          return (
            email.includes('temp') ||
            email.includes('fake') ||
            email.includes('test') ||
            email.includes('example') ||
            !email.includes('@') ||
            email.includes('10minutemail') ||
            email.includes('guerrillamail')
          );
        });
        
        if (suspiciousMaintainers.length > 0) {
          threats.push({
            type: 'compromised-maintainer',
            packageName: dep.name,
            severity: 'high',
            description: `Package "${dep.name}" has maintainers with suspicious email addresses`,
            evidence: [
              `Found ${suspiciousMaintainers.length} suspicious maintainers`,
              ...suspiciousMaintainers.map(m => `Maintainer: ${m.name} (${m.email})`)
            ],
            recommendations: [
              'Verify maintainer authenticity',
              'Check maintainer\'s other packages',
              'Consider packages with more reputable maintainers'
            ],
            detectedAt: new Date(),
          });
        }
        
        // Check for single maintainer packages (higher risk)
        if (packageInfo.maintainers.length === 1 && !this.popularPackages.has(dep.name)) {
          threats.push({
            type: 'compromised-maintainer',
            packageName: dep.name,
            severity: 'low',
            description: `Package "${dep.name}" has only one maintainer`,
            evidence: [
              'Single point of failure',
              'Higher risk if maintainer account is compromised',
              'No redundancy in maintenance'
            ],
            recommendations: [
              'Monitor maintainer account security',
              'Consider packages with multiple maintainers',
              'Keep track of maintainer activity'
            ],
            detectedAt: new Date(),
          });
        }
        
      } catch (error) {
        logger.warn(`Failed to analyze maintainers for ${dep.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    
    return threats;
  }

  private isTyposquattingPackage(packageName: string): boolean {
    // Skip popular packages
    if (this.popularPackages.has(packageName)) {
      return false;
    }
    
    // Check against popular packages for typosquatting
    for (const popular of this.popularPackages) {
      if (this.isTypoSquat(packageName, popular)) {
        return true;
      }
    }
    
    return false;
  }

  private isTypoSquat(candidate: string, target: string): boolean {
    // Skip if lengths are too different
    if (Math.abs(candidate.length - target.length) > 2) {
      return false;
    }
    
    // Check for common typosquatting techniques
    
    // 1. Single character substitution
    if (candidate.length === target.length) {
      let differences = 0;
      for (let i = 0; i < candidate.length; i++) {
        if (candidate[i] !== target[i]) {
          differences++;
        }
      }
      if (differences === 1) return true;
    }
    
    // 2. Character omission
    if (target.length === candidate.length + 1) {
      for (let i = 0; i < candidate.length; i++) {
        const modified = target.slice(0, i) + target.slice(i + 1);
        if (modified === candidate) return true;
      }
    }
    
    // 3. Character addition
    if (candidate.length === target.length + 1) {
      for (let i = 0; i < target.length; i++) {
        const modified = candidate.slice(0, i) + candidate.slice(i + 1);
        if (modified === target) return true;
      }
    }
    
    // 4. Character swapping (adjacent)
    if (candidate.length === target.length) {
      for (let i = 0; i < candidate.length - 1; i++) {
        const swapped = candidate.slice(0, i) + candidate[i + 1] + candidate[i] + candidate.slice(i + 2);
        if (swapped === target) return true;
      }
    }
    
    // 5. Common character confusion
    const confusionPairs: [string, string][] = [
      ['l', '1'],
      ['i', '1'],
      ['o', '0'],
      ['rn', 'm'],
      ['vv', 'w'],
      ['rn', 'n'],
    ];
    
    for (const [a, b] of confusionPairs) {
      if (candidate.replace(new RegExp(a, 'g'), b) === target) return true;
      if (candidate.replace(new RegExp(b, 'g'), a) === target) return true;
    }
    
    return false;
  }

  private async fetchPackageInfo(packageName: string): Promise<NPMRegistryResponse> {
    const response = await fetch(`${this.npmRegistry}/${packageName}`);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch package info for ${packageName}: ${response.status}`);
    }
    
    return response.json() as unknown as NPMRegistryResponse;
  }
}
