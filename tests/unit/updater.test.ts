import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SafeUpgradeCalculator } from '../../src/core/updater.js';
import { Vulnerability, Dependency } from '../../src/types/vulnerability.js';
import { OSVClient } from '../../src/integrations/osv.js';

// Mock node-fetch
vi.mock('node-fetch', () => ({
  default: vi.fn(),
}));

import fetch from 'node-fetch';
const mockFetch = vi.mocked(fetch);

// Mock OSVClient
vi.mock('../../src/integrations/osv.js');

describe('SafeUpgradeCalculator', () => {
  let calculator: SafeUpgradeCalculator;
  let mockOSVClient: any;

  beforeEach(() => {
    // Set up mock before creating calculator
    mockOSVClient = {
      queryVulnerabilities: vi.fn(),
    };
    (OSVClient as any).mockImplementation(() => mockOSVClient);
    
    calculator = new SafeUpgradeCalculator();
    vi.clearAllMocks();
  });

  describe('calculateUpgradePath', () => {
    it('should calculate upgrade path for vulnerable package', async () => {
      // Mock npm registry response
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.1': {},
          '1.1.0': {},
          '2.0.0': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      // Mock vulnerability with patched version
      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
      ];

      // Mock no new vulnerabilities in target version
      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath).toBeTruthy();
      expect(upgradePath!.packageName).toBe('test-package');
      expect(upgradePath!.currentVersion).toBe('1.0.0');
      expect(upgradePath!.targetVersion).toBe('1.0.1');
      expect(upgradePath!.isBreaking).toBe(false);
      expect(upgradePath!.fixedVulnerabilities).toContain('VULN-1');
    });

    it('should prefer non-breaking upgrades', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.1': {},
          '2.0.0': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1', '2.0.0'],
          source: 'osv',
        },
      ];

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath!.targetVersion).toBe('1.0.1'); // Should prefer non-breaking
      expect(upgradePath!.isBreaking).toBe(false);
    });

    it('should return breaking upgrade if no non-breaking options', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '2.0.0': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['2.0.0'], // Only breaking version available
          source: 'osv',
        },
      ];

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath!.targetVersion).toBe('2.0.0');
      expect(upgradePath!.isBreaking).toBe(true);
    });

    it('should return null if no available versions', async () => {
      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}), // No versions
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
      ];

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath).toBeNull();
    });

    it('should return null if no fixed versions available', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.2': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1'], // Not available
          source: 'osv',
        },
      ];

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath).toBeNull();
    });
  });

  describe('findSafeVersion', () => {
    it('should find safe version within constraint', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.1': {},
          '1.1.0': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const safeVersion = await calculator.findSafeVersion('test-package', '^1.0.0');

      expect(safeVersion).toBe('1.1.0'); // Latest version in constraint
    });

    it('should return null if no versions satisfy constraint', async () => {
      const mockRegistryResponse = {
        versions: {
          '2.0.0': {},
          '2.1.0': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const safeVersion = await calculator.findSafeVersion('test-package', '^1.0.0');

      expect(safeVersion).toBeNull();
    });

    it('should avoid versions with critical vulnerabilities', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.1': {},
          '1.0.2': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      // Latest version has critical vulnerability
      mockOSVClient.queryVulnerabilities
        .mockImplementation((packageName: string, version: string) => {
          if (version === '1.0.2') return Promise.resolve([{ severity: 'critical' }]);
          if (version === '1.0.1') return Promise.resolve([{ severity: 'critical' }]);
          if (version === '1.0.0') return Promise.resolve([]);
          return Promise.resolve([]);
        });

      const safeVersion = await calculator.findSafeVersion('test-package', '^1.0.0');

      expect(safeVersion).toBe('1.0.0'); // Should pick the safe version
    });
  });

  describe('calculateAllUpgradePaths', () => {
    it('should calculate upgrade paths for multiple packages', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.1': {},
          '2.0.0': {},
          '3.0.0': {},
        },
      };

      (mockFetch as any).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const dependencies: Dependency[] = [
        { name: 'package1', version: '1.0.0', type: 'dependencies' },
        { name: 'package2', version: '2.0.0', type: 'dependencies' },
      ];

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'package1',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability 1',
          description: 'Test description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
        {
          id: 'VULN-2',
          packageName: 'package2',
          version: '2.0.0',
          severity: 'medium',
          title: 'Test Vulnerability 2',
          description: 'Test description',
          patchedVersions: ['3.0.0'],
          source: 'osv',
        },
      ];

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePaths = await calculator.calculateAllUpgradePaths(dependencies, vulnerabilities);

      expect(upgradePaths).toHaveLength(2);
      expect(upgradePaths[0].packageName).toBe('package1');
      expect(upgradePaths[1].packageName).toBe('package2');
    });

    it('should handle packages without vulnerabilities', async () => {
      const dependencies: Dependency[] = [
        { name: 'safe-package', version: '1.0.0', type: 'dependencies' },
      ];

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'vulnerable-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
      ];

      const upgradePaths = await calculator.calculateAllUpgradePaths(dependencies, vulnerabilities);

      expect(upgradePaths).toHaveLength(0);
    });
  });

  describe('confidence calculation', () => {
    it('should assign high confidence for direct patched versions', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.1': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
      ];

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath!.confidence).toBe('high');
    });

    it('should assign medium confidence for same major version', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.5.0': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.5.0'],
          source: 'osv',
        },
      ];

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath!.confidence).toBe('medium');
    });

    it('should assign low confidence for major version changes', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '2.0.0': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['2.0.0'],
          source: 'osv',
        },
      ];

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath!.confidence).toBe('low');
    });
  });

  describe('risk score calculation', () => {
    it('should calculate risk score based on vulnerabilities', async () => {
      const mockRegistryResponse = {
        versions: {
          '1.0.0': {},
          '1.0.1': {},
        },
      };

      (mockFetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRegistryResponse),
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'critical',
          title: 'Critical Vulnerability',
          description: 'Critical description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
        {
          id: 'VULN-2',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'medium',
          title: 'Medium Vulnerability',
          description: 'Medium description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
      ];

      mockOSVClient.queryVulnerabilities.mockResolvedValue([]);

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath!.riskScore).toBeGreaterThan(0);
      expect(upgradePath!.riskScore).toBeLessThan(100); // Should be reasonable
    });
  });

  describe('error handling', () => {
    it('should handle fetch errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
      ];

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath).toBeNull();
    });

    it('should handle registry errors gracefully', async () => {
      (mockFetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const vulnerabilities: Vulnerability[] = [
        {
          id: 'VULN-1',
          packageName: 'test-package',
          version: '1.0.0',
          severity: 'high',
          title: 'Test Vulnerability',
          description: 'Test description',
          patchedVersions: ['1.0.1'],
          source: 'osv',
        },
      ];

      const upgradePath = await calculator.calculateUpgradePath(
        'test-package',
        '1.0.0',
        vulnerabilities
      );

      expect(upgradePath).toBeNull();
    });
  });
});
