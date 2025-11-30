import { describe, it, expect } from 'vitest';
import { SemverUtils } from '../../src/utils/semver-utils.js';

describe('SemverUtils', () => {
  let semverUtils: SemverUtils;

  beforeEach(() => {
    semverUtils = new SemverUtils();
  });

  describe('satisfies', () => {
    it('should check if version satisfies constraint', () => {
      expect(semverUtils.satisfies('1.0.0', '^1.0.0')).toBe(true);
      expect(semverUtils.satisfies('1.1.0', '^1.0.0')).toBe(true);
      expect(semverUtils.satisfies('2.0.0', '^1.0.0')).toBe(false);
      expect(semverUtils.satisfies('1.0.0', '>=1.0.0')).toBe(true);
      expect(semverUtils.satisfies('0.9.0', '>=1.0.0')).toBe(false);
    });

    it('should handle invalid versions gracefully', () => {
      expect(semverUtils.satisfies('invalid', '^1.0.0')).toBe(false);
      expect(semverUtils.satisfies('1.0.0', 'invalid')).toBe(false);
    });
  });

  describe('maxSatisfying', () => {
    it('should find the latest version that satisfies constraint', () => {
      const versions = ['1.0.0', '1.1.0', '1.2.0', '2.0.0'];
      
      expect(semverUtils.maxSatisfying(versions, '^1.0.0')).toBe('1.2.0');
      expect(semverUtils.maxSatisfying(versions, '1.1.x')).toBe('1.1.0');
      expect(semverUtils.maxSatisfying(versions, '2.x.x')).toBe('2.0.0');
      expect(semverUtils.maxSatisfying(versions, '3.x.x')).toBe(null);
    });

    it('should handle empty versions array', () => {
      expect(semverUtils.maxSatisfying([], '^1.0.0')).toBe(null);
    });
  });

  describe('greaterThan', () => {
    it('should compare versions correctly', () => {
      expect(semverUtils.greaterThan('2.0.0', '1.0.0')).toBe(true);
      expect(semverUtils.greaterThan('1.2.0', '1.1.0')).toBe(true);
      expect(semverUtils.greaterThan('1.0.0', '1.0.0')).toBe(false);
      expect(semverUtils.greaterThan('1.0.0', '2.0.0')).toBe(false);
    });

    it('should handle invalid versions', () => {
      expect(semverUtils.greaterThan('invalid', '1.0.0')).toBe(false);
      expect(semverUtils.greaterThan('1.0.0', 'invalid')).toBe(false);
    });
  });

  describe('isBreakingUpgrade', () => {
    it('should detect breaking upgrades', () => {
      expect(semverUtils.isBreakingUpgrade('1.0.0', '2.0.0')).toBe(true);
      expect(semverUtils.isBreakingUpgrade('1.5.0', '2.0.0')).toBe(true);
      expect(semverUtils.isBreakingUpgrade('2.0.0', '3.0.0')).toBe(true);
    });

    it('should allow non-breaking upgrades', () => {
      expect(semverUtils.isBreakingUpgrade('1.0.0', '1.1.0')).toBe(false);
      expect(semverUtils.isBreakingUpgrade('1.0.0', '1.0.1')).toBe(false);
      expect(semverUtils.isBreakingUpgrade('1.5.0', '1.6.0')).toBe(false);
    });

    it('should handle invalid versions', () => {
      expect(semverUtils.isBreakingUpgrade('invalid', '2.0.0')).toBe(true);
      expect(semverUtils.isBreakingUpgrade('1.0.0', 'invalid')).toBe(true);
    });
  });

  describe('getNextFixVersion', () => {
    it('should find the next version that fixes vulnerabilities', () => {
      const fixedVersions = ['1.0.1', '1.0.2', '1.1.0', '2.0.0'];
      
      expect(semverUtils.getNextFixVersion('1.0.0', fixedVersions)).toBe('1.0.1');
      expect(semverUtils.getNextFixVersion('1.0.1', fixedVersions)).toBe('1.0.2');
      expect(semverUtils.getNextFixVersion('1.0.2', fixedVersions)).toBe('1.1.0');
      expect(semverUtils.getNextFixVersion('1.1.0', fixedVersions)).toBe('2.0.0');
    });

    it('should return null if no fix version available', () => {
      const fixedVersions = ['1.0.1', '1.0.2'];
      
      expect(semverUtils.getNextFixVersion('2.0.0', fixedVersions)).toBe(null);
      expect(semverUtils.getNextFixVersion('1.0.2', fixedVersions)).toBe(null);
    });

    it('should handle empty fixed versions', () => {
      expect(semverUtils.getNextFixVersion('1.0.0', [])).toBe(null);
    });
  });

  describe('sameMajorVersion', () => {
    it('should check if versions have same major version', () => {
      expect(semverUtils.sameMajorVersion('1.0.0', '1.1.0')).toBe(true);
      expect(semverUtils.sameMajorVersion('1.5.0', '1.9.0')).toBe(true);
      expect(semverUtils.sameMajorVersion('2.0.0', '2.1.0')).toBe(true);
      expect(semverUtils.sameMajorVersion('1.0.0', '2.0.0')).toBe(false);
    });

    it('should handle pre-release versions', () => {
      expect(semverUtils.sameMajorVersion('1.0.0-alpha', '1.0.0-beta')).toBe(true);
      expect(semverUtils.sameMajorVersion('1.0.0', '2.0.0-alpha')).toBe(false);
    });

    it('should handle invalid versions', () => {
      expect(semverUtils.sameMajorVersion('invalid', '1.0.0')).toBe(false);
      expect(semverUtils.sameMajorVersion('1.0.0', 'invalid')).toBe(false);
    });
  });

  describe('versionsInRange', () => {
    it('should filter versions within range', () => {
      const allVersions = ['1.0.0', '1.0.1', '1.1.0', '2.0.0', '2.1.0'];
      
      expect(semverUtils.versionsInRange(allVersions, '^1.0.0')).toEqual(['1.0.0', '1.0.1', '1.1.0']);
      expect(semverUtils.versionsInRange(allVersions, '2.x.x')).toEqual(['2.0.0', '2.1.0']);
      expect(semverUtils.versionsInRange(allVersions, '>=1.1.0')).toEqual(['1.1.0', '2.0.0', '2.1.0']);
    });

    it('should handle empty versions array', () => {
      expect(semverUtils.versionsInRange([], '^1.0.0')).toEqual([]);
    });

    it('should handle invalid range', () => {
      const allVersions = ['1.0.0', '1.1.0'];
      expect(semverUtils.versionsInRange(allVersions, 'invalid')).toEqual([]);
    });
  });
});
