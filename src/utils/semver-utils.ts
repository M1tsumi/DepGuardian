import * as semver from 'semver';

export class SemverUtils {
  /**
   * Check if a version satisfies a constraint
   */
  satisfies(version: string, constraint: string): boolean {
    try {
      return semver.satisfies(version, constraint);
    } catch {
      return false;
    }
  }

  /**
   * Find the latest version that satisfies a constraint
   */
  maxSatisfying(versions: string[], constraint: string): string | null {
    try {
      return semver.maxSatisfying(versions, constraint);
    } catch {
      return null;
    }
  }

  /**
   * Get the highest version from a list
   */
  maxVersion(versions: string[]): string | null {
    try {
      return semver.maxSatisfying(versions, '*');
    } catch {
      return null;
    }
  }

  /**
   * Check if version1 is greater than version2
   */
  greaterThan(version1: string, version2: string): boolean {
    try {
      return semver.gt(version1, version2);
    } catch {
      return false;
    }
  }

  /**
   * Check if an upgrade is breaking
   */
  isBreakingUpgrade(fromVersion: string, toVersion: string): boolean {
    try {
      const from = semver.coerce(fromVersion);
      const to = semver.coerce(toVersion);
      
      if (!from || !to) return true;
      
      // Major version changes are breaking
      return to.major > from.major;
    } catch {
      return true;
    }
  }

  /**
   * Get the next version that would fix vulnerabilities
   */
  getNextFixVersion(currentVersion: string, fixedVersions: string[]): string | null {
    try {
      const validVersions = fixedVersions.filter(v => {
        try {
          return semver.valid(v);
        } catch {
          return false;
        }
      });

      if (validVersions.length === 0) return null;

      // Find the smallest version that's greater than current
      const sortedVersions = validVersions.sort(semver.compare);
      
      for (const version of sortedVersions) {
        if (semver.gt(version, currentVersion)) {
          return version;
        }
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Parse a version range to get min and max versions
   */
  parseRange(range: string): { min: string | null; max: string | null } {
    try {
      const rangeObj = new semver.Range(range);
      return {
        min: rangeObj.set[0]?.[0]?.semver.version || null,
        max: rangeObj.set[0]?.[1]?.semver.version || null,
      };
    } catch {
      return { min: null, max: null };
    }
  }

  /**
   * Check if two versions have the same major version
   */
  sameMajorVersion(version1: string, version2: string): boolean {
    try {
      const v1 = semver.coerce(version1);
      const v2 = semver.coerce(version2);
      
      if (!v1 || !v2) return false;
      
      return v1.major === v2.major;
    } catch {
      return false;
    }
  }

  /**
   * Get all versions within a range
   */
  versionsInRange(allVersions: string[], range: string): string[] {
    try {
      return allVersions.filter(version => semver.satisfies(version, range));
    } catch {
      return [];
    }
  }
}
