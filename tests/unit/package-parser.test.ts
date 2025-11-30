import { describe, it, expect, vi } from 'vitest';
import { PackageParser } from '../../src/utils/package-parser.js';
import { readFile } from 'fs/promises';
import { join } from 'path';

// Mock fs module
vi.mock('fs/promises');

describe('PackageParser', () => {
  let packageParser: PackageParser;

  beforeEach(() => {
    packageParser = new PackageParser();
  });

  describe('parsePackageJson', () => {
    it('should parse a valid package.json file', async () => {
      const mockPackageJson = {
        name: 'test-project',
        version: '1.0.0',
        dependencies: {
          express: '^4.18.0',
          lodash: '4.17.21',
        },
        devDependencies: {
          vitest: '^1.0.0',
        },
      };

      vi.mocked(readFile).mockResolvedValue(JSON.stringify(mockPackageJson));

      const result = await packageParser.parsePackageJson('/test/path');

      expect(result).toEqual(mockPackageJson);
      expect(readFile).toHaveBeenCalledWith(join('/test/path', 'package.json'), 'utf-8');
    });

    it('should throw error for invalid JSON', async () => {
      vi.mocked(readFile).mockResolvedValue('invalid json');

      await expect(packageParser.parsePackageJson('/test/path')).rejects.toThrow('Failed to parse package.json');
    });

    it('should throw error when file does not exist', async () => {
      const error = new Error('ENOENT: no such file');
      vi.mocked(readFile).mockRejectedValue(error);

      await expect(packageParser.parsePackageJson('/test/path')).rejects.toThrow('Failed to parse package.json');
    });
  });

  describe('extractDependencies', () => {
    it('should extract all dependency types', () => {
      const packageJson = {
        dependencies: {
          express: '^4.18.0',
        },
        devDependencies: {
          vitest: '^1.0.0',
        },
        peerDependencies: {
          react: '^18.0.0',
        },
        optionalDependencies: {
          fsevents: '^2.3.0',
        },
      };

      const dependencies = packageParser.extractDependencies(packageJson);

      expect(dependencies).toHaveLength(4);
      expect(dependencies).toContainEqual({
        name: 'express',
        version: '^4.18.0',
        type: 'dependencies',
      });
      expect(dependencies).toContainEqual({
        name: 'vitest',
        version: '^1.0.0',
        type: 'devDependencies',
      });
      expect(dependencies).toContainEqual({
        name: 'react',
        version: '^18.0.0',
        type: 'peerDependencies',
      });
      expect(dependencies).toContainEqual({
        name: 'fsevents',
        version: '^2.3.0',
        type: 'optionalDependencies',
      });
    });

    it('should handle empty dependencies', () => {
      const packageJson = {};
      const dependencies = packageParser.extractDependencies(packageJson);

      expect(dependencies).toHaveLength(0);
    });
  });

  describe('parsePackageLockJson', () => {
    it('should parse package-lock.json format', () => {
      const lockJsonContent = {
        name: 'test-project',
        version: '1.0.0',
        lockfileVersion: 2,
        dependencies: {
          express: {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            integrity: 'sha512-123',
          },
        },
        packages: {
          'node_modules/express': {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            integrity: 'sha512-123',
          },
        },
      };

      const result = packageParser.parsePackageLockJson(JSON.stringify(lockJsonContent));

      expect(result.dependencies).toEqual(lockJsonContent.dependencies);
      expect(result.packages).toEqual(lockJsonContent.packages);
    });

    it('should handle empty lock file', () => {
      const lockJsonContent = { lockfileVersion: 2, dependencies: {}, packages: {} };
      const result = packageParser.parsePackageLockJson(JSON.stringify(lockJsonContent));

      expect(result.dependencies).toEqual({});
      expect(result.packages).toEqual({});
    });
  });

  describe('extractAllDependencies', () => {
    it('should extract dependencies from lock file', () => {
      const lockFile = {
        dependencies: {
          express: {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            integrity: 'sha512-123',
          },
          'lodash@4.17.21': {
            version: '4.17.21',
          },
        },
        packages: {
          'node_modules/express': {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            integrity: 'sha512-456',
          },
        },
      };

      const dependencies = packageParser.extractAllDependencies(lockFile);

      expect(dependencies).toHaveLength(3);
      expect(dependencies[0]).toEqual({
        name: 'express',
        version: '4.18.2',
        type: 'dependencies',
        resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
        integrity: 'sha512-123',
      });
      expect(dependencies[1]).toEqual({
        name: 'lodash',
        version: '4.17.21',
        type: 'dependencies',
      });
    });

    it('should handle empty lock file', () => {
      const lockFile = { dependencies: {}, packages: {} };
      const dependencies = packageParser.extractAllDependencies(lockFile);

      expect(dependencies).toHaveLength(0);
    });
  });
});
