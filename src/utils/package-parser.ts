import { readFile } from 'fs/promises';
import { join } from 'path';
import { Dependency } from '../types/vulnerability.js';

export interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export interface LockFile {
  dependencies: Record<string, DependencyInfo>;
  packages?: Record<string, DependencyInfo>;
}

export interface DependencyInfo {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, DependencyInfo>;
}

export class PackageParser {
  async parsePackageJson(projectPath: string): Promise<PackageJson> {
    const packageJsonPath = join(projectPath, 'package.json');
    
    try {
      const content = await readFile(packageJsonPath, 'utf-8');
      return JSON.parse(content) as PackageJson;
    } catch (error) {
      throw new Error(`Failed to parse package.json: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  extractDependencies(packageJson: PackageJson): Dependency[] {
    const dependencies: Dependency[] = [];

    const addDependencies = (deps: Record<string, string> | undefined, type: Dependency['type']) => {
      if (!deps) return;
      
      Object.entries(deps).forEach(([name, version]) => {
        dependencies.push({
          name,
          version,
          type,
        });
      });
    };

    addDependencies(packageJson.dependencies, 'dependencies');
    addDependencies(packageJson.devDependencies, 'devDependencies');
    addDependencies(packageJson.peerDependencies, 'peerDependencies');
    addDependencies(packageJson.optionalDependencies, 'optionalDependencies');

    return dependencies;
  }

  async parseLockFile(projectPath: string): Promise<LockFile | null> {
    const lockFiles = [
      'package-lock.json',
      'pnpm-lock.yaml',
      'yarn.lock'
    ];

    for (const lockFile of lockFiles) {
      const lockFilePath = join(projectPath, lockFile);
      
      try {
        const content = await readFile(lockFilePath, 'utf-8');
        
        if (lockFile === 'package-lock.json') {
          return this.parsePackageLockJson(content);
        } else if (lockFile === 'pnpm-lock.yaml') {
          return this.parsePnpmLockYaml(content);
        } else if (lockFile === 'yarn.lock') {
          return this.parseYarnLock(content);
        }
      } catch {
        // File doesn't exist or can't be parsed, try next
        continue;
      }
    }

    return null;
  }

  public parsePackageLockJson(content: string): LockFile {
    const lockData = JSON.parse(content);
    return {
      dependencies: lockData.dependencies || {},
      packages: lockData.packages || {}
    };
  }

  private parsePnpmLockYaml(content: string): LockFile {
    // Basic PNPM lock file parsing
    // This is a simplified implementation - in production, you'd want to use a proper YAML parser
    const dependencies: Record<string, DependencyInfo> = {};
    
    const lines = content.split('\n');
    let currentPackage = '';
    
    for (const line of lines) {
      if (line.startsWith('    ')) {
        // This is a property of the current package
        const trimmed = line.trim();
        if (trimmed.includes(':')) {
          const [key, value] = trimmed.split(':');
          if (currentPackage && dependencies[currentPackage]) {
            (dependencies[currentPackage] as any)[key.trim()] = value.trim().replace(/['"]/g, '');
          }
        }
      } else if (line.endsWith(':')) {
        // This is a new package
        currentPackage = line.slice(0, -1).trim();
        dependencies[currentPackage] = {
          version: '',
        };
      }
    }

    return { dependencies };
  }

  private parseYarnLock(content: string): LockFile {
    const dependencies: Record<string, DependencyInfo> = {};
    
    // Basic yarn.lock parsing - simplified implementation
    const entries = content.split('\n\n');
    
    for (const entry of entries) {
      const lines = entry.trim().split('\n');
      if (lines.length === 0) continue;
      
      const nameVersionMatch = lines[0].match(/^(.+?)@(.+?):$/);
      if (!nameVersionMatch) continue;
      
      const [, name, version] = nameVersionMatch;
      const depInfo: DependencyInfo = { version };
      
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('resolved ')) {
          depInfo.resolved = line.slice(9).replace(/['"]/g, '');
        } else if (line.startsWith('integrity ')) {
          depInfo.integrity = line.slice(10).replace(/['"]/g, '');
        }
      }
      
      dependencies[`${name}@${version}`] = depInfo;
    }

    return { dependencies };
  }

  extractAllDependencies(lockFile: LockFile): Dependency[] {
    const dependencies: Dependency[] = [];
    
    const processDeps = (deps: Record<string, DependencyInfo>) => {
      Object.entries(deps).forEach(([key, info]) => {
        // Extract package name from key (format might be "package@version" or just "package")
        const name = key.includes('@') ? key.split('@').slice(0, -1).join('@') : key;
        
        dependencies.push({
          name,
          version: info.version,
          type: 'dependencies', // Lock files don't distinguish dependency types
          resolved: info.resolved,
          integrity: info.integrity,
        });
      });
    };

    processDeps(lockFile.dependencies);
    if (lockFile.packages) {
      processDeps(lockFile.packages);
    }

    return dependencies;
  }
}
