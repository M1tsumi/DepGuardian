import { readFileSync } from 'fs';
import { join } from 'path';
import { logger } from './logger.js';

export interface DepGuardianConfig {
  snyk?: {
    enabled: boolean;
    token?: string;
    organization?: string;
    endpoint?: string;
  };
  github?: {
    enabled: boolean;
    token?: string;
    owner?: string;
    repo?: string;
  };
  osv?: {
    enabled: boolean;
    endpoint?: string;
  };
  scanning?: {
    severity?: 'critical' | 'high' | 'medium' | 'low';
    ignorePackages?: string[];
    parallelRequests?: number;
  };
  reporting?: {
    format?: 'json' | 'html' | 'markdown';
    outputPath?: string;
  };
}

export class ConfigResolver {
  private static instance: ConfigResolver;
  private config: DepGuardianConfig = {};

  static getInstance(): ConfigResolver {
    if (!ConfigResolver.instance) {
      ConfigResolver.instance = new ConfigResolver();
    }
    return ConfigResolver.instance;
  }

  loadConfig(configPath?: string): DepGuardianConfig {
    try {
      const path = configPath || join(process.cwd(), '.depguardian.json');
      const configData = readFileSync(path, 'utf-8');
      const rawConfig = JSON.parse(configData);
      
      // Process environment variable substitution
      this.config = this.processEnvironmentVariables(rawConfig);
      
      logger.debug('Configuration loaded successfully');
      return this.config;
    } catch (error) {
      if (error instanceof Error && error.message.includes('ENOENT')) {
        logger.warn('No configuration file found, using defaults');
        return this.getDefaultConfig();
      }
      
      if (error instanceof SyntaxError) {
        logger.error('Configuration file contains invalid JSON');
        throw new Error('Invalid JSON in configuration file');
      }
      
      logger.error(`Configuration error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  private processEnvironmentVariables(config: any): DepGuardianConfig {
    const processed = JSON.parse(JSON.stringify(config));
    
    // Helper function to substitute environment variables
    const substitute = (value: any): any => {
      if (typeof value === 'string') {
        // Replace ${VAR_NAME} patterns with environment variables
        return value.replace(/\$\{([^}]+)\}/g, (match, varName) => {
          const envValue = process.env[varName];
          if (envValue === undefined) {
            logger.warn(`Environment variable ${varName} not found, keeping placeholder`);
            return match;
          }
          return envValue;
        });
      } else if (Array.isArray(value)) {
        return value.map(substitute);
      } else if (typeof value === 'object' && value !== null) {
        const result: any = {};
        for (const [key, val] of Object.entries(value)) {
          result[key] = substitute(val);
        }
        return result;
      }
      return value;
    };
    
    return substitute(processed);
  }

  getDefaultConfig(): DepGuardianConfig {
    return {
      snyk: {
        enabled: false,
        endpoint: 'https://api.snyk.io'
      },
      github: {
        enabled: false
      },
      osv: {
        enabled: true,
        endpoint: 'https://api.osv.dev'
      },
      scanning: {
        severity: 'medium',
        ignorePackages: [],
        parallelRequests: 20
      },
      reporting: {
        format: 'html',
        outputPath: './depguardian-report.html'
      }
    };
  }

  validateConfig(config: DepGuardianConfig): void {
    const errors: string[] = [];
    
    // Validate Snyk config
    if (config.snyk?.enabled && !config.snyk.token) {
      errors.push('Snyk token is required when Snyk integration is enabled');
    }
    
    // Validate GitHub config
    if (config.github?.enabled && !config.github.token) {
      errors.push('GitHub token is required when GitHub integration is enabled');
    }
    
    // Validate scanning config
    if (config.scanning?.parallelRequests && config.scanning.parallelRequests < 1) {
      errors.push('Parallel requests must be at least 1');
    }
    
    if (config.scanning?.severity && !['critical', 'high', 'medium', 'low'].includes(config.scanning.severity)) {
      errors.push('Severity must be one of: critical, high, medium, low');
    }
    
    if (errors.length > 0) {
      throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
    }
  }

  getConfig(): DepGuardianConfig {
    return this.config;
  }

  get(key: string): any {
    return this.getNestedValue(this.config, key);
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }
}
