export { Scanner } from './core/scanner.js';
export { PackageParser } from './utils/package-parser.js';
export { SemverUtils } from './utils/semver-utils.js';
export { Logger, logger, LogLevel } from './utils/logger.js';
export { OSVClient } from './integrations/osv.js';
export type { 
  Vulnerability, 
  ScanResult, 
  Dependency, 
  SupplyChainThreat, 
  UpgradePath 
} from './types/vulnerability.js';
export type { 
  DepGuardianConfig, 
  ScanConfig, 
  GitHubConfig, 
  NotificationConfig, 
  CIConfig 
} from './types/config.js';
