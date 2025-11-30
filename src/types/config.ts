export interface ScanConfig {
  paths: string[];
  exclude: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  ignoredPackages: string[];
  ignoredVulnerabilities: string[];
}

export interface GitHubConfig {
  enabled: boolean;
  token: string;
  repository: string;
  baseBranch: string;
  labels: string[];
  reviewers: string[];
  separatePRs: boolean;
  prTitle: string;
}

export interface NotificationConfig {
  slack: {
    enabled: boolean;
    webhookUrl: string;
  };
  email: {
    enabled: boolean;
    recipients: string[];
  };
}

export interface CIConfig {
  failOnVulnerabilities: boolean;
  failOnSeverity: 'critical' | 'high' | 'medium' | 'low';
  failOnSupplyChainThreats: boolean;
}

export interface DepGuardianConfig {
  scan: ScanConfig;
  github: GitHubConfig;
  notifications: NotificationConfig;
  ci: CIConfig;
}
