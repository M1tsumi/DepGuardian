#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { Scanner } from './core/scanner.js';
import { SafeUpgradeCalculator } from './core/updater.js';
import { GitHubIntegration } from './integrations/github.js';
import { HTMLReporter } from './reporting/html-reporter.js';
import { ConfigResolver, DepGuardianConfig } from './utils/config-resolver.js';
import { logger, LogLevel } from './utils/logger.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, resolve } from 'path';

const program = new Command();

function loadConfig(configPath?: string): DepGuardianConfig {
  const configResolver = ConfigResolver.getInstance();
  
  try {
    const config = configResolver.loadConfig(configPath);
    configResolver.validateConfig(config);
    return config;
  } catch (error) {
    if (error instanceof Error && error.message.includes('ENOENT')) {
      logger.warn('No configuration file found, using defaults');
      logger.info('Create a .depguardian.json file to customize settings');
      return configResolver.getDefaultConfig();
    }
    
    if (error instanceof SyntaxError) {
      logger.error('Configuration file contains invalid JSON');
      logger.error('Please check your .depguardian.json file for syntax errors');
      process.exit(1);
    }
    
    logger.error(`Configuration error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    process.exit(1);
  }
}

program
  .name('depguardian')
  .description('Scan your npm dependencies for known vulnerabilities and supply-chain red flags')
  .version('1.1.0');

program
  .command('scan')
  .description('Scan project for vulnerabilities')
  .argument('[path]', 'Path to scan', '.')
  .option('-s, --severity <level>', 'Only report vulnerabilities of specified severity', 'medium')
  .option('-i, --ignore <packages>', 'Comma-separated list of packages to ignore', '')
  .option('--pr', 'Create GitHub PR for fixes')
  .option('--fix', 'Automatically update dependencies')
  .option('--dry-run', 'Run actions in dry-run mode (no changes)')
  .option('--auto-fix', 'Suggest safe upgrades (works with --dry-run)')
  .option('--format <format>', 'Output format: json|html|md', 'text')
  // Backwards compatible flags
  .option('--json', 'Output results as JSON')
  .option('--html', 'Generate HTML report')
  .option('--markdown', 'Generate Markdown report')
  .option('-c, --config <path>', 'Path to config file')
  .option('--watch', 'Continuous monitoring mode')
  .option('-v, --verbose', 'Enable detailed logging')
  .option('-q, --quiet', 'Only show errors')
  .option('--log-level <level>', 'Set log level (debug, info, warn, error)', 'info')
  .action(async (path: string, options: any) => {
    // Configure logging based on options
    if (options.verbose) {
      logger.setLevel(LogLevel.DEBUG);
    } else if (options.quiet) {
      logger.setLevel(LogLevel.ERROR);
    } else {
      const levelMap: Record<string, LogLevel> = {
        debug: LogLevel.DEBUG,
        info: LogLevel.INFO,
        warn: LogLevel.WARN,
        error: LogLevel.ERROR
      };
      logger.setLevel(levelMap[options.logLevel] || LogLevel.INFO);
    }
    
    // Validate path
    const resolvedPath = resolve(path);
    if (!existsSync(resolvedPath)) {
      logger.error(`Path does not exist: ${resolvedPath}`);
      logger.info('Please provide a valid path to scan');
      process.exit(1);
    }
    
    const spinner = ora('Initializing scanner...').start();
    
    try {
      spinner.text = 'Loading configuration...';
      const config = loadConfig(options.config);
      
      // Apply config defaults to CLI options
      const severity = options.severity || config.scanning?.severity || 'medium';
      const ignorePackages = options.ignore ? options.ignore.split(',').map((s: string) => s.trim()) : (config.scanning?.ignorePackages || []);
      
      spinner.text = 'Initializing scanner...';
      const scanner = new Scanner(config.snyk);
      
      spinner.text = 'Analyzing dependencies...';
      const result = await scanner.scanProject(resolvedPath);
      
      spinner.succeed('Scan completed');
      
      // Determine output format (preference: --format, then legacy flags)
      let format = options.format || 'text';
      if (options.json) format = 'json';
      if (options.html) format = 'html';
      if (options.markdown) format = 'md';

      if (format === 'json') {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      if (format === 'html') {
        const htmlReporter = new HTMLReporter();
        const reportPath = join(process.cwd(), 'depguardian-report.html');
        htmlReporter.generateReport(result, reportPath, program.version);
        console.log(chalk.green(`\n📄 HTML report generated: ${reportPath}`));
        return;
      }

      if (format === 'md') {
        // Minimal markdown output
        console.log(`# DepGuardian Report\n\nGenerated: ${new Date().toISOString()}\n\n`);
        console.log(`Total packages: ${result.totalPackages}`);
        console.log(`Vulnerable packages: ${result.vulnerablePackages}`);
        return;
      }
      
      // Display results
      console.log(chalk.bold('\n📊 Scan Results:'));
      console.log(`Total packages: ${result.totalPackages}`);
      console.log(`Vulnerable packages: ${result.vulnerablePackages}`);
      console.log(`Scan duration: ${result.scanDuration}ms`);
      
      if (result.supplyChainThreats.length > 0) {
        console.log(chalk.bold('\n🚨 Supply Chain Threats:'));
        console.log(`Total threats: ${result.supplyChainThreats.length}`);
        
        const groupedThreats = result.supplyChainThreats.reduce((acc, threat) => {
          if (!acc[threat.severity]) acc[threat.severity] = [];
          acc[threat.severity].push(threat);
          return acc;
        }, {} as Record<string, typeof result.supplyChainThreats>);
        
        const severityOrder = ['critical', 'high', 'medium', 'low'];
        
        for (const severity of severityOrder) {
          const threats = groupedThreats[severity];
          if (threats && threats.length > 0) {
            const color = severity === 'critical' ? chalk.red.bold : 
                         severity === 'high' ? chalk.red :
                         severity === 'medium' ? chalk.yellow : chalk.blue;
            
            console.log(color(`\n${severity.toUpperCase()} (${threats.length}):`));
            
            threats.forEach(threat => {
              console.log(`  • ${threat.packageName} - ${threat.type}`);
              console.log(`    ${threat.description}`);
              console.log(`    Evidence: ${threat.evidence.slice(0, 2).join(', ')}...`);
            });
          }
        }
      }
      
      if (result.vulnerabilities.length > 0) {
        console.log(chalk.bold('\n🔴 Vulnerabilities Found:'));
        
        const groupedVulns = result.vulnerabilities.reduce((acc, vuln) => {
          if (!acc[vuln.severity]) acc[vuln.severity] = [];
          acc[vuln.severity].push(vuln);
          return acc;
        }, {} as Record<string, typeof result.vulnerabilities>);
        
        const severityOrder = ['critical', 'high', 'medium', 'low'];
        
        for (const severity of severityOrder) {
          const vulns = groupedVulns[severity];
          if (vulns && vulns.length > 0) {
            const color = severity === 'critical' ? chalk.red.bold : 
                         severity === 'high' ? chalk.red :
                         severity === 'medium' ? chalk.yellow : chalk.blue;
            
            console.log(color(`\n${severity.toUpperCase()} (${vulns.length}):`));
            
            vulns.forEach(vuln => {
              console.log(`  • ${vuln.packageName}@${vuln.packageVersion}`);
              console.log(`    ${vuln.title}`);
              console.log(`    ${vuln.description.substring(0, 100)}...`);
              if (vuln.cveId) {
                console.log(`    CVE: ${vuln.cveId}`);
              }
              console.log('');
            });
          }
        }
      } else {
        console.log(chalk.green('\n✅ No vulnerabilities found!'));
      }
      
      if (result.supplyChainThreats.length === 0 && result.vulnerabilities.length === 0) {
        console.log(chalk.green('\n✅ No security issues detected!'));
      }
      
      // Dry-run / auto-fix flow: suggest safe upgrades without making changes
      if (options.autoFix || options.fix) {
        if (!options.dryRun) {
          console.log(chalk.yellow('\n⚠️  Auto-fix will run in dry-run mode by default. Re-run with proper config to enable changes.'));
        }

        const SafeCalc = SafeUpgradeCalculator;
        const calc = new SafeCalc();

        // Build dependency list from vulnerabilities (unique)
        const depsMap: Record<string, any> = {};
        for (const v of result.vulnerabilities) {
          if (!depsMap[v.packageName]) depsMap[v.packageName] = { name: v.packageName, version: v.packageVersion || 'latest', type: 'dependencies' };
        }
        const deps = Object.values(depsMap);

        const upgradePaths = await calc.calculateAllUpgradePaths(deps, result.vulnerabilities);

        if (upgradePaths.length === 0) {
          console.log(chalk.green('\n✅ No safe upgrade paths found')); 
        } else {
          console.log(chalk.bold('\n🔧 Suggested Safe Upgrades:'));
          upgradePaths.forEach(up => {
            console.log(`- ${up.packageName}: ${up.currentVersion} -> ${up.targetVersion} (${up.confidence})`);
            if (up.changelogUrl) console.log(`  Changelog: ${up.changelogUrl}`);
          });
        }
      }

      if (options.pr) {
        console.log(chalk.yellow('\n⚠️  PR creation not yet implemented'));
      }
      
    } catch (error) {
      spinner.fail('Scan failed');
      console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
      process.exit(1);
    }
  });

program
  .command('check')
  .description('Check specific package for vulnerabilities')
  .argument('<package-name>', 'Package name to check')
  .option('-v, --version <version>', 'Specific version to check')
  .action(async (packageName: string, options: any) => {
    const spinner = ora(`Checking ${packageName}...`).start();
    
    try {
      const scanner = new Scanner();
      const vulnerabilities = await scanner.scanPackage(packageName, options.version || 'latest');
      
      spinner.succeed('Check completed');
      
      if (vulnerabilities.length > 0) {
        console.log(chalk.bold(`\n🔴 Found ${vulnerabilities.length} vulnerabilities in ${packageName}:`));
        
        vulnerabilities.forEach(vuln => {
          const color = vuln.severity === 'critical' ? chalk.red.bold : 
                       vuln.severity === 'high' ? chalk.red :
                       vuln.severity === 'medium' ? chalk.yellow : chalk.blue;
          
          console.log(color(`\n${vuln.severity.toUpperCase()}: ${vuln.title}`));
          console.log(`Version: ${vuln.packageVersion}`);
          console.log(`Description: ${vuln.description}`);
          if (vuln.cveId) {
            console.log(`CVE: ${vuln.cveId}`);
          }
          if (vuln.patchedVersions && vuln.patchedVersions.length > 0) {
            console.log(`Patched in: ${vuln.patchedVersions.join(', ')}`);
          }
        });
      } else {
        console.log(chalk.green(`\n✅ No vulnerabilities found in ${packageName}`));
      }
      
    } catch (error) {
      spinner.fail('Check failed');
      console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
      process.exit(1);
    }
  });

program
  .command('init')
  .description('Initialize configuration file')
  .action(() => {
    const configPath = join(process.cwd(), '.depguardian.json');
    
    try {
      // Check if config already exists
      readFileSync(configPath);
      console.log(chalk.yellow(`Configuration file already exists at ${configPath}`));
      return;
    } catch {
      // File doesn't exist, create it
    }
    
    const defaultConfig = {
      scan: {
        paths: ["."],
        exclude: ["node_modules", "dist", "build"],
        severity: "medium",
        ignoredPackages: [],
        ignoredVulnerabilities: []
      },
      snyk: {
        enabled: false,
        token: "${SNYK_TOKEN}",
        organization: "",
        endpoint: "https://api.snyk.io"
      },
      github: {
        enabled: false,
        token: "${GITHUB_TOKEN}",
        repository: "owner/repo",
        baseBranch: "main",
        labels: ["security", "dependencies", "automated"],
        reviewers: [],
        separatePRs: true,
        prTitle: "🔒 Security: Update [package] to fix [vulnerability]"
      },
      notifications: {
        slack: {
          enabled: false,
          webhookUrl: "${SLACK_WEBHOOK}"
        },
        email: {
          enabled: false,
          recipients: []
        }
      },
      ci: {
        failOnVulnerabilities: true,
        failOnSeverity: "high",
        failOnSupplyChainThreats: true
      }
    };
    
    try {
      writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2));
      console.log(chalk.green(`✅ Configuration file created at ${configPath}`));
    } catch (error) {
      console.error(chalk.red(`Failed to create config file: ${error instanceof Error ? error.message : 'Unknown error'}`));
      process.exit(1);
    }
  });

program
  .command('watch')
  .description('Watch mode for continuous monitoring')
  .argument('[path]', 'Path to watch', '.')
  .option('-i, --interval <minutes>', 'Check interval in minutes', '60')
  .action(async (path: string, options: any) => {
    console.log(chalk.blue(`👀 Watching ${path} for vulnerabilities (interval: ${options.interval} minutes)`));
    console.log(chalk.gray('Press Ctrl+C to stop'));
    
    const interval = parseInt(options.interval) * 60 * 1000; // Convert to milliseconds
    
    const scan = async () => {
      const spinner = ora('Scanning...').start();
      
      try {
        const scanner = new Scanner();
        const result = await scanner.scanProject(path);
        
        if (result.vulnerabilities.length > 0) {
          spinner.succeed(`Found ${result.vulnerabilities.length} vulnerabilities`);
          // TODO: Send notifications
        } else {
          spinner.succeed('No vulnerabilities found');
        }
      } catch (error) {
        spinner.fail('Scan failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
      }
    };
    
    // Initial scan
    await scan();
    
    // Set up interval
    const intervalId = setInterval(scan, interval);
    
    // Handle cleanup
    process.on('SIGINT', () => {
      clearInterval(intervalId);
      console.log(chalk.gray('\n👋 Stopped watching'));
      process.exit(0);
    });
  });

program.parse();
