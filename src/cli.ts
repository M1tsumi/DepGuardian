#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { Scanner } from './core/scanner.js';
import { SafeUpgradeCalculator } from './core/updater.js';
import { GitHubIntegration } from './integrations/github.js';
import { HTMLReporter } from './reporting/html-reporter.js';
import { logger } from './utils/logger.js';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const program = new Command();

function loadConfig(configPath?: string): any {
  try {
    const path = configPath || join(process.cwd(), '.depguardian.json');
    const configData = readFileSync(path, 'utf-8');
    return JSON.parse(configData);
  } catch {
    return {};
  }
}

program
  .name('depguardian')
  .description('Real-time npm vulnerability scanning with automatic PR creation')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan project for vulnerabilities')
  .argument('[path]', 'Path to scan', '.')
  .option('-s, --severity <level>', 'Only report vulnerabilities of specified severity', 'medium')
  .option('-i, --ignore <packages>', 'Comma-separated list of packages to ignore', '')
  .option('--pr', 'Create GitHub PR for fixes')
  .option('--fix', 'Automatically update dependencies')
  .option('--json', 'Output results as JSON')
  .option('--html', 'Generate HTML report')
  .option('--markdown', 'Generate Markdown report')
  .option('-c, --config <path>', 'Path to config file')
  .option('--watch', 'Continuous monitoring mode')
  .action(async (path: string, options: any) => {
    const spinner = ora('Scanning for vulnerabilities...').start();
    
    try {
      const config = loadConfig(options.config);
      const scanner = new Scanner(config.snyk);
      const result = await scanner.scanProject(path);
      
      spinner.succeed('Scan completed');
      
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }
      
      if (options.html) {
        const htmlReporter = new HTMLReporter();
        const reportPath = join(process.cwd(), 'depguardian-report.html');
        htmlReporter.generateReport(result, reportPath);
        console.log(chalk.green(`\n📄 HTML report generated: ${reportPath}`));
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
      
      // TODO: Implement PR creation, fixing, etc.
      if (options.pr) {
        console.log(chalk.yellow('\n⚠️  PR creation not yet implemented'));
      }
      
      if (options.fix) {
        console.log(chalk.yellow('\n⚠️  Auto-fix not yet implemented'));
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
