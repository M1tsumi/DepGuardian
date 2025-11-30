import { ScanResult, Vulnerability, SupplyChainThreat } from '../types/vulnerability.js';
import { logger } from '../utils/logger.js';
import { writeFileSync } from 'fs';

export class HTMLReporter {
  generateReport(scanResult: ScanResult, outputPath: string): void {
    const html = this.generateHTML(scanResult);
    
    try {
      writeFileSync(outputPath, html, 'utf-8');
      logger.info(`HTML report generated: ${outputPath}`);
    } catch (error) {
      logger.error(`Failed to write HTML report: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  private generateHTML(scanResult: ScanResult): string {
    const timestamp = new Date().toISOString();
    const vulnerabilities = scanResult.vulnerabilities;
    const threats = scanResult.supplyChainThreats;

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DepGuardian Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
        }
        
        .summary-card h3 {
            font-size: 1.1em;
            color: #666;
            margin-bottom: 10px;
        }
        
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .critical { color: #e74c3c; }
        .high { color: #f39c12; }
        .medium { color: #f1c40f; }
        .low { color: #3498db; }
        .safe { color: #27ae60; }
        
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .section-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .section-header h2 {
            font-size: 1.5em;
            color: #333;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .vulnerability-item, .threat-item {
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: box-shadow 0.2s;
        }
        
        .vulnerability-item:hover, .threat-item:hover {
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #f39c12; color: white; }
        .severity-medium { background: #f1c40f; color: #333; }
        .severity-low { background: #3498db; color: white; }
        
        .package-name {
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
            color: #2c3e50;
        }
        
        .description {
            color: #666;
            margin-bottom: 15px;
            line-height: 1.5;
        }
        
        .details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .detail-item {
            font-size: 0.9em;
        }
        
        .detail-label {
            font-weight: bold;
            color: #666;
        }
        
        .detail-value {
            color: #333;
        }
        
        .evidence-list, .recommendations-list {
            list-style: none;
            margin-top: 10px;
        }
        
        .evidence-list li, .recommendations-list li {
            background: #f8f9fa;
            padding: 8px 12px;
            margin-bottom: 5px;
            border-radius: 4px;
            border-left: 4px solid #3498db;
        }
        
        .recommendations-list li {
            border-left-color: #27ae60;
        }
        
        .no-issues {
            text-align: center;
            padding: 40px;
            color: #27ae60;
            font-size: 1.2em;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ DepGuardian Security Report</h1>
            <div class="subtitle">Generated on ${new Date().toLocaleString()}</div>
        </header>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Packages</h3>
                <div class="number">${scanResult.totalPackages}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerable Packages</h3>
                <div class="number ${scanResult.vulnerablePackages > 0 ? 'critical' : 'safe'}">${scanResult.vulnerablePackages}</div>
            </div>
            <div class="summary-card">
                <h3>Supply Chain Threats</h3>
                <div class="number ${threats.length > 0 ? 'high' : 'safe'}">${threats.length}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="number">${scanResult.scanDuration}ms</div>
            </div>
        </div>

        ${vulnerabilities.length > 0 ? `
        <section class="section">
            <div class="section-header">
                <h2>🚨 Vulnerabilities Found (${vulnerabilities.length})</h2>
            </div>
            <div class="section-content">
                ${vulnerabilities.map(vuln => this.renderVulnerability(vuln)).join('')}
            </div>
        </section>
        ` : `
        <section class="section">
            <div class="section-content">
                <div class="no-issues">
                    ✅ No vulnerabilities found!
                </div>
            </div>
        </section>
        `}

        ${threats.length > 0 ? `
        <section class="section">
            <div class="section-header">
                <h2>⚠️ Supply Chain Threats (${threats.length})</h2>
            </div>
            <div class="section-content">
                ${threats.map(threat => this.renderThreat(threat)).join('')}
            </div>
        </section>
        ` : ''}

        <footer class="footer">
            <p>Report generated by DepGuardian v1.0.0 | Scan completed in ${scanResult.scanDuration}ms</p>
        </footer>
    </div>

    <script>
        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Add click-to-copy functionality for package names
            document.querySelectorAll('.package-name').forEach(element => {
                element.style.cursor = 'pointer';
                element.title = 'Click to copy';
                element.addEventListener('click', function() {
                    navigator.clipboard.writeText(this.textContent);
                    const original = this.textContent;
                    this.textContent = 'Copied!';
                    setTimeout(() => {
                        this.textContent = original;
                    }, 1000);
                });
            });

            // Add expand/collapse for long descriptions
            document.querySelectorAll('.description').forEach(element => {
                if (element.scrollHeight > element.clientHeight) {
                    element.style.cursor = 'pointer';
                    element.addEventListener('click', function() {
                        this.style.maxHeight = this.style.maxHeight ? '' : '200px';
                    });
                }
            });
        });
    </script>
</body>
</html>`;
  }

  private renderVulnerability(vuln: Vulnerability): string {
    const severityClass = `severity-${vuln.severity}`;
    
    return `
        <div class="vulnerability-item">
            <span class="severity-badge ${severityClass}">${vuln.severity}</span>
            <div class="package-name">${vuln.packageName}@${vuln.packageVersion}</div>
            <div class="description">
                <strong>${vuln.title}</strong><br>
                ${vuln.description}
            </div>
            <div class="details">
                ${vuln.cveId ? `
                <div class="detail-item">
                    <div class="detail-label">CVE ID:</div>
                    <div class="detail-value">${vuln.cveId}</div>
                </div>
                ` : ''}
                ${vuln.cvssScore ? `
                <div class="detail-item">
                    <div class="detail-label">CVSS Score:</div>
                    <div class="detail-value">${vuln.cvssScore}</div>
                </div>
                ` : ''}
                ${vuln.source ? `
                <div class="detail-item">
                    <div class="detail-label">Source:</div>
                    <div class="detail-value">${vuln.source}</div>
                </div>
                ` : ''}
                ${vuln.firstPatchedVersion ? `
                <div class="detail-item">
                    <div class="detail-label">Fixed in:</div>
                    <div class="detail-value">${vuln.firstPatchedVersion}</div>
                </div>
                ` : ''}
                ${vuln.publishedDate ? `
                <div class="detail-item">
                    <div class="detail-label">Published:</div>
                    <div class="detail-value">${new Date(vuln.publishedDate).toLocaleDateString()}</div>
                </div>
                ` : ''}
            </div>
            ${vuln.references && vuln.references.length > 0 ? `
            <div style="margin-top: 15px;">
                <strong>References:</strong>
                <ul style="margin-top: 5px; padding-left: 20px;">
                    ${vuln.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
                </ul>
            </div>
            ` : ''}
        </div>
    `;
  }

  private renderThreat(threat: SupplyChainThreat): string {
    const severityClass = `severity-${threat.severity}`;
    
    return `
        <div class="threat-item">
            <span class="severity-badge ${severityClass}">${threat.severity}</span>
            <div class="package-name">${threat.packageName}</div>
            <div class="description">
                <strong>${threat.type.replace('-', ' ').toUpperCase()}</strong><br>
                ${threat.description}
            </div>
            <div class="details">
                <div class="detail-item">
                    <div class="detail-label">Detected:</div>
                    <div class="detail-value">${new Date(threat.detectedAt).toLocaleString()}</div>
                </div>
            </div>
            ${threat.evidence && threat.evidence.length > 0 ? `
            <div style="margin-top: 15px;">
                <strong>Evidence:</strong>
                <ul class="evidence-list">
                    ${threat.evidence.slice(0, 3).map(evidence => `<li>${evidence}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
            ${threat.recommendations && threat.recommendations.length > 0 ? `
            <div style="margin-top: 15px;">
                <strong>Recommendations:</strong>
                <ul class="recommendations-list">
                    ${threat.recommendations.slice(0, 3).map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
        </div>
    `;
  }
}
