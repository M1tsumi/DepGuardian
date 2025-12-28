import { ScanResult, Vulnerability, SupplyChainThreat } from '../types/vulnerability.js';
import { logger } from '../utils/logger.js';
import { writeFileSync } from 'fs';

export class HTMLReporter {
    generateReport(scanResult: ScanResult, outputPath: string, version?: string): void {
        const html = this.generateHTML(scanResult, version);
    
    try {
      writeFileSync(outputPath, html, 'utf-8');
      logger.info(`HTML report generated: ${outputPath}`);
    } catch (error) {
      logger.error(`Failed to write HTML report: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

    private generateHTML(scanResult: ScanResult, version?: string): string {
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
        
        /* Mobile Responsive */
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            .summary {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .summary-card {
                padding: 20px;
            }
            
            .summary-card .number {
                font-size: 2em;
            }
            
            .section-header, .section-content {
                padding: 15px;
            }
            
            .vulnerability-item, .threat-item {
                padding: 15px;
            }
            
            .details {
                grid-template-columns: 1fr;
            }
        }
        
        /* Interactive Elements */
        .copy-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8em;
            transition: background 0.2s;
        }
        
        .copy-btn:hover {
            background: #2980b9;
        }
        
        .copy-btn.copied {
            background: #27ae60;
        }
        
        .search-box {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 1em;
            margin-bottom: 20px;
        }
        
        .search-box:focus {
            outline: none;
            border-color: #3498db;
        }
        
        .filter-group {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid #e9ecef;
            background: white;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .filter-btn.active {
            background: #3498db;
            color: white;
            border-color: #3498db;
        }
        
        .expandable {
            cursor: pointer;
        }
        
        .expandable .toggle-icon {
            transition: transform 0.2s;
        }
        
        .expandable.expanded .toggle-icon {
            transform: rotate(180deg);
        }
        
        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        
        .collapsible-content.expanded {
            max-height: 1000px;
        }
        
        /* Accessibility */
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0,0,0,0);
            white-space: nowrap;
            border: 0;
        }
        
        :focus-visible {
            outline: 2px solid #3498db;
            outline-offset: 2px;
        }
        
        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
            body {
                background-color: #1a1a1a;
                color: #e0e0e0;
            }
            
            .summary-card, .section, .vulnerability-item, .threat-item {
                background: #2d2d2d;
                color: #e0e0e0;
            }
            
            .section-header {
                background: #3d3d3d;
                border-bottom-color: #4d4d4d;
            }
            
            .evidence-list li, .recommendations-list li {
                background: #3d3d3d;
            }
        }
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

        ${vulnerabilities.length > 0 || threats.length > 0 ? `
        <div style="margin-bottom: 30px;">
            <input type="text" class="search-box" placeholder="🔍 Search vulnerabilities, threats, or package names..." id="searchBox">
            
            <div class="filter-group">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="critical">Critical</button>
                <button class="filter-btn" data-filter="high">High</button>
                <button class="filter-btn" data-filter="medium">Medium</button>
                <button class="filter-btn" data-filter="low">Low</button>
            </div>
        </div>
        ` : ''}

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
            <p>Report generated by DepGuardian ${version ? `v${version}` : ''} | Scan completed in ${scanResult.scanDuration}ms</p>
        </footer>
    </div>

    <script>
        // Enhanced interactive features
        document.addEventListener('DOMContentLoaded', function() {
            const searchBox = document.getElementById('searchBox');
            const filterButtons = document.querySelectorAll('.filter-btn');
            const allItems = document.querySelectorAll('.vulnerability-item, .threat-item');
            
            // Search functionality
            if (searchBox) {
                searchBox.addEventListener('input', function() {
                    const searchTerm = this.value.toLowerCase();
                    filterItems(searchTerm, getCurrentFilter());
                });
            }
            
            // Filter functionality
            filterButtons.forEach(button => {
                button.addEventListener('click', function() {
                    filterButtons.forEach(btn => btn.classList.remove('active'));
                    this.classList.add('active');
                    const searchTerm = searchBox ? searchBox.value.toLowerCase() : '';
                    filterItems(searchTerm, this.dataset.filter);
                });
            });
            
            function getCurrentFilter() {
                const activeBtn = document.querySelector('.filter-btn.active');
                return activeBtn ? activeBtn.dataset.filter : 'all';
            }
            
            function filterItems(searchTerm, severityFilter) {
                allItems.forEach(item => {
                    const text = item.textContent.toLowerCase();
                    const severity = item.querySelector('.severity-badge').textContent.toLowerCase();
                    
                    const matchesSearch = !searchTerm || text.includes(searchTerm);
                    const matchesSeverity = severityFilter === 'all' || severity === severityFilter;
                    
                    if (matchesSearch && matchesSeverity) {
                        item.style.display = 'block';
                    } else {
                        item.style.display = 'none';
                    }
                });
                
                updateSectionHeaders();
            }
            
            function updateSectionHeaders() {
                const sections = document.querySelectorAll('.section');
                sections.forEach(section => {
                    const visibleItems = section.querySelectorAll('.vulnerability-item:not([style*="display: none"]), .threat-item:not([style*="display: none"])');
                    const header = section.querySelector('h2');
                    if (header && visibleItems.length > 0) {
                        const originalText = header.textContent.split('(')[0].trim();
                        header.textContent = \`\${originalText} (\${visibleItems.length})\`;
                    }
                });
            }
            
            // Enhanced click-to-copy functionality
            document.querySelectorAll('.package-name').forEach(element => {
                element.style.cursor = 'pointer';
                element.title = 'Click to copy package name';
                element.addEventListener('click', function(e) {
                    e.stopPropagation();
                    const packageName = this.textContent;
                    navigator.clipboard.writeText(packageName).then(() => {
                        const originalBg = this.style.backgroundColor;
                        this.style.backgroundColor = '#27ae60';
                        this.style.color = 'white';
                        this.textContent = 'Copied!';
                        
                        setTimeout(() => {
                            this.style.backgroundColor = originalBg;
                            this.style.color = '';
                            this.textContent = packageName;
                        }, 1500);
                    }).catch(() => {
                        // Fallback for older browsers
                        const textArea = document.createElement('textarea');
                        textArea.value = packageName;
                        document.body.appendChild(textArea);
                        textArea.select();
                        document.execCommand('copy');
                        document.body.removeChild(textArea);
                        
                        this.textContent = 'Copied!';
                        setTimeout(() => {
                            this.textContent = packageName;
                        }, 1000);
                    });
                });
            });
            
            // Add expand/collapse for long content
            document.querySelectorAll('.description').forEach(element => {
                if (element.scrollHeight > 120) {
                    element.style.maxHeight = '120px';
                    element.style.overflow = 'hidden';
                    element.style.position = 'relative';
                    
                    const expandBtn = document.createElement('button');
                    expandBtn.textContent = 'Show more';
                    expandBtn.className = 'copy-btn';
                    expandBtn.style.marginTop = '10px';
                    expandBtn.style.fontSize = '0.9em';
                    
                    let isExpanded = false;
                    expandBtn.addEventListener('click', function(e) {
                        e.stopPropagation();
                        isExpanded = !isExpanded;
                        
                        if (isExpanded) {
                            element.style.maxHeight = 'none';
                            this.textContent = 'Show less';
                        } else {
                            element.style.maxHeight = '120px';
                            this.textContent = 'Show more';
                        }
                    });
                    
                    element.parentNode.insertBefore(expandBtn, element.nextSibling);
                }
            });
            
            // Keyboard navigation
            document.addEventListener('keydown', function(e) {
                if (e.key === '/' && document.activeElement !== searchBox) {
                    e.preventDefault();
                    if (searchBox) searchBox.focus();
                }
                
                if (e.key === 'Escape') {
                    if (searchBox) {
                        searchBox.value = '';
                        searchBox.blur();
                        filterItems('', getCurrentFilter());
                    }
                }
            });
            
            // Accessibility improvements
            document.querySelectorAll('.severity-badge').forEach(badge => {
                const severity = badge.textContent;
                badge.setAttribute('aria-label', \`Severity level: \${severity}\`);
                badge.setAttribute('role', 'status');
            });
            
            // Add ARIA live region for search results
            const liveRegion = document.createElement('div');
            liveRegion.setAttribute('aria-live', 'polite');
            liveRegion.setAttribute('aria-atomic', 'true');
            liveRegion.className = 'sr-only';
            document.body.appendChild(liveRegion);
            
            // Update live region when filters change
            const originalFilterItems = filterItems;
            filterItems = function(searchTerm, severityFilter) {
                originalFilterItems(searchTerm, severityFilter);
                
                const visibleCount = document.querySelectorAll('.vulnerability-item:not([style*="display: none"]), .threat-item:not([style*="display: none"])').length;
                const totalCount = allItems.length;
                
                liveRegion.textContent = \`Showing \${visibleCount} of \${totalCount} items\`;
            };
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
