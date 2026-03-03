#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report Generator
Generates HTML, JSON, XML, and TXT reports
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict

class ReportGenerator:
    """Generate scan reports in multiple formats"""
    
    async def generate(self, vulnerabilities: List, stats: Dict, 
                      output_file: str, format_type: str = 'html'):
        """Generate report in specified format"""
        
        if format_type == 'html':
            await self._generate_html(vulnerabilities, stats, output_file)
        elif format_type == 'json':
            await self._generate_json(vulnerabilities, stats, output_file)
        elif format_type == 'xml':
            await self._generate_xml(vulnerabilities, stats, output_file)
        elif format_type == 'txt':
            await self._generate_txt(vulnerabilities, stats, output_file)
    
    async def _generate_html(self, vulnerabilities: List, stats: Dict, output_file: str):
        """Generate HTML report"""
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: rgba(255,255,255,0.95);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .header h1 {{
            color: #e74c3c;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.95);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }}
        .stat-label {{
            color: #666;
            margin-top: 5px;
        }}
        .vulnerability {{
            background: rgba(255,255,255,0.95);
            margin-bottom: 20px;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            border-left: 5px solid #e74c3c;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .vuln-title {{
            color: #e74c3c;
            font-size: 1.3em;
        }}
        .severity {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }}
        .severity-Critical {{
            background: #e74c3c;
            color: white;
        }}
        .severity-High {{
            background: #e67e22;
            color: white;
        }}
        .severity-Medium {{
            background: #f39c12;
            color: white;
        }}
        .severity-Low {{
            background: #27ae60;
            color: white;
        }}
        .vuln-detail {{
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .vuln-label {{
            font-weight: bold;
            color: #2a5298;
        }}
        .payload-box {{
            background: #2c3e50;
            color: #2ecc71;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .proof-box {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: rgba(255,255,255,0.8);
            margin-top: 40px;
        }}
        .no-vuln {{
            text-align: center;
            padding: 60px;
            background: rgba(255,255,255,0.95);
            border-radius: 10px;
        }}
        .no-vuln h2 {{
            color: #27ae60;
            font-size: 2em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ XSS Vulnerability Scan Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{stats['urls_scanned']}</div>
                <div class="stat-label">URLs Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['forms_tested']}</div>
                <div class="stat-label">Forms Tested</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['parameters_tested']}</div>
                <div class="stat-label">Parameters Tested</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: {'#e74c3c' if stats['vulnerabilities_found'] > 0 else '#27ae60'};">
                    {stats['vulnerabilities_found']}
                </div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
        </div>
"""
        
        if not vulnerabilities:
            html_content += """
        <div class="no-vuln">
            <h2>✅ No XSS Vulnerabilities Found</h2>
            <p>The target appears to be secure against the tested XSS vectors.</p>
        </div>
"""
        else:
            for vuln in vulnerabilities:
                html_content += f"""
        <div class="vulnerability">
            <div class="vuln-header">
                <span class="vuln-title">🐛 {vuln.vulnerability_type}</span>
                <span class="severity severity-{vuln.severity}">{vuln.severity}</span>
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">URL:</span> {vuln.url}
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">Parameter:</span> {vuln.parameter}
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">Context:</span> {vuln.context}
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">Payload:</span>
                <div class="payload-box">{self._escape_html(vuln.payload)}</div>
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">Proof:</span>
                <div class="proof-box">{self._escape_html(vuln.proof)}</div>
            </div>
            <div class="vuln-detail">
                <span class="vuln-label">Timestamp:</span> {vuln.timestamp}
            </div>
        </div>
"""
        
        html_content += """
        <div class="footer">
            <p>Generated by Advanced XSS Scanner v3.0.0</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    async def _generate_json(self, vulnerabilities: List, stats: Dict, output_file: str):
        """Generate JSON report"""
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '3.0.0',
            },
            'statistics': stats,
            'vulnerabilities': [v.to_dict() for v in vulnerabilities]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    
    async def _generate_xml(self, vulnerabilities: List, stats: Dict, output_file: str):
        """Generate XML report"""
        root = ET.Element('xss_scan_report')
        
        # Scan info
        info = ET.SubElement(root, 'scan_info')
        ET.SubElement(info, 'timestamp').text = datetime.now().isoformat()
        ET.SubElement(info, 'version').text = '3.0.0'
        
        # Statistics
        stats_elem = ET.SubElement(root, 'statistics')
        for key, value in stats.items():
            ET.SubElement(stats_elem, key).text = str(value)
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, 'vulnerabilities')
        for vuln in vulnerabilities:
            v = ET.SubElement(vulns_elem, 'vulnerability')
            for key, value in vuln.to_dict().items():
                ET.SubElement(v, key).text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
    
    async def _generate_txt(self, vulnerabilities: List, stats: Dict, output_file: str):
        """Generate plain text report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("XSS VULNERABILITY SCAN REPORT\n")
            f.write("="*60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanner Version: 3.0.0\n\n")
            
            f.write("STATISTICS\n")
            f.write("-"*60 + "\n")
            for key, value in stats.items():
                f.write(f"{key}: {value}\n")
            
            f.write("\n" + "="*60 + "\n")
            f.write("VULNERABILITIES\n")
            f.write("="*60 + "\n\n")
            
            if not vulnerabilities:
                f.write("No vulnerabilities found.\n")
            else:
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"\n[{i}] {vuln.vulnerability_type}\n")
                    f.write(f"Severity: {vuln.severity}\n")
                    f.write(f"URL: {vuln.url}\n")
                    f.write(f"Parameter: {vuln.parameter}\n")
                    f.write(f"Payload: {vuln.payload}\n")
                    f.write(f"Context: {vuln.context}\n")
                    f.write(f"Proof: {vuln.proof}\n")
                    f.write(f"Time: {vuln.timestamp}\n")
                    f.write("-"*60 + "\n")
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))
