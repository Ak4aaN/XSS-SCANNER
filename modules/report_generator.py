#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report Generator"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict

class ReportGenerator:
    async def generate(self, vulnerabilities: List, stats: Dict, output_file: str, format_type: str = 'html'):
        if format_type == 'html':
            await self._generate_html(vulnerabilities, stats, output_file)
        elif format_type == 'json':
            await self._generate_json(vulnerabilities, stats, output_file)
        elif format_type == 'xml':
            await self._generate_xml(vulnerabilities, stats, output_file)
        elif format_type == 'txt':
            await self._generate_txt(vulnerabilities, stats, output_file)

    async def _generate_html(self, vulnerabilities: List, stats: Dict, output_file: str):
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>XSS Report</title>
<style>
body {{ font-family: Arial; background: #f0f0f0; padding: 20px; }}
.container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
.header {{ background: #e74c3c; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
.stat {{ display: inline-block; margin: 10px 20px; }}
.vuln {{ border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; background: #f9f9f9; }}
.payload {{ background: #2c3e50; color: #2ecc71; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; }}
</style></head><body>
<div class="container">
<div class="header"><h1>XSS Scan Report</h1><p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p></div>
<div class="stats">
<div class="stat"><h3>{stats.get('urls_scanned', 0)}</h3><p>URLs Scanned</p></div>
<div class="stat"><h3>{stats.get('forms_tested', 0)}</h3><p>Forms Tested</p></div>
<div class="stat"><h3>{stats.get('vulnerabilities_found', 0)}</h3><p>Vulnerabilities</p></div>
</div>
<h2>Vulnerabilities Found</h2>
"""
        if not vulnerabilities:
            html += "<p>No vulnerabilities found.</p>"
        else:
            for v in vulnerabilities:
                html += f"""
<div class="vuln">
<h3>{v.vulnerability_type} ({v.severity})</h3>
<p><strong>URL:</strong> {v.url}</p>
<p><strong>Parameter:</strong> {v.parameter}</p>
<div class="payload">{v.payload}</div>
<p><strong>Context:</strong> {v.context}</p>
</div>
"""
        html += "</div></body></html>"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

    async def _generate_json(self, vulnerabilities: List, stats: Dict, output_file: str):
        report = {
            'timestamp': datetime.now().isoformat(),
            'statistics': stats,
            'vulnerabilities': [v.__dict__ if hasattr(v, '__dict__') else v for v in vulnerabilities]
        }
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

    async def _generate_xml(self, vulnerabilities: List, stats: Dict, output_file: str):
        root = ET.Element('report')
        stats_elem = ET.SubElement(root, 'statistics')
        for k, v in stats.items():
            ET.SubElement(stats_elem, k).text = str(v)
        vulns = ET.SubElement(root, 'vulnerabilities')
        for v in vulnerabilities:
            vuln = ET.SubElement(vulns, 'vulnerability')
            for key, val in (v.__dict__ if hasattr(v, '__dict__') else v).items():
                ET.SubElement(vuln, key).text = str(val)
        ET.ElementTree(root).write(output_file, encoding='utf-8', xml_declaration=True)

    async def _generate_txt(self, vulnerabilities: List, stats: Dict, output_file: str):
        with open(output_file, 'w') as f:
            f.write("XSS SCAN REPORT\n" + "="*50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for k, v in stats.items():
                f.write(f"{k}: {v}\n")
            f.write("\nVULNERABILITIES:\n" + "="*50 + "\n")
            for i, v in enumerate(vulnerabilities, 1):
                vd = v.__dict__ if hasattr(v, '__dict__') else v
                f.write(f"\n[{i}] {vd.get('vulnerability_type', 'Unknown')}\n")
                f.write(f"Severity: {vd.get('severity', 'Unknown')}\n")
                f.write(f"URL: {vd.get('url', 'Unknown')}\n")
                f.write(f"Payload: {vd.get('payload', 'Unknown')}\n")
                f.write("-"*50 + "\n")
