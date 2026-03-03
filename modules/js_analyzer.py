#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JavaScript Analyzer
Analyzes JavaScript files for security issues
"""

import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import List, Dict

class JSAnalyzer:
    """Analyze JavaScript files for XSS vulnerabilities"""
    
    DANGEROUS_PATTERNS = {
        'eval_usage': {
            'pattern': r'eval\s*\(',
            'severity': 'High',
            'description': 'Use of eval() detected'
        },
        'innerHTML': {
            'pattern': r'\.innerHTML\s*=',
            'severity': 'High',
            'description': 'Direct innerHTML assignment'
        },
        'document_write': {
            'pattern': r'document\.write\s*\(',
            'severity': 'High',
            'description': 'document.write usage'
        },
        'setTimeout_string': {
            'pattern': r'setTimeout\s*\(\s*["\']',
            'severity': 'Medium',
            'description': 'setTimeout with string argument'
        },
        'setInterval_string': {
            'pattern': r'setInterval\s*\(\s*["\']',
            'severity': 'Medium',
            'description': 'setInterval with string argument'
        },
        'new_function': {
            'pattern': r'new\s+Function\s*\(',
            'severity': 'High',
            'description': 'Dynamic code execution with Function constructor'
        },
        'jquery_html': {
            'pattern': r'\$\([^)]+\)\.html\s*\(',
            'severity': 'Medium',
            'description': 'jQuery .html() usage'
        },
        'jquery_append': {
            'pattern': r'\$\([^)]+\)\.append\s*\(',
            'severity': 'Low',
            'description': 'jQuery .append() usage'
        },
        'postMessage': {
            'pattern': r'postMessage\s*\(',
            'severity': 'Medium',
            'description': 'postMessage usage - check origin validation'
        },
        'localStorage_access': {
            'pattern': r'localStorage\.(getItem|setItem)',
            'severity': 'Info',
            'description': 'localStorage access'
        },
        'sessionStorage_access': {
            'pattern': r'sessionStorage\.(getItem|setItem)',
            'severity': 'Info',
            'description': 'sessionStorage access'
        },
        'cookie_access': {
            'pattern': r'document\.cookie',
            'severity': 'Info',
            'description': 'Cookie access'
        },
        'webpack_sourcemap': {
            'pattern': r'//# sourceMappingURL=',
            'severity': 'Low',
            'description': 'Source map reference found'
        },
        'debug_mode': {
            'pattern': r'debug\s*=\s*true|console\.(log|debug|info)',
            'severity': 'Info',
            'description': 'Debug code in production'
        },
        'sensitive_comments': {
            'pattern': r'(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE|REVIEW)',
            'severity': 'Info',
            'description': 'Development comments found'
        },
        'api_keys': {
            'pattern': r'(api[_-]?key|apikey|secret[_-]?key|password)\s*[:=]\s*["\'][^"\']+["\']',
            'severity': 'Critical',
            'description': 'Potential API key or secret'
        },
        'internal_ips': {
            'pattern': r'\b(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)[0-9.]+\b',
            'severity': 'Medium',
            'description': 'Internal IP address exposed'
        },
    }
    
    async def analyze(self, url: str, soup: BeautifulSoup, content: str, session) -> List[Dict]:
        """Analyze JavaScript files"""
        findings = []
        
        # Find all script tags
        scripts = soup.find_all('script')
        
        for script in scripts:
            src = script.get('src')
            
            if src:
                # External script
                full_url = urljoin(url, src)
                try:
                    async with session.get(full_url, ssl=False) as resp:
                        if resp.status == 200:
                            js_content = await resp.text()
                            script_findings = self._analyze_js_content(js_content, full_url)
                            findings.extend(script_findings)
                except:
                    continue
            else:
                # Inline script
                if script.string:
                    script_findings = self._analyze_js_content(script.string, f"{url} (inline)")
                    findings.extend(script_findings)
        
        return findings
    
    def _analyze_js_content(self, content: str, source: str) -> List[Dict]:
        """Analyze JavaScript content"""
        findings = []
        
        for pattern_name, pattern_info in self.DANGEROUS_PATTERNS.items():
            matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE)
            
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ')
                
                finding = {
                    'source': source,
                    'pattern': pattern_name,
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description'],
                    'line': line_num,
                    'context': context,
                    'match': match.group()
                }
                findings.append(finding)
        
        return findings
