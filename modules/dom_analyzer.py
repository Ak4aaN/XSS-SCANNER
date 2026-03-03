#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DOM-based XSS Analyzer
Detects DOM XSS vulnerabilities through source/sink analysis
"""

import re
import json
from typing import List, Dict
from bs4 import BeautifulSoup
from dataclasses import dataclass

@dataclass
class DOMVulnerability:
    url: str
    source: str
    sink: str
    payload: str
    line_number: int
    confidence: str

class DOMAnalyzer:
    """Analyzes JavaScript for DOM-based XSS vulnerabilities"""
    
    SOURCES = [
        'document.URL',
        'document.documentURI',
        'document.URLUnencoded',
        'document.baseURI',
        'location',
        'location.href',
        'location.search',
        'location.hash',
        'location.pathname',
        'window.name',
        'document.cookie',
        'localStorage',
        'sessionStorage',
        'indexedDB',
        'URLSearchParams',
        'history.pushState',
        'history.replaceState',
        'postMessage',
    ]
    
    SINKS = {
        'execution': [
            'eval',
            'setTimeout',
            'setInterval',
            'new Function',
            'setImmediate',
            'execScript',
            'crypto.generateCRMFRequest',
        ],
        'html': [
            'innerHTML',
            'outerHTML',
            'document.write',
            'document.writeln',
            'insertAdjacentHTML',
            'domManip',
            'parseHTML',
        ],
        'url': [
            'location',
            'location.href',
            'location.replace',
            'location.assign',
            'window.open',
            'postMessage',
        ],
        'jquery': [
            '.html',
            '.append',
            '.prepend',
            '.after',
            '.before',
            '.replaceWith',
            '.wrap',
            '.wrapAll',
        ],
        'angular': [
            '$eval',
            '$parse',
            '$interpolate',
            '$compile',
            '$sanitize',
        ],
        'react': [
            'dangerouslySetInnerHTML',
            'innerHTML',
        ],
        'vue': [
            'v-html',
            '{{',
            '${',
        ]
    }
    
    def __init__(self):
        self.vulnerabilities = []
        
    async def analyze(self, url: str, content: str, soup: BeautifulSoup, session) -> List:
        """Analyze page for DOM-based XSS"""
        vulnerabilities = []
        
        # Extract inline scripts
        scripts = soup.find_all('script')
        inline_scripts = []
        external_scripts = []
        
        for script in scripts:
            if script.string:
                inline_scripts.append(script.string)
            elif script.get('src'):
                external_scripts.append(script['src'])
        
        # Analyze inline scripts
        for i, script in enumerate(inline_scripts):
            vulns = self._analyze_javascript(script, url, f"inline-{i}")
            vulnerabilities.extend(vulns)
        
        # Fetch and analyze external scripts
        for script_url in external_scripts:
            try:
                full_url = url if script_url.startswith('http') else url + script_url
                async with session.get(full_url, ssl=False) as resp:
                    if resp.status == 200:
                        js_content = await resp.text()
                        vulns = self._analyze_javascript(js_content, full_url, "external")
                        vulnerabilities.extend(vulns)
            except:
                continue
        
        # Check for DOM XSS indicators in HTML
        dom_indicators = self._check_dom_indicators(soup)
        
        return vulnerabilities
    
    def _analyze_javascript(self, code: str, source: str, script_type: str) -> List:
        """Analyze JavaScript code for DOM XSS patterns"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for source to sink flows
            for source in self.SOURCES:
                if source in line:
                    for category, sinks in self.SINKS.items():
                        for sink in sinks:
                            if sink in line:
                                # Potential DOM XSS found
                                confidence = self._calculate_confidence(line, source, sink)
                                vuln = DOMVulnerability(
                                    url=source,
                                    source=source,
                                    sink=sink,
                                    payload=line.strip(),
                                    line_number=i,
                                    confidence=confidence
                                )
                                vulnerabilities.append(vuln)
            
            # Check for dangerous patterns
            dangerous_patterns = [
                r'location\s*=\s*.*\+',
                r'location\.href\s*=\s*.*\+',
                r'location\.replace\s*\(.*\+',
                r'location\.assign\s*\(.*\+',
                r'eval\s*\(.*(location|document\.URL)',
                r'innerHTML\s*=\s*.*\+',
                r'document\.write\s*\(.*\+',
                r'\.html\s*\(.*\+',
                r'\.append\s*\(.*\+',
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = DOMVulnerability(
                        url=source,
                        source="dynamic_input",
                        sink="execution",
                        payload=line.strip(),
                        line_number=i,
                        confidence="High"
                    )
                    if vuln not in vulnerabilities:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_confidence(self, line: str, source: str, sink: str) -> str:
        """Calculate confidence level of vulnerability"""
        confidence = "Medium"
        
        # High confidence if direct assignment
        if '=' in line and (source in line.split('=')[1] and sink in line.split('=')[0]):
            confidence = "High"
        
        # High confidence if no sanitization
        if not any(sanitizer in line.lower() for sanitizer in 
                  ['escape', 'encode', 'sanitize', 'filter', 'clean', 'purify']):
            confidence = "High"
        
        # Low confidence if sanitization detected
        if any(sanitizer in line.lower() for sanitizer in 
               ['escape', 'encode', 'sanitize']):
            confidence = "Low"
            
        return confidence
    
    def _check_dom_indicators(self, soup: BeautifulSoup) -> List[Dict]:
        """Check HTML for DOM XSS indicators"""
        indicators = []
        
        # Check for hash-based routing
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Check for hashchange listeners
                if 'hashchange' in script.string or 'popstate' in script.string:
                    indicators.append({
                        'type': 'hash_router',
                        'description': 'Hash-based routing detected - potential DOM XSS vector'
                    })
                
                # Check for postMessage listeners
                if 'addEventListener' in script.string and 'message' in script.string:
                    indicators.append({
                        'type': 'postMessage',
                        'description': 'postMessage listener detected - check origin validation'
                    })
        
        # Check for dangerous HTML attributes
        dangerous_attrs = ['onerror', 'onload', 'onmouseover', 'onclick', 'onfocus']
        for attr in dangerous_attrs:
            elements = soup.find_all(attrs={attr: True})
            for elem in elements:
                indicators.append({
                    'type': 'event_handler',
                    'element': elem.name,
                    'attribute': attr,
                    'value': elem.get(attr)
                })
        
        return indicators
