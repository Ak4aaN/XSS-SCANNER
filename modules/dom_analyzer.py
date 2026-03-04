#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DOM-based XSS Analyzer"""

import re
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
    SOURCES = [
        'document.URL', 'document.documentURI', 'document.URLUnencoded',
        'document.baseURI', 'location', 'location.href', 'location.search',
        'location.hash', 'location.pathname', 'window.name', 'document.cookie',
        'localStorage', 'sessionStorage', 'indexedDB', 'URLSearchParams'
    ]

    SINKS = {
        'execution': ['eval', 'setTimeout', 'setInterval', 'new Function'],
        'html': ['innerHTML', 'outerHTML', 'document.write', 'document.writeln'],
        'url': ['location', 'location.href', 'location.replace', 'window.open'],
    }

    async def analyze(self, url: str, content: str, soup: BeautifulSoup, session) -> List:
        vulnerabilities = []
        scripts = soup.find_all('script')

        for i, script in enumerate(scripts):
            if script.string:
                vulns = self._analyze_javascript(script.string, url, f"inline-{i}")
                vulnerabilities.extend(vulns)

        return vulnerabilities

    def _analyze_javascript(self, code: str, source: str, script_type: str) -> List:
        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            for src in self.SOURCES:
                if src in line:
                    for category, sinks in self.SINKS.items():
                        for sink in sinks:
                            if sink in line:
                                vuln = DOMVulnerability(
                                    url=source, source=src, sink=sink,
                                    payload=line.strip(), line_number=i, confidence="High"
                                )
                                vulnerabilities.append(vuln)
        return vulnerabilities
