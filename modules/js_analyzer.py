#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JavaScript Analyzer"""

import re
from typing import List, Dict

class JSAnalyzer:
    PATTERNS = {
        'eval_usage': (r'eval\s*\(', 'High', 'Use of eval()'),
        'innerHTML': (r'\.innerHTML\s*=', 'High', 'innerHTML assignment'),
        'document_write': (r'document\.write\s*\(', 'High', 'document.write'),
    }

    async def analyze(self, url: str, soup, content: str, session) -> List[Dict]:
        findings = []
        scripts = soup.find_all('script')

        for script in scripts:
            if script.string:
                findings.extend(self._analyze_content(script.string, f"{url} (inline)"))
        return findings

    def _analyze_content(self, code: str, source: str) -> List[Dict]:
        findings = []
        for name, (pattern, severity, desc) in self.PATTERNS.items():
            for match in re.finditer(pattern, code, re.I):
                line = code[:match.start()].count('\n') + 1
                findings.append({
                    'source': source, 'pattern': name, 'severity': severity,
                    'description': desc, 'line': line, 'match': match.group()
                })
        return findings
