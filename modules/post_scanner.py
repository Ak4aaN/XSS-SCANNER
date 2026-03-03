#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POST Scanner
Scans POST endpoints for XSS vulnerabilities
"""

from typing import List, Dict
from urllib.parse import parse_qs

class POSTScanner:
    """Scan POST requests for XSS"""
    
    def __init__(self):
        self.content_types = [
            'application/x-www-form-urlencoded',
            'application/json',
            'text/xml',
            'multipart/form-data',
        ]
        
        self.payloads = [
            {"input": "<script>alert('XSS_JSON')</script>"},
            {"input": "'-alert(1)-'"},
            {"input": "\"><img src=x onerror=alert('XSS_JSON')>"},
            {"input": "<svg onload=alert('XSS_JSON')>"},
            {"data": "<script>alert('XSS_JSON')</script>"},
            {"value": "<script>alert('XSS_JSON')</script>"},
            {"content": "<script>alert('XSS_JSON')</script>"},
        ]
    
    async def scan_endpoint(self, url: str, session, params: Dict = None) -> List[Dict]:
        """Scan a POST endpoint"""
        vulnerabilities = []
        
        # Test with form data
        for payload_dict in self.payloads:
            try:
                async with session.post(url, data=payload_dict, ssl=False) as resp:
                    response_text = await resp.text()
                    
                    # Check for reflection
                    for key, value in payload_dict.items():
                        if value in response_text or 'XSS_JSON' in response_text:
                            vuln = {
                                'url': url,
                                'parameter': f'POST body: {key}',
                                'payload': value,
                                'vulnerability_type': 'POST-based XSS',
                                'severity': 'High',
                                'context': 'POST request body reflected'
                            }
                            vulnerabilities.append(vuln)
                            break
            except:
                continue
        
        # Test with JSON
        for payload_dict in self.payloads:
            try:
                async with session.post(
                    url, 
                    json=payload_dict,
                    headers={'Content-Type': 'application/json'},
                    ssl=False
                ) as resp:
                    response_text = await resp.text()
                    
                    for key, value in payload_dict.items():
                        if value in response_text or 'XSS_JSON' in response_text:
                            vuln = {
                                'url': url,
                                'parameter': f'JSON body: {key}',
                                'payload': value,
                                'vulnerability_type': 'JSON-based XSS',
                                'severity': 'High',
                                'context': 'JSON request body reflected'
                            }
                            vulnerabilities.append(vuln)
                            break
            except:
                continue
        
        return vulnerabilities
