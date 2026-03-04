#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""POST Scanner"""

from typing import List, Dict

class POSTScanner:
    async def scan_endpoint(self, url: str, session, params: Dict = None) -> List[Dict]:
        vulnerabilities = []
        payloads = [
            {"input": "<script>alert('XSS')</script>"},
            {"data": "<script>alert('XSS')</script>"},
        ]

        for payload in payloads:
            try:
                async with session.post(url, data=payload, ssl=False) as resp:
                    text = await resp.text()
                    for k, v in payload.items():
                        if v in text:
                            vulnerabilities.append({
                                'url': url, 'parameter': f'POST: {k}',
                                'payload': v, 'vulnerability_type': 'POST XSS',
                                'severity': 'High'
                            })
            except:
                continue
        return vulnerabilities
