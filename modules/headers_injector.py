#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Headers Injector"""

from typing import List, Dict

class HeadersInjector:
    HEADERS = ['User-Agent', 'Referer', 'X-Forwarded-For']

    async def test(self, url: str, session) -> List[Dict]:
        vulnerabilities = []
        payloads = ["<script>alert('XSS')</script>", "'-alert(1)-'"]

        for header in self.HEADERS:
            for payload in payloads:
                try:
                    async with session.get(url, headers={header: payload}, ssl=False) as resp:
                        text = await resp.text()
                        if payload in text:
                            vulnerabilities.append({
                                'url': url, 'parameter': f'Header: {header}',
                                'payload': payload, 'vulnerability_type': 'Header XSS',
                                'severity': 'Medium', 'context': 'Header reflected'
                            })
                            break
                except:
                    continue
        return vulnerabilities
