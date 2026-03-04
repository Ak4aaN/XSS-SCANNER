#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF Bypass Techniques"""

import random
import base64
import html
from typing import List

class WAFBypass:
    def __init__(self):
        self.techniques = {
            'case_variation': self._case_variation,
            'encoding': self._encoding_bypass,
            'null_byte': self._null_byte,
            'double_encoding': self._double_encoding,
            'unicode': self._unicode_bypass,
        }

    def encode_payload(self, payload: str) -> List[str]:
        encoded = [payload]
        for name, technique in self.techniques.items():
            try:
                result = technique(payload)
                if isinstance(result, list):
                    encoded.extend(result)
                else:
                    encoded.append(result)
            except:
                continue
        return list(set(encoded))

    def _case_variation(self, payload: str) -> str:
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                      for c in payload if c.isalpha()) or payload

    def _encoding_bypass(self, payload: str) -> List[str]:
        return [
            ''.join(f'%{ord(c):02x}' for c in payload),
            ''.join(f'&#{ord(c)};' for c in payload),
            ''.join(f'&#x{ord(c):x};' for c in payload),
        ]

    def _null_byte(self, payload: str) -> str:
        return payload.replace('<', '%00<')

    def _double_encoding(self, payload: str) -> str:
        first = ''.join(f'%{ord(c):02x}' for c in payload)
        return first.replace('%', '%25')

    def _unicode_bypass(self, payload: str) -> List[str]:
        return [payload.replace('script', 'scr\u200bipt')]
