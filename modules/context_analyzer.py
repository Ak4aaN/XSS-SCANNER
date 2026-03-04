#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Context Analyzer
Analyzes where payload is reflected in response
"""

import re

class ContextAnalyzer:
    """Analyze XSS payload context in response"""

    def analyze(self, response: str, encoded_payload: str, original_payload: str) -> str:
        """Analyze the context of payload reflection"""

        # Define patterns as separate variables to avoid quote issues
        html_attr_pattern = r'<[^>]+=["\'][^"\']*' + re.escape(encoded_payload) + r'[^"\']*["\'][^>]*>'
        script_pattern = r'<script[^>]*>.*' + re.escape(encoded_payload) + r'.*</script>'
        js_string_pattern = r'["\'][^"\']*' + re.escape(encoded_payload) + r'[^"\']*["\']'
        comment_pattern = r'<!--.*' + re.escape(encoded_payload) + r'.*-->'
        textarea_pattern = r'<textarea[^>]*>.*' + re.escape(encoded_payload) + r'.*</textarea>'
        title_pattern = r'<title>.*' + re.escape(encoded_payload) + r'.*</title>'
        body_pattern = r'<body[^>]*>.*' + re.escape(encoded_payload) + r'.*</body>'

        # Check each context
        if re.search(script_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Inside script tag (Exploitable)"

        if re.search(js_string_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Inside JavaScript string (Exploitable)"

        if re.search(html_attr_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Inside HTML attribute value (Exploitable)"

        if re.search(comment_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Inside HTML comment (Not directly exploitable)"

        if re.search(textarea_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Inside textarea (Not directly exploitable)"

        if re.search(title_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Inside title tag (Exploitable)"

        if re.search(body_pattern, response, re.IGNORECASE | re.DOTALL):
            return "Inside HTML body content (Exploitable)"

        # Check if in URL
        if encoded_payload in response and 'href=' in response:
            return "Inside URL/href attribute (check for javascript: protocol)"

        # Check if reflected at all
        if encoded_payload not in response and original_payload not in response:
            return "Not reflected in response"

        return "Unknown context (reflected but location unclear)"

    def get_context_specific_payload(self, context: str, base_payload: str) -> str:
        """Get payload tailored for specific context"""

        if 'attribute' in context.lower():
            return '" onmouseover="alert(1)" x="'
        elif 'javascript string' in context.lower():
            return "';alert(1);//"
        elif 'javascript code' in context.lower():
            return "alert(1)"
        elif 'style' in context.lower():
            return "expression(alert(1))"
        elif 'title' in context.lower():
            return "</title><script>alert(1)</script>"
        elif 'textarea' in context.lower():
            return "</textarea><script>alert(1)</script>"

        return base_payload
