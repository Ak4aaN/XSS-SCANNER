#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utility Functions
Helper functions for the scanner
"""

import re
import html
import random
import string
import hashlib
from urllib.parse import unquote, urlparse

class Utils:
    """Utility functions"""

    @staticmethod
    def html_decode(text: str) -> str:
        """Decode HTML entities"""
        return html.unescape(text)

    @staticmethod
    def url_decode(text: str) -> str:
        """URL decode"""
        return unquote(text)

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid"""
        pattern = re.compile(
            r'^https?://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(pattern.match(url))

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename"""
        return re.sub(r'[^\w\-\_\. ]', '_', filename)

    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        return urlparse(url).netloc

    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """Generate random string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def calculate_hash(text: str) -> str:
        """Calculate MD5 hash"""
        return hashlib.md5(text.encode()).hexdigest()
