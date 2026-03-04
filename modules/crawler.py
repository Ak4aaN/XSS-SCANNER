#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Smart Web Crawler"""

import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List, Dict

class SmartCrawler:
    def __init__(self):
        self.visited_urls: Set[str] = set()
        self.forms_found: List[Dict] = []

    async def crawl(self, start_url: str, session, max_depth: int = 3, max_urls: int = 100) -> List[str]:
        urls_to_visit = [(start_url, 0)]
        found_urls = []

        while urls_to_visit and len(self.visited_urls) < max_urls:
            current_url, depth = urls_to_visit.pop(0)
            if current_url in self.visited_urls or depth > max_depth:
                continue

            self.visited_urls.add(current_url)

            try:
                async with session.get(current_url, ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        new_urls = self._extract_urls(current_url, soup)
                        forms = self._extract_forms(current_url, soup)
                        self.forms_found.extend(forms)

                        for url in new_urls:
                            if url not in self.visited_urls:
                                urls_to_visit.append((url, depth + 1))
                        found_urls.append(current_url)
            except:
                continue

        return found_urls

    def _extract_urls(self, base_url: str, soup: BeautifulSoup) -> Set[str]:
        urls = set()
        base_domain = urlparse(base_url).netloc

        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'form']):
            for attr in ['href', 'src', 'action']:
                if tag.get(attr):
                    url = urljoin(base_url, tag.get(attr))
                    if urlparse(url).netloc == base_domain:
                        urls.add(url.split('#')[0])
        return urls

    def _extract_forms(self, url: str, soup: BeautifulSoup) -> List[Dict]:
        forms = []
        for form in soup.find_all('form'):
            form_info = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                if input_tag.get('name'):
                    form_info['inputs'].append({
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
            forms.append(form_info)
        return forms
