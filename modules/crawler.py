#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart Web Crawler
Intelligent crawling with form discovery
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List, Dict
import asyncio

class SmartCrawler:
    """Intelligent web crawler for XSS scanning"""
    
    def __init__(self):
        self.visited_urls: Set[str] = set()
        self.forms_found: List[Dict] = []
        self.parameters_found: Set[str] = set()
        
    async def crawl(self, start_url: str, session, max_depth: int = 3, 
                   max_urls: int = 100) -> List[str]:
        """Crawl website starting from start_url"""
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
                        
                        # Extract links
                        new_urls = self._extract_urls(current_url, soup)
                        
                        # Extract forms
                        forms = self._extract_forms(current_url, soup)
                        self.forms_found.extend(forms)
                        
                        # Extract parameters from URL
                        self._extract_parameters(current_url)
                        
                        for url in new_urls:
                            if url not in self.visited_urls:
                                urls_to_visit.append((url, depth + 1))
                        
                        found_urls.append(current_url)
                        
            except Exception as e:
                continue
        
        return found_urls
    
    def _extract_urls(self, base_url: str, soup: BeautifulSoup) -> Set[str]:
        """Extract all URLs from page"""
        urls = set()
        base_domain = urlparse(base_url).netloc
        
        # Find all links
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'form']):
            for attr in ['href', 'src', 'action']:
                if tag.get(attr):
                    url = urljoin(base_url, tag.get(attr))
                    parsed = urlparse(url)
                    
                    # Only same domain
                    if parsed.netloc == base_domain:
                        # Remove fragment
                        url = url.split('#')[0]
                        urls.add(url)
        
        # Find URLs in JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Find URLs in JS
                url_pattern = r'["\']((?:https?:)?//[^"\']+|/[^"\']+)["\']'
                matches = re.findall(url_pattern, script.string)
                for match in matches:
                    full_url = urljoin(base_url, match)
                    if urlparse(full_url).netloc == base_domain:
                        urls.add(full_url)
        
        # Find URLs in onclick handlers
        onclick_elements = soup.find_all(onclick=True)
        for elem in onclick_elements:
            onclick = elem.get('onclick', '')
            matches = re.findall(r'location\.href\s*=\s*["\']([^"\']+)["\']', onclick)
            for match in matches:
                urls.add(urljoin(base_url, match))
        
        return urls
    
    def _extract_forms(self, url: str, soup: BeautifulSoup) -> List[Dict]:
        """Extract all forms from page"""
        forms = []
        
        for form in soup.find_all('form'):
            form_info = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Get all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'id': input_tag.get('id'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.get('required') is not None
                }
                form_info['inputs'].append(input_info)
            
            forms.append(form_info)
        
        return forms
    
    def _extract_parameters(self, url: str):
        """Extract URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params.keys():
            self.parameters_found.add(param)
    
    def get_forms(self) -> List[Dict]:
        """Get all discovered forms"""
        return self.forms_found
    
    def get_parameters(self) -> Set[str]:
        """Get all discovered parameters"""
        return self.parameters_found
