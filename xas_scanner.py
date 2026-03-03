#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Vulnerability Scanner
==================================
A powerful, multi-module XSS detection suite with 11 integrated components.
Author: Security Research Team
Version: 3.0.0
"""

import sys
import os
import json
import time
import asyncio
import aiohttp
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
import re
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
import warnings
warnings.filterwarnings('ignore')

# Initialize colorama
init(autoreset=True)

# Import sub-modules
from modules.payload_engine import PayloadEngine
from modules.dom_analyzer import DOMAnalyzer
from modules.waf_bypass import WAFBypass
from modules.crawler import SmartCrawler
from modules.report_generator import ReportGenerator
from modules.blind_xss import BlindXSSHandler
from modules.context_analyzer import ContextAnalyzer
from modules.headers_injector import HeadersInjector
from modules.js_analyzer import JSAnalyzer
from modules.post_scanner import POSTScanner
from modules.utils import Utils

@dataclass
class Vulnerability:
    """Data class for storing vulnerability information"""
    url: str
    parameter: str
    payload: str
    vulnerability_type: str
    severity: str
    context: str
    proof: str
    timestamp: str
    
    def to_dict(self):
        return asdict(self)

class XSSScanner:
    """Main XSS Scanner Class"""
    
    VERSION = "3.0.0"
    
    def __init__(self, config: dict):
        self.config = config
        self.vulnerabilities: List[Vulnerability] = []
        self.scanned_urls: Set[str] = set()
        self.session = None
        self.stats = {
            'urls_scanned': 0,
            'forms_tested': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
            'start_time': None
        }
        
        # Initialize components
        self.payload_engine = PayloadEngine()
        self.dom_analyzer = DOMAnalyzer()
        self.waf_bypass = WAFBypass()
        self.crawler = SmartCrawler()
        self.report_gen = ReportGenerator()
        self.blind_xss = BlindXSSHandler()
        self.context_analyzer = ContextAnalyzer()
        self.headers_injector = HeadersInjector()
        self.js_analyzer = JSAnalyzer()
        self.post_scanner = POSTScanner()
        self.utils = Utils()
        
        # Colors
        self.R = Fore.RED
        self.G = Fore.GREEN
        self.Y = Fore.YELLOW
        self.B = Fore.BLUE
        self.C = Fore.CYAN
        self.M = Fore.MAGENTA
        self.W = Fore.WHITE
        self.RST = Style.RESET_ALL
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.get('timeout', 30))
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._get_headers()
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    def _get_headers(self) -> dict:
        """Get default HTTP headers"""
        return {
            'User-Agent': self.config.get('user_agent', 
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
    
    def banner(self):
        """Display scanner banner"""
        banner_text = f"""
{self.C}╔══════════════════════════════════════════════════════════════════╗
║{self.R}   ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗{self.C}║
║{self.R}   ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║{self.C}║
║{self.R}    ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║{self.C}║
║{self.R}    ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║{self.C}║
║{self.R}   ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║{self.C}║
║{self.R}   ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{self.C}║
║                                                                  ║
║{self.G}           Advanced XSS Detection Suite v{self.VERSION}{self.C}              ║
║{self.Y}              11-Module Integrated Scanner{self.C}                      ║
╚══════════════════════════════════════════════════════════════════╝{self.RST}
        """
        print(banner_text)
        
    async def scan_url(self, url: str, depth: int = 0) -> List[Vulnerability]:
        """Scan a single URL for XSS vulnerabilities"""
        if url in self.scanned_urls or depth > self.config.get('max_depth', 3):
            return []
            
        self.scanned_urls.add(url)
        self.stats['urls_scanned'] += 1
        
        print(f"\n{self.B}[*] Scanning: {self.C}{url}{self.RST}")
        
        vulnerabilities = []
        
        try:
            # Fetch page
            async with self.session.get(url, ssl=False) as response:
                content = await response.text()
                headers = dict(response.headers)
                status = response.status
                
                if status != 200:
                    print(f"{self.Y}[!] Non-200 status code: {status}{self.RST}")
                    return vulnerabilities
                
                # Parse HTML
                soup = BeautifulSoup(content, 'html.parser')
                
                # 1. Test URL parameters
                param_vulns = await self._test_url_parameters(url, content)
                vulnerabilities.extend(param_vulns)
                
                # 2. Test forms
                form_vulns = await self._test_forms(url, soup)
                vulnerabilities.extend(form_vulns)
                
                # 3. DOM-based XSS analysis
                dom_vulns = await self._analyze_dom(url, content, soup)
                vulnerabilities.extend(dom_vulns)
                
                # 4. Header injection tests
                if self.config.get('test_headers', True):
                    header_vulns = await self._test_headers(url)
                    vulnerabilities.extend(header_vulns)
                
                # 5. JavaScript analysis
                js_vulns = await self._analyze_javascript(url, soup, content)
                vulnerabilities.extend(js_vulns)
                
                # Crawl links if enabled
                if self.config.get('crawl', True) and depth < self.config.get('max_depth', 3):
                    links = self._extract_links(url, soup)
                    for link in links:
                        if self._is_same_domain(link, url):
                            sub_vulns = await self.scan_url(link, depth + 1)
                            vulnerabilities.extend(sub_vulns)
                            
        except Exception as e:
            print(f"{self.R}[!] Error scanning {url}: {str(e)}{self.RST}")
            
        return vulnerabilities
    
    async def _test_url_parameters(self, url: str, original_content: str) -> List[Vulnerability]:
        """Test URL parameters for reflected XSS"""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
            
        print(f"{self.C}[→] Testing {len(params)} URL parameters...{self.RST}")
        
        for param_name, param_values in params.items():
            self.stats['parameters_tested'] += 1
            payloads = self.payload_engine.get_payloads_for_context('url')
            
            for payload in payloads:
                # Encode payload for WAF bypass
                encoded_payloads = self.waf_bypass.encode_payload(payload)
                
                for enc_payload in encoded_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [enc_payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = parsed._replace(query=new_query).geturl()
                    
                    try:
                        async with self.session.get(test_url, ssl=False) as resp:
                            response_text = await resp.text()
                            
                            # Check if payload is reflected
                            if self._check_reflection(enc_payload, response_text, payload):
                                context = self.context_analyzer.analyze(
                                    response_text, enc_payload, payload
                                )
                                
                                vuln = Vulnerability(
                                    url=test_url,
                                    parameter=param_name,
                                    payload=payload,
                                    vulnerability_type="Reflected XSS",
                                    severity="High",
                                    context=context,
                                    proof=self._extract_proof(response_text, payload),
                                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                                )
                                vulnerabilities.append(vuln)
                                self._print_vulnerability(vuln)
                                break
                                
                    except Exception as e:
                        continue
                        
        return vulnerabilities
    
    async def _test_forms(self, url: str, soup: BeautifulSoup) -> List[Vulnerability]:
        """Test HTML forms for XSS"""
        vulnerabilities = []
        forms = soup.find_all('form')
        
        if not forms:
            return vulnerabilities
            
        print(f"{self.C}[→] Testing {len(forms)} forms...{self.RST}")
        
        for form in forms:
            self.stats['forms_tested'] += 1
            form_details = self._get_form_details(form)
            action = urljoin(url, form_details['action'])
            method = form_details['method'].upper()
            
            inputs = form_details['inputs']
            if not inputs:
                continue
                
            # Test each input field
            for input_field in inputs:
                if input_field['type'] in ['submit', 'button', 'image', 'hidden']:
                    continue
                    
                field_name = input_field['name']
                if not field_name:
                    continue
                    
                payloads = self.payload_engine.get_payloads_for_context('form')
                
                for payload in payloads:
                    data = {}
                    for inp in inputs:
                        if inp['name'] == field_name:
                            data[inp['name']] = payload
                        else:
                            data[inp['name']] = inp.get('value', 'test')
                    
                    try:
                        if method == 'POST':
                            async with self.session.post(action, data=data, ssl=False) as resp:
                                response_text = await resp.text()
                        else:
                            async with self.session.get(action, params=data, ssl=False) as resp:
                                response_text = await resp.text()
                                
                        if self._check_reflection(payload, response_text, payload):
                            context = self.context_analyzer.analyze(response_text, payload, payload)
                            
                            vuln = Vulnerability(
                                url=action,
                                parameter=field_name,
                                payload=payload,
                                vulnerability_type="Stored/Reflected XSS (Form)",
                                severity="Critical",
                                context=context,
                                proof=self._extract_proof(response_text, payload),
                                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                            )
                            vulnerabilities.append(vuln)
                            self._print_vulnerability(vuln)
                            break
                            
                    except Exception as e:
                        continue
                        
        return vulnerabilities
    
    async def _analyze_dom(self, url: str, content: str, soup: BeautifulSoup) -> List[Vulnerability]:
        """Analyze for DOM-based XSS"""
        print(f"{self.C}[→] Analyzing DOM sinks...{self.RST}")
        return await self.dom_analyzer.analyze(url, content, soup, self.session)
    
    async def _test_headers(self, url: str) -> List[Vulnerability]:
        """Test HTTP headers for XSS"""
        return await self.headers_injector.test(url, self.session)
    
    async def _analyze_javascript(self, url: str, soup: BeautifulSoup, content: str) -> List[Vulnerability]:
        """Analyze JavaScript files for XSS vulnerabilities"""
        print(f"{self.C}[→] Analyzing JavaScript...{self.RST}")
        return await self.js_analyzer.analyze(url, soup, content, self.session)
    
    def _check_reflection(self, payload: str, response: str, original: str) -> bool:
        """Check if payload is reflected in response"""
        # Check exact match
        if payload in response:
            return True
            
        # Check decoded match
        decoded = self.utils.html_decode(payload)
        if decoded in response and decoded != payload:
            return True
            
        # Check for script execution indicators
        execution_indicators = [
            f"<script>{original}</script>",
            f"onerror={original}",
            f"onload={original}",
            "javascript:",
            "alert(",
            "confirm(",
            "prompt(",
            "eval("
        ]
        
        for indicator in execution_indicators:
            if indicator in response.lower():
                return True
                
        return False
    
    def _extract_proof(self, response: str, payload: str) -> str:
        """Extract proof of vulnerability from response"""
        # Find context around payload
        index = response.find(payload)
        if index == -1:
            # Try decoded version
            decoded = self.utils.html_decode(payload)
            index = response.find(decoded)
            if index == -1:
                return "Payload reflected but location unclear"
        
        start = max(0, index - 100)
        end = min(len(response), index + len(payload) + 100)
        proof = response[start:end]
        
        # Clean up for display
        proof = proof.replace('\n', ' ').replace('\r', '')
        return f"...{proof}..."
    
    def _print_vulnerability(self, vuln: Vulnerability):
        """Print vulnerability details"""
        print(f"\n{self.R}{'='*60}{self.RST}")
        print(f"{self.R}[!!!] XSS VULNERABILITY DETECTED{self.RST}")
        print(f"{self.R}{'='*60}{self.RST}")
        print(f"{self.Y}URL:{self.RST} {vuln.url}")
        print(f"{self.Y}Parameter:{self.RST} {vuln.parameter}")
        print(f"{self.Y}Type:{self.RST} {vuln.vulnerability_type}")
        print(f"{self.Y}Severity:{self.RST} {vuln.severity}")
        print(f"{self.Y}Payload:{self.RST} {vuln.payload}")
        print(f"{self.Y}Context:{self.RST} {vuln.context}")
        print(f"{self.Y}Proof:{self.RST} {vuln.proof[:200]}...")
        print(f"{self.R}{'='*60}{self.RST}\n")
        
        self.vulnerabilities.append(vuln)
        self.stats['vulnerabilities_found'] += 1
    
    def _get_form_details(self, form) -> dict:
        """Extract form details"""
        details = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name')
            input_value = input_tag.get('value', '')
            
            if input_name:
                details['inputs'].append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })
                
        return details
    
    def _extract_links(self, url: str, soup: BeautifulSoup) -> Set[str]:
        """Extract all links from page"""
        links = set()
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
            for attr in ['href', 'src']:
                if tag.get(attr):
                    full_url = urljoin(url, tag.get(attr))
                    links.add(full_url)
        return links
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain"""
        return urlparse(url1).netloc == urlparse(url2).netloc
    
    async def generate_report(self, output_file: str):
        """Generate scan report"""
        await self.report_gen.generate(
            self.vulnerabilities, 
            self.stats, 
            output_file,
            self.config.get('format', 'html')
        )
    
    def print_summary(self):
        """Print scan summary"""
        duration = time.time() - self.stats['start_time']
        
        print(f"\n{self.G}{'='*60}{self.RST}")
        print(f"{self.G}SCAN SUMMARY{self.RST}")
        print(f"{self.G}{'='*60}{self.RST}")
        print(f"{self.C}URLs Scanned:{self.RST} {self.stats['urls_scanned']}")
        print(f"{self.C}Forms Tested:{self.RST} {self.stats['forms_tested']}")
        print(f"{self.C}Parameters Tested:{self.RST} {self.stats['parameters_tested']}")
        print(f"{self.R}Vulnerabilities Found:{self.RST} {self.stats['vulnerabilities_found']}")
        print(f"{self.C}Duration:{self.RST} {duration:.2f} seconds")
        print(f"{self.G}{'='*60}{self.RST}")

async def main():
    parser = argparse.ArgumentParser(
        description='Advanced XSS Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xss_scanner.py -u http://example.com
  python xss_scanner.py -u http://example.com --crawl --depth 3
  python xss_scanner.py -u http://example.com -o report.html --format html
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-o', '--output', default='xss_report.html', help='Output file')
    parser.add_argument('-f', '--format', choices=['html', 'json', 'xml', 'txt'], 
                       default='html', help='Report format')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Concurrent threads')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
    parser.add_argument('--blind', help='Blind XSS callback URL')
    parser.add_argument('--waf-bypass', action='store_true', help='Enable WAF bypass techniques')
    parser.add_argument('--headers', action='store_true', help='Test HTTP headers')
    parser.add_argument('--dom', action='store_true', help='Deep DOM analysis')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--proxy', help='Proxy URL (http://host:port)')
    
    args = parser.parse_args()
    
    config = {
        'target': args.url,
        'output': args.output,
        'format': args.format,
        'crawl': args.crawl,
        'max_depth': args.depth,
        'threads': args.threads,
        'timeout': args.timeout,
        'blind_xss': args.blind,
        'waf_bypass': args.waf_bypass,
        'test_headers': args.headers,
        'dom_analysis': args.dom,
        'verbose': args.verbose,
        'proxy': args.proxy,
        'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    }
    
    async with XSSScanner(config) as scanner:
        scanner.banner()
        scanner.stats['start_time'] = time.time()
        
        print(f"{self.Y}[*] Starting scan of {config['target']}{self.RST}")
        print(f"{self.Y}[*] Loaded 11 scanning modules{self.RST}\n")
        
        vulnerabilities = await scanner.scan_url(config['target'])
        
        scanner.print_summary()
        await scanner.generate_report(config['output'])
        
        print(f"\n{self.G}[+] Report saved to: {config['output']}{self.RST}")

if __name__ == "__main__":
    asyncio.run(main())
