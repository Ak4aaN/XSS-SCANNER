# Advanced XSS Scanner v3.0.0

A powerful, multi-module XSS (Cross-Site Scripting) vulnerability detection suite with 11 integrated components.

## ⚠️ Legal Disclaimer

This tool is for authorized security testing only. Always obtain proper permission before scanning any system you do not own.

## Features

- **11 Integrated Modules:**
  1. Payload Engine - 100+ XSS payloads with multiple encodings
  2. DOM Analyzer - DOM-based XSS detection
  3. WAF Bypass - 7 bypass techniques
  4. Smart Crawler - Automatic website crawling
  5. Report Generator - HTML/JSON/XML/TXT reports
  6. Blind XSS Handler - Callback server for blind XSS
  7. Context Analyzer - Precise injection context detection
  8. Headers Injector - HTTP header XSS testing
  9. JS Analyzer - JavaScript security analysis
  10. POST Scanner - POST endpoint testing
  11. Utils - Helper functions

## Installation

```bash
# Clone or download the scanner
cd XSS-Scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python xss_scanner.py -u http://example.com
```

### With Crawling
```bash
python xss_scanner.py -u http://example.com --crawl --depth 3
```

### Test Headers
```bash
python xss_scanner.py -u http://example.com --headers
```

### JSON Report
```bash
python xss_scanner.py -u http://example.com -o report.json --format json
```

### All Options
```bash
python xss_scanner.py -u http://example.com \
    --crawl \
    --depth 3 \
    --headers \
    -o report.html \
    --format html \
    -t 30
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL (required) |
| `-o, --output` | Output file (default: xss_report.html) |
| `-f, --format` | Report format: html/json/xml/txt |
| `--crawl` | Enable crawling |
| `-d, --depth` | Crawl depth (default: 2) |
| `-t, --timeout` | Request timeout (default: 30) |
| `--headers` | Test HTTP headers |
| `-v, --verbose` | Verbose output |

## File Structure

```
XSS-Scanner/
├── xss_scanner.py          # Main scanner
├── requirements.txt        # Dependencies
├── config.json            # Configuration
├── README.md              # This file
└── modules/
    ├── __init__.py        # Package init
    ├── payload_engine.py  # XSS payloads
    ├── dom_analyzer.py    # DOM XSS detection
    ├── waf_bypass.py      # WAF bypass
    ├── crawler.py         # Web crawler
    ├── report_generator.py # Report generation
    ├── blind_xss.py       # Blind XSS
    ├── context_analyzer.py # Context analysis
    ├── headers_injector.py # Header testing
    ├── js_analyzer.py     # JS analysis
    ├── post_scanner.py    # POST testing
    └── utils.py           # Utilities
```

## Payload Categories

- **Basic:** Simple script tags, event handlers
- **Advanced:** Case variations, comment injection
- **Polyglots:** Multi-context payloads
- **DOM:** Hash/fragment-based vectors
- **WAF Bypass:** Encoded/obfuscated payloads
- **HTML5:** New HTML5 elements
- **Framework-specific:** Angular, React, Vue

## Detection Capabilities

- Reflected XSS in URL parameters
- Stored XSS in forms
- DOM-based XSS
- Blind XSS (with callback server)
- Header-based XSS
- POST body XSS
- JavaScript sink analysis

## Output Formats

### HTML Report
Beautiful, color-coded report with:
- Statistics dashboard
- Vulnerability details
- Payloads and proof of concept
- Severity indicators

### JSON Report
Machine-readable format for integration

### XML Report
Standardized vulnerability format

### TXT Report
Plain text for quick review

## Examples

### Scan Single URL
```bash
python xss_scanner.py -u "http://testphp.vulnweb.com/search.php?test=query"
```

### Full Site Scan
```bash
python xss_scanner.py -u http://example.com --crawl -d 5 -o full_scan.html
```

### Quick Test
```bash
python xss_scanner.py -u http://target.com/page.php?id=1 --format txt
```

## Troubleshooting

### Module Not Found Error
Make sure you're running from the XSS-Scanner directory:
```bash
cd XSS-Scanner
python xss_scanner.py -u http://example.com
```

### SSL Errors
The scanner ignores SSL verification by default for testing purposes.

### Timeout Issues
Increase timeout with `-t` flag:
```bash
python xss_scanner.py -u http://slow-site.com -t 60
```

## Security Considerations

1. **Authorization:** Only scan systems you own or have written permission to test
2. **Rate Limiting:** Built-in delays to avoid overwhelming targets
3. **Data Handling:** Reports may contain sensitive data - handle securely
4. **False Positives:** Always manually verify findings

## License

For educational and authorized security testing purposes only.

## Author

Security Research Team

## Version History

- v3.0.0 - Current release with 11 modules
- v2.0.0 - Added DOM analysis and WAF bypass
- v1.0.0 - Initial release
