# XSS Vulnerability Scanner

A comprehensive Cross-Site Scripting (XSS) vulnerability scanner that can test web applications for various types of XSS vulnerabilities.

## Features

🎯 **Multiple XSS Detection Types:**
- Reflected XSS
- Stored XSS  
- DOM-based XSS
- Blind XSS

🚀 **Advanced Capabilities:**
- Multi-threaded scanning
- Form auto-discovery
- Parameter fuzzing
- Custom payload support
- Multiple output formats

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ttiimmaa123/xss-scanner.git
cd xss-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scanning
```bash
# Scan an IP address
python xss_scanner.py --target 192.168.1.100

# Scan a domain
python xss_scanner.py --target example.com

# Scan a specific URL
python xss_scanner.py --url https://example.com/page.php
```

### Advanced Options
```bash
# Deep scan with custom port
python xss_scanner.py --target example.com --port 8080 --deep-scan

# Use custom payloads
python xss_scanner.py --target example.com --custom-payloads payloads.txt

# Generate HTML report
python xss_scanner.py --target example.com --format html --output scan_results
```

## Examples

```python
from src.scanner import XSSScanner

# Basic usage
scanner = XSSScanner()
results = scanner.scan_target("192.168.1.100")

# Advanced configuration
scanner = XSSScanner(
    threads=10,
    timeout=30,
    custom_headers={'User-Agent': 'Custom Agent'}
)
results = scanner.scan_target("example.com", deep_scan=True)
```

## Ethical Use

⚠️ **Important:** This tool is for educational and authorized testing purposes only. Only use this scanner on systems you own or have explicit permission to test.

## License

MIT License - see LICENSE file for details.