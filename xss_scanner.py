#!/usr/bin/env python3
import sys
import requests
import argparse
from urllib.parse import urlparse, urljoin

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<script>alert('XSS1')</script>",
            "<img src=x onerror=alert('XSS2')>", 
            "<svg/onload=alert('XSS3')>",
            "javascript:alert('XSS4')",
            "'><script>alert('XSS5')</script>",
            '"><script>alert('XSS6')</script>',
            "<iframe src=javascript:alert('XSS7')></iframe>",
            "<body onload=alert('XSS8')>",
            "<input type=button onclick=alert('XSS9') value=Click>",
            "<div onmouseover=alert('XSS10')>Hover</div>"
        ]
        
    def scan_url(self, target_url):
        """Scan target URL for XSS vulnerabilities"""
        print(f"[+] Starting XSS scan on: {target_url}")
        print(f"[+] Testing {len(self.payloads)} payloads...")
        print("-" * 60)
        
        results = []
        
        for i, payload in enumerate(self.payloads, 1):
            print(f"[{i}/{len(self.payloads)}] Testing payload: {payload[:50]}...")
            
            # Test GET parameter injection
            test_url = f"{target_url}?test={payload}"
            
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                if self.check_reflection(response.text, payload):
                    result = {
                        'type': 'Reflected XSS',
                        'url': test_url,
                        'payload': payload,
                        'method': 'GET',
                        'status': 'VULNERABLE'
                    }
                    results.append(result)
                    print(f"    [!] VULNERABLE - Payload reflected!")
                else:
                    print(f"    [-] Safe - Payload not reflected")
                    
            except requests.RequestException as e:
                print(f"    [!] Request failed: {str(e)}")
            except Exception as e:
                print(f"    [!] Error: {str(e)}")
        
        return results
    
    def check_reflection(self, response_text, payload):
        """Check if payload is reflected in response"""
        # Simple reflection check
        if payload.lower() in response_text.lower():
            return True
        
        # Check for common XSS indicators
        xss_indicators = ['alert(', 'javascript:', '<script', 'onerror=', 'onload=', 'onmouseover=']
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        for indicator in xss_indicators:
            if indicator in payload_lower and indicator in response_lower:
                return True
                
        return False
    
    def display_results(self, results):
        """Display scan results"""
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        
        if results:
            print(f"[!] Found {len(results)} potential XSS vulnerabilities:")
            print()
            
            for i, result in enumerate(results, 1):
                print(f"Vulnerability #{i}:")
                print(f"  Type: {result['type']}")
                print(f"  Method: {result['method']}")
                print(f"  URL: {result['url']}")
                print(f"  Payload: {result['payload']}")
                print(f"  Status: {result['status']}")
                print() 
        else:
            print("[+] No XSS vulnerabilities found.")
            print("[i] The target appears to be protected against basic XSS attacks.")
        
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='XSS Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan (e.g., https://example.com)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    target_url = args.target
    
    # Validate URL
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        print("[!] Error: Invalid URL format. Use: https://example.com")
        sys.exit(1)
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Initialize scanner
    scanner = XSSScanner()
    
    try:
        # Perform scan
        results = scanner.scan_url(target_url)
        
        # Display results
        scanner.display_results(results)
        
        # Exit code based on results
        if results:
            sys.exit(1)  # Vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()