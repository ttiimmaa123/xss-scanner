# Practical XSS Scanner v3.0

import requests
import threading
import time
from queue import Queue

class XSSScanner:
    def __init__(self, urls, thread_count=5):
        self.urls = urls
        self.queue = Queue()
        self.thread_count = thread_count
        self.vulnerabilities = []
        self.start_time = time.time()

    def scan_url(self, url):
        try:
            response = requests.get(url)
            if "<script>alert(1)</script>" in response.text:
                self.vulnerabilities.append(url)
                print(f"[+] Found XSS vulnerability at: {url}")
            else:
                print(f"[-] No vulnerability found at: {url}")
        except requests.RequestException as e:
            print(f"[!] Error scanning {url}: {e}")

    def worker(self):
        while not self.queue.empty():
            url = self.queue.get()
            self.scan_url(url)
            self.queue.task_done()

    def run(self):
        # Load URLs into the queue
        for url in self.urls:
            self.queue.put(url)

        # Create threads
        threads = []
        for _ in range(self.thread_count):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)

        # Wait for all tasks to complete
        self.queue.join()
        for thread in threads:
            thread.join()

        # Reporting
        print(f"\nScan completed in {time.time() - self.start_time:.2f} seconds.")
        if self.vulnerabilities:
            print("Found vulnerabilities:")
            for vuln in self.vulnerabilities:
                print(vuln)
        else:
            print("No vulnerabilities found.")

# Example usage
if __name__ == '__main__':
    urls_to_scan = ['http://example.com']  # Replace with your target URLs
    scanner = XSSScanner(urls_to_scan)
    scanner.run()