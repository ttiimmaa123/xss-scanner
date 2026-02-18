import requests
import sys

# Basic XSS payloads for testing.
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
]

def test_get(url):
    for payload in XSS_PAYLOADS:
        # Append payload to URL
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url)
            # Check for payload in response
            if payload in response.text:
                print(f"XSS vulnerability found at: {test_url}")
            else:
                print(f"No XSS at: {test_url}")
        except requests.RequestException as e:
            print(f"Error during GET request: {e}")


def test_post(url):
    for payload in XSS_PAYLOADS:
        # Prepare data with payload
        data = {"input": payload}
        try:
            response = requests.post(url, data=data)
            # Check for payload in response
            if payload in response.text:
                print(f"XSS vulnerability found at: {url}")
            else:
                print(f"No XSS at: {url}")
        except requests.RequestException as e:
            print(f"Error during POST request: {e}")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python xss_scanner.py <url> <method (get/post)>")
        sys.exit(1)

    target_url = sys.argv[1]
    method = sys.argv[2].lower()

    if method == 'get':
        test_get(target_url)
    elif method == 'post':
        test_post(target_url)
    else:
        print("Invalid method. Use 'get' or 'post'.")
        sys.exit(1)