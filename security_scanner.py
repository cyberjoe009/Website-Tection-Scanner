import argparse
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.visited_urls = set()
        self.vulnerabilities = []
        self.domain = urlparse(target_url).netloc

    def is_same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def spider(self):
        queue = [self.target_url]
        while queue:
            current_url = queue.pop(0)
            if current_url in self.visited_urls:
                continue
            
            try:
                response = self.session.get(current_url, timeout=5)
                self.visited_urls.add(current_url)
                print(f"Scanning: {current_url}")

                # Parse HTML and extract links
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    url = urljoin(current_url, link['href'])
                    if url not in self.visited_urls and self.is_same_domain(url):
                        queue.append(url)

                # Extract forms for testing
                forms = soup.find_all('form')
                for form in forms:
                    form_details = self.parse_form(form)
                    self.test_xss(form_details, current_url)

            except Exception as e:
                print(f"Error scanning {current_url}: {e}")

    def parse_form(self, form):
        details = {}
        details['action'] = form.attrs.get('action', '').lower()
        details['method'] = form.attrs.get('method', 'get').lower()
        details['inputs'] = []
        for input_tag in form.find_all('input'):
            input_details = {
                'type': input_tag.attrs.get('type', 'text'),
                'name': input_tag.attrs.get('name')
            }
            details['inputs'].append(input_details)
        return details

    def test_sql_injection(self, url):
        payloads = [
            "' OR 1=1 --",
            "' OR '1'='1",
            "%27%20OR%201=1--"
        ]
        for payload in payloads:
            modified_url = f"{url}{payload}"
            try:
                response = self.session.get(modified_url, timeout=5)
                if "error in your SQL syntax" in response.text.lower():
                    self.vulnerabilities.append({
                        'url': url,
                        'type': 'SQL Injection',
                        'payload': payload
                    })
            except Exception as e:
                print(f"Error testing SQLi on {url}: {e}")

    def test_xss(self, form_details, url):
        xss_payload = "<script>alert('XSS')</script>"
        target_url = urljoin(url, form_details['action'])
        data = {}
        for input in form_details['inputs']:
            if input['type'] == 'hidden':
                data[input['name']] = input.get('value', '')
            else:
                data[input['name']] = xss_payload

        try:
            if form_details['method'] == 'post':
                response = self.session.post(target_url, data=data, timeout=5)
            else:
                response = self.session.get(target_url, params=data, timeout=5)
            
            if xss_payload in response.text:
                self.vulnerabilities.append({
                    'url': target_url,
                    'type': 'XSS',
                    'payload': xss_payload
                })
        except Exception as e:
            print(f"Error testing XSS on {url}: {e}")

    def test_directory_traversal(self, url):
        payloads = [
            "../../../../etc/passwd",
            "%2e%2e%2fetc%2fpasswd"
        ]
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "root:" in response.text:
                    self.vulnerabilities.append({
                        'url': test_url,
                        'type': 'Directory Traversal',
                        'payload': payload
                    })
            except Exception as e:
                print(f"Error testing directory traversal on {url}: {e}")

    def scan(self):
        self.spider()
        for url in self.visited_urls:
            self.test_sql_injection(url)
            self.test_directory_traversal(url)
        
    def generate_report(self, filename="security_report.txt"):
        with open(filename, 'w') as f:
            f.write("Web Security Scan Report\n")
            f.write("========================\n\n")
            f.write(f"Target URL: {self.target_url}\n")
            f.write(f"Scanned Pages: {len(self.visited_urls)}\n\n")
            
            if not self.vulnerabilities:
                f.write("No vulnerabilities found!\n")
                return
            
            f.write("Vulnerabilities Found:\n")
            f.write("----------------------\n")
            for vuln in self.vulnerabilities:
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Payload: {vuln['payload']}\n\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Web Security Scanner")
    parser.add_argument("target", help="Target URL to scan")
    args = parser.parse_args()

    scanner = SecurityScanner(args.target)
    print(f"Starting security scan for {args.target}")
    scanner.scan()
    scanner.generate_report()
    print("Scan completed. Report generated as security_report.txt"
