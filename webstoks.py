import requests

import requests
import urllib3
import socket
import ssl
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init

# Init
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Config
TARGET_URL = input("clone")
DOMAIN = urlparse(TARGET_URL).netloc
PORT = 443 if TARGET_URL.startswith("https") else 80

COMMON_PATHS = ["admin", "login", "api/v1", "config", ".git", "dashboard", "test.php"]
FUZZ_STRINGS = ["../", "%2e%2e%2f", ";cat /etc/passwd", "<script>alert(1)</script>"]
SUBDOMAINS = ["mail", "dev", "test", "ftp", "api"]
HEADERS_TO_CHECK = [
    "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security",
    "Content-Security-Policy", "X-Content-Type-Options"
]

vulnerabilities = []

# TLS/SSL Check
def check_ssl_version(domain, port):
    print(f"{Fore.CYAN}[*] Checking SSL/TLS version...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                print(f"{Fore.GREEN}[SSL] Protocol: {ssock.version()}")
    except Exception as e:
        print(f"{Fore.RED}[SSL] Error: {e}")
        vulnerabilities.append("SSL handshake failed or insecure version")

# HTTP Version
def check_http_version(url):
    print(f"{Fore.CYAN}[*] Checking HTTP version...")
    try:
        response = requests.get(url, verify=False, timeout=5)
        version = response.raw.version
        version_str = {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2.0"}.get(version, f"Unknown ({version})")
        print(f"{Fore.GREEN}[HTTP] Version: {version_str}")
    except Exception as e:
        print(f"{Fore.RED}[HTTP] Error: {e}")
        vulnerabilities.append("Unable to determine HTTP version")

# DNS Poisoning Check (Basic)
def check_dns_poisoning(domain):
    print(f"{Fore.CYAN}[*] Checking for DNS poisoning (public vs local IP)...")
    try:
        local_ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[DNS] Local IP: {local_ip}")
        # For actual public DNS comparison, use an external resolver (or API)
        # Placeholder here
    except Exception as e:
        print(f"{Fore.RED}[DNS] Resolution error: {e}")
        vulnerabilities.append("Potential DNS resolution issue")

# Fuzzing
def fuzz_paths(base_url, fuzz_list):
    print(f"{Fore.CYAN}[*] Fuzzing for injection and traversal vulnerabilities...")
    for fuzz in fuzz_list:
        url = base_url + fuzz
        try:
            res = requests.get(url, timeout=5, verify=False)
            if res.status_code == 200:
                print(f"{Fore.YELLOW}[FUZZ FOUND] {url}")
                vulnerabilities.append(f"Fuzzing found accessible path: {url}")
        except Exception:
            continue

# Subdomain Scan
def scan_subdomains(domain, subdomains):
    print(f"{Fore.CYAN}[*] Scanning subdomains...")
    for sub in subdomains:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            print(f"{Fore.GREEN}[FOUND] {full} -> {ip}")
            vulnerabilities.append(f"Exposed subdomain: {full}")
        except:
            continue

# Headers
def check_headers(url):
    print(f"{Fore.CYAN}[*] Checking headers...")
    try:
        res = requests.get(url, verify=False)
        for header in HEADERS_TO_CHECK:
            if header not in res.headers:
                print(f"{Fore.RED}[MISSING] {header}")
                vulnerabilities.append(f"Missing security header: {header}")
            else:
                print(f"{Fore.GREEN}[OK] {header}")
    except Exception as e:
        print(f"{Fore.RED}[HEADERS] Error: {e}")

# Cookies
def check_cookies(url):
    print(f"{Fore.CYAN}[*] Checking cookies...")
    try:
        res = requests.get(url, verify=False)
        for cookie in res.cookies:
            if not cookie.secure or 'httponly' not in cookie._rest:
                print(f"{Fore.RED}[VULN] Cookie {cookie.name} missing flags")
                vulnerabilities.append(f"Insecure cookie: {cookie.name}")
    except Exception as e:
        print(f"{Fore.RED}[COOKIES] Error: {e}")

# robots.txt
def check_robots(url):
    robots_url = urljoin(url, "robots.txt")
    print(f"{Fore.CYAN}[*] Checking robots.txt...")
    try:
        res = requests.get(robots_url, verify=False)
        if res.status_code == 200 and "Disallow" in res.text:
            print(f"{Fore.YELLOW}[robots.txt] Disallows found")
            vulnerabilities.append("robots.txt disallows sensitive paths")
    except:
        pass

# Path Scanner
def scan_paths(base_url, paths):
    print(f"{Fore.CYAN}[*] Scanning common paths...")
    for path in paths:
        full_url = urljoin(base_url, path)
        try:
            res = requests.get(full_url, verify=False)
            if res.status_code in [200, 403, 401]:
                print(f"{Fore.YELLOW}[{res.status_code}] {full_url}")
                vulnerabilities.append(f"Interesting path ({res.status_code}): {full_url}")
        except:
            continue

# Summary
def summary():
    print(f"\n{Fore.CYAN}[*] Vulnerability Report:")
    if vulnerabilities:
        for v in vulnerabilities:
            print(f"{Fore.RED}- {v}")
    else:
        print(f"{Fore.GREEN}No major issues found.")

# Run All Checks
if __name__ == "__main__":
    print(f"{Fore.BLUE}=== Advanced Web Vulnerability Scanner ===")
    check_ssl_version(DOMAIN, PORT)
    check_http_version(TARGET_URL)
    check_dns_poisoning(DOMAIN)
    check_robots(TARGET_URL)
    scan_paths(TARGET_URL, COMMON_PATHS)
    fuzz_paths(TARGET_URL, FUZZ_STRINGS)
    check_headers(TARGET_URL)
    check_cookies(TARGET_URL)
    scan_subdomains(DOMAIN, SUBDOMAINS)
    summary()
