import requests 
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

visited = set()
MAX_PAGES = 20
pages_scanned = 0

def banner():
    return """
    <div style="text-align:center; color:#1a73e8; font-size:32px; margin-bottom:20px;">
    Web Application Vulnerability Scanner
    </div>
    """

def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = url + "?q=" + payload
    try:
        start = time.time()
        res = requests.get(test_url, timeout=5)
        duration = round(time.time() - start, 2)
        if payload in res.text:
            return f"<span style='color:red'>[!] Possible XSS at: {test_url} (took {duration}s)</span><br>"
        else:
            return f"<span style='color:green'>[+] No XSS at: {url} (took {duration}s)</span><br>"
    except Exception as e:
        return f"<span style='color:orange'>[!] XSS check error: {str(e)}</span><br>"

def check_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = url + "?id=" + payload
    try:
        start = time.time()
        res = requests.get(test_url, timeout=5)
        duration = round(time.time() - start, 2)
        if "sql" in res.text.lower() or "mysql" in res.text.lower():
            return f"<span style='color:red'>[!] Possible SQLi at: {test_url} (took {duration}s)</span><br>"
        else:
            return f"<span style='color:green'>[+] No SQLi at: {url} (took {duration}s)</span><br>"
    except Exception as e:
        return f"<span style='color:orange'>[!] SQLi check error: {str(e)}</span><br>"

def crawl_and_scan(base_url):
    global pages_scanned
    results = ""

    if pages_scanned >= MAX_PAGES:
        results += f"<span style='color:cyan'>[i] Reached max scan limit of {MAX_PAGES} pages. Stopping crawl.</span><br>"
        return results

    if base_url in visited:
        return results
    visited.add(base_url)
    pages_scanned += 1

    results += f"<span style='color:cyan'>[*] Crawling ({pages_scanned}/{MAX_PAGES}): {base_url}</span><br>"

    try:
        start = time.time()
        res = requests.get(base_url, timeout=5)
        duration = round(time.time() - start, 2)
        results += f"<span style='color:magenta'>[i] Page loaded in {duration}s</span><br>"

        soup = BeautifulSoup(res.text, "html.parser")

        # Run vulnerability checks
        results += check_xss(base_url)
        results += check_sql_injection(base_url)

        # Extract all links
        for link in soup.find_all("a", href=True):
            full_url = urljoin(base_url, link['href'])
            if urlparse(base_url).netloc in full_url:
                results += crawl_and_scan(full_url)

    except Exception as e:
        results += f"<span style='color:orange'>[!] Crawl error: {str(e)}</span><br>"

    return results

if __name__ == "__main__":
    print(banner())
    target = input("Enter target URL: ")
    print(crawl_and_scan(target))
