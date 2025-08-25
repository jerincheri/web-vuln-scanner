import os

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0 Safari/537.36 WebVulnScanner/3.0"
)

REQUEST_TIMEOUT = 12
MAX_PAGES = 300
MAX_WORKERS = 12
RATE_LIMIT_DELAY = 0.08  # seconds between network actions

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

DEFAULT_HEADERS = {"User-Agent": USER_AGENT}
DEFAULT_COOKIES = {}
VERIFY_TLS = True

# Security header expectations (severity hint)
SECURITY_HEADERS = {
    "Content-Security-Policy": "Low",
    "X-Content-Type-Options": "Low",
    "X-Frame-Options": "Medium",
    "Referrer-Policy": "Low",
    "Strict-Transport-Security": "High",
}

CSRF_TOKEN_HINTS = ["csrf", "xsrf", "token", "authenticity_token", "__requestverificationtoken"]

# Blind SQLi timing threshold (seconds)
TIME_THRESHOLD = 2.5

# Stored XSS follow-up limits
STORED_XSS_RECRAWL_PAGES = 80
