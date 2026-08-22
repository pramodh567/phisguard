import math
import re
import socket
import requests
import tldextract
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ----------------- CONSTANTS ----------------- #
TARGET_BRANDS = [
    'microsoft', 'apple', 'paypal', 'facebook', 'google', 'netflix', 'amazon', 
    'instagram', 'chase', 'wellsfargo', 'binance', 'coinbase', 'icloud', 
    'office365', 'outlook', 'roblox', 'steam', 'tiktok', 'shopee', 'adobe', 
    'whatsapp', 'linkedin', 'bankofamerica', 'citibank', 'americanexpress', 
    'discord', 'dropbox', 'dhl', 'fedex', 'ups', 'usps', 'royalmail', 'evri'
]

URGENCY_KEYWORDS = {'urgent', 'immediate', 'action', 'suspended', 'limited', 'expire', 'danger', 'alert', 'penalty'}
SECURITY_KEYWORDS = {'verify', 'secure', 'login', 'update', 'account', 'banking', 'confirm', 'auth', 'recover', 'wallet'}
SUSPICIOUS_EXTENSIONS = ('.exe', '.apk', '.bat', '.scr', '.vbs', '.js', '.zip', '.rar', '.iso', '.ps1', '.sh', '.msi', '.bin')
IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
SPOOFED_HOST_REGEX = re.compile(r'(https?://)?([a-zA-Z0-9-]+\.)+(com|net|org|edu|gov|io|xyz|top)', re.IGNORECASE)

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    length = len(text)
    char_counts = {c: text.count(c) for c in set(text)}
    return round(-sum((count / length) * math.log2(count / length) for count in char_counts.values()), 4)

# ----------------- TIER 1: FAST MATH (< 1ms) ----------------- #
def extract_tier1_features(url: str) -> dict:
    url_to_parse = url if url.startswith(('http://', 'https://')) else 'http://' + url
    parsed = urlparse(url_to_parse)
    domain = parsed.netloc.split(':')[0].lower()
    path = parsed.path.lower()
    url_lower = url.lower()
    ext = tldextract.extract(url_to_parse)
    
    is_ip = 1 if IP_REGEX.match(domain) else 0
    has_spoofed_path = 1 if SPOOFED_HOST_REGEX.search(path) else 0
    abnormal_url = 1 if (is_ip or has_spoofed_path) else 0

    brand_mentions = sum(1 for b in TARGET_BRANDS if b in url_lower)
    exact_brand_spoof = 0
    for b in TARGET_BRANDS:
        if b in url_lower and b in ext.subdomain and ext.domain != b:
            exact_brand_spoof = 1

    tokens = re.split(r'[/_.\-?=&]', url_lower)
    urgency_words = sum(1 for t in tokens if t in URGENCY_KEYWORDS)
    security_words = sum(1 for t in tokens if t in SECURITY_KEYWORDS)

    subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
    suspicious_ext = 1 if any(path.endswith(e) for e in SUSPICIOUS_EXTENSIONS) else 0

    return {
        'abnormal_url': abnormal_url,
        'path_len': len(path),
        'url_len': len(url),
        'domain_len': len(domain),
        'url_entropy': calculate_entropy(url),
        'subdomain_count': subdomain_count,
        'suspicious_extension': suspicious_ext,
        'phish_brand_mentions': brand_mentions,
        'phish_adv_exact_brand_match': exact_brand_spoof,
        'phish_urgency_words': urgency_words,
        'phish_security_words': security_words,
        'phish_adv_number_count': sum(c.isdigit() for c in url),
        'phish_adv_hyphen_count': url.count('-'),
        'path_underscore_count': path.count('_')
    }

# ----------------- PARALLEL HELPER TASKS ----------------- #
def _check_host_resolution(host: str) -> bool:
    """Uses native OS C-level gethostbyname (fast & cached)."""
    try:
        socket.setdefaulttimeout(0.2)
        socket.gethostbyname(host)
        return True
    except Exception:
        return False

def _fetch_headers_fast(url: str, timeout: float = 0.25) -> dict:
    """Uses HTTP HEAD without following redirects for maximum speed."""
    res = {'status': 0, 'hsts': 0, 'xframe': 0, 'is_https': 0}
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        # Disable allow_redirects to prevent multi-hop CDN latency delays
        r = requests.head(url, timeout=timeout, headers=headers, allow_redirects=False)
        res['status'] = r.status_code
        if 'Strict-Transport-Security' in r.headers: res['hsts'] = 1
        if 'X-Frame-Options' in r.headers or 'Content-Security-Policy' in r.headers: res['xframe'] = 1
        if url.startswith('https'): res['is_https'] = 1
    except Exception:
        pass
    return res

# ----------------- TIER 2: CONCURRENT NETWORK RESOLUTION ----------------- #
def extract_tier2_features(url: str, timeout: float = 0.35) -> dict:
    url_to_fetch = url if url.startswith(('http://', 'https://')) else 'http://' + url
    parsed = urlparse(url_to_fetch)
    host = parsed.netloc.split(':')[0]

    features = {
        'web_unique_domains': 0,
        'web_security_score': 0.0,
        'web_hsts': 0,
        'web_xframe': 0,
        'web_http_status': 0,
        'web_is_live': 0
    }
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_dns = executor.submit(_check_host_resolution, host)
        future_http = executor.submit(_fetch_headers_fast, url_to_fetch, timeout)
        
        is_live = future_dns.result()
        http_data = future_http.result()

    if is_live:
        features['web_is_live'] = 1

    features['web_http_status'] = http_data['status']
    features['web_hsts'] = http_data['hsts']
    features['web_xframe'] = http_data['xframe']
    
    # Calculate Composite Security Score
    score = 0.0
    if http_data['is_https']: score += 0.3
    if http_data['hsts']: score += 0.35
    if http_data['xframe']: score += 0.35
    features['web_security_score'] = round(min(1.0, score), 2)
    
    return features