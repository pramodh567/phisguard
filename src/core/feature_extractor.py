import math
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract

# ----------------- CONSTANTS (Top Phishing Targets) ----------------- #
# Representing the highest-value targets for impersonation across industries
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

# ----------------- HELPER ----------------- #
def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    length = len(text)
    char_counts = {c: text.count(c) for c in set(text)}
    return round(-sum((count / length) * math.log2(count / length) for count in char_counts.values()), 4)

# ----------------- TIER 1: FAST MATH (< 5ms) ----------------- #
def extract_tier1_features(url: str) -> dict:
    url_to_parse = url if url.startswith(('http://', 'https://')) else 'http://' + url
    parsed = urlparse(url_to_parse)
    domain = parsed.netloc.split(':')[0].lower()
    path = parsed.path.lower()
    url_lower = url.lower()
    ext = tldextract.extract(url_to_parse)
    
    # 1. Abnormal URL Logic
    is_ip = 1 if IP_REGEX.match(domain) else 0
    has_spoofed_path = 1 if SPOOFED_HOST_REGEX.search(path) else 0
    abnormal_url = 1 if (is_ip or has_spoofed_path) else 0

    # 2. Brands & Keywords Logic
    brand_mentions = sum(1 for b in TARGET_BRANDS if b in url_lower)
    exact_brand_spoof = 0
    for b in TARGET_BRANDS:
        # If the brand is in the subdomain but the root domain is NOT the brand (e.g. paypal.attacker.com)
        if b in url_lower and b in ext.subdomain and ext.domain != b:
            exact_brand_spoof = 1

    tokens = re.split(r'[/_.\-?=&]', url_lower)
    urgency_words = sum(1 for t in tokens if t in URGENCY_KEYWORDS)
    security_words = sum(1 for t in tokens if t in SECURITY_KEYWORDS)

    # 3. Structural Logic
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

# ----------------- TIER 2: LIVE NETWORK (200 - 800ms) ----------------- #
def extract_tier2_features(url: str, timeout: float = 2.0) -> dict:
    url_to_fetch = url if url.startswith(('http://', 'https://')) else 'http://' + url
    
    features = {
        'web_unique_domains': 0,
        'web_security_score': 0.0,
        'web_hsts': 0,
        'web_xframe': 0,
        'web_http_status': 0,
        'web_is_live': 0
    }
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url_to_fetch, timeout=timeout, headers=headers, allow_redirects=True)
        
        # HTTP Status & Liveness
        features['web_is_live'] = 1
        features['web_http_status'] = response.status_code
        
        # Security Headers
        if 'Strict-Transport-Security' in response.headers:
            features['web_hsts'] = 1
        if 'X-Frame-Options' in response.headers or 'Content-Security-Policy' in response.headers:
            features['web_xframe'] = 1
            
        # Composite Security Score (0.0 to 1.0)
        score = 0.0
        if response.url.startswith('https'): score += 0.4
        if features['web_hsts']: score += 0.3
        if features['web_xframe']: score += 0.3
        features['web_security_score'] = round(score, 2)
        
        # HTML Parsing: Safely count unique external domains linked in the page
        soup = BeautifulSoup(response.text, 'html.parser')
        unique_domains = set()
        for link in soup.find_all('a', href=True):
            href_val = str(link.get('href', ''))
            href_domain = tldextract.extract(href_val).domain
            if href_domain:
                unique_domains.add(href_domain)
        features['web_unique_domains'] = len(unique_domains)
        
    except requests.RequestException:
        pass
        
    return features

if __name__ == "__main__":
    import json
    
    test_url = input("Enter a URL to test (e.g., https://google.com): ").strip()
    
    print(f"\n--- Extracting Tier 1 (Math) Features ---")
    t1_features = extract_tier1_features(test_url)
    print(json.dumps(t1_features, indent=4))
    
    print(f"\n--- Extracting Tier 2 (Network) Features ---")
    print("(Fetching live data, please wait up to 2 seconds...)")
    t2_features = extract_tier2_features(test_url)
    print(json.dumps(t2_features, indent=4))