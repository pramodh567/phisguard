import sys
import os
import time
import dns.resolver

# Dynamically append the project root relative to this script's location
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.feature_extractor import extract_tier1_features, extract_tier2_features

test_urls = [
    ("Safe Active Site", "https://github.com/torvalds/linux"),
    ("Safe Content Site", "https://en.wikipedia.org/wiki/Phishing"),
    ("Slow/Active Server", "http://br-icloud.com.br"),
    ("Dead Phishing Host", "http://login.microsoftonline.com.account-verify.xyz/auth"),
    ("Unresolved Domain", "http://paypal-security-account-verification-login.com/update")
]

print("==================== TIER 2 DNS & LATENCY BENCHMARK ====================")
for label, url in test_urls:
    t0 = time.time()
    t1_data = extract_tier1_features(url)
    t1_time = (time.time() - t0) * 1000

    t2_start = time.time()
    t2_data = extract_tier2_features(url)
    t2_time = (time.time() - t2_start) * 1000

    print(f"\n[Target]: {label} ({url})")
    print(f"  ├─ Tier 1 Math Time:    {t1_time:.2f} ms")
    print(f"  ├─ Tier 2 DNS+Net Time: {t2_time:.2f} ms")
    print(f"  └─ Tier 2 Features:     web_is_live={t2_data['web_is_live']}, status={t2_data['web_http_status']}, sec_score={t2_data['web_security_score']}")
print("\n=========================================================================")