import os
import math
import socket
import re
from urllib.parse import urlparse
import pandas as pd
import numpy as np
from multiprocessing import Pool, cpu_count
from functools import partial

# Ensure output directory exists
os.makedirs("data/processed", exist_ok=True)

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'bank', 'account', 
    'confirm', 'signin', 'authenticate', 'service', 'wallet', 'free', 'bonus'
]

IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

def calculate_entropy(text: str) -> float:
    """Computes Shannon entropy to measure randomness in the domain/path."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_single_url_features(row):
    url, label = row
    if not isinstance(url, str) or not url.strip():
        return None

    try:
        # Standardize URL structure
        if not url.startswith(('http://', 'https://')):
            url_to_parse = 'http://' + url
        else:
            url_to_parse = url

        parsed = urlparse(url_to_parse)
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        path = parsed.path

        # 1. Lexical Features
        url_len = len(url)
        domain_len = len(domain)
        path_len = len(path)
        
        num_dots = url.count('.')
        num_hyphens = url.count('-')
        num_underscores = url.count('_')
        num_slashes = url.count('/')
        num_question_marks = url.count('?')
        num_equals = url.count('=')
        num_at = url.count('@')
        num_digits = sum(c.isdigit() for c in url)
        
        # 2. Structural & Heuristic Features
        has_ip = 1 if IP_REGEX.match(domain) else 0
        has_at_symbol = 1 if num_at > 0 else 0
        has_double_slash_redirect = 1 if '//' in path else 0
        has_suspicious_keyword = 1 if any(word in url.lower() for word in SUSPICIOUS_KEYWORDS) else 0
        is_https = 1 if parsed.scheme == 'https' else 0
        subdomain_count = len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0

        # 3. Entropy
        domain_entropy = calculate_entropy(domain)
        url_entropy = calculate_entropy(url)

        return {
            'url_length': url_len,
            'domain_length': domain_len,
            'path_length': path_len,
            'num_dots': num_dots,
            'num_hyphens': num_hyphens,
            'num_underscores': num_underscores,
            'num_slashes': num_slashes,
            'num_question_marks': num_question_marks,
            'num_equals': num_equals,
            'num_at': num_at,
            'num_digits': num_digits,
            'has_ip': has_ip,
            'has_at_symbol': has_at_symbol,
            'has_double_slash_redirect': has_double_slash_redirect,
            'has_suspicious_keyword': has_suspicious_keyword,
            'is_https': is_https,
            'subdomain_count': subdomain_count,
            'domain_entropy': domain_entropy,
            'url_entropy': url_entropy,
            'label': int(label)
        }
    except Exception:
        return None

def process_dataset(input_file="data/raw/initial_dataset.csv", output_file="data/processed/features.csv"):
    print(f"Loading raw dataset from {input_file}...")
    df = pd.read_csv(input_file)
    
    records = list(zip(df['url'], df['label']))
    total_records = len(records)
    num_workers = max(1, cpu_count() - 1)
    
    print(f"Extracting features across {num_workers} CPU cores for {total_records} records...")
    
    with Pool(processes=num_workers) as pool:
        # Process in chunks for high throughput
        results = pool.map(extract_single_url_features, records, chunksize=1000)
    
    # Filter out failed parses
    valid_results = [r for r in results if r is not None]
    
    feature_df = pd.DataFrame(valid_results)
    feature_df.to_csv(output_file, index=False)
    
    print(f"\nFeature extraction complete!")
    print(f"Saved {len(feature_df)} rows with {feature_df.shape[1] - 1} engineered features to '{output_file}'.")

if __name__ == "__main__":
    process_dataset()