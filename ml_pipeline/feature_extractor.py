"""
SafeLink Feature Extractor — 36 URL features (35 URL-only + domain_age_days placeholder).
This is the feature contract between Python training and Kotlin inference.
Column order MUST match exactly what trainer.py fits the scaler on.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict


# --- Constants ---
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'info', 'biz', 'tk', 'ml',
    'ga', 'cf', 'gq', 'click', 'link', 'download', 'win', 'loan', 'work',
    'review', 'stream', 'gdn', 'racing', 'accountant', 'science', 'date',
    'faith', 'party', 'trade', 'webcam', 'cricket', 'bid', 'rocks',
}

TRUSTED_TLDS = {'gov', 'edu', 'mil', 'ac'}

PHISHING_KEYWORDS = {
    'login', 'signin', 'account', 'update', 'secure', 'verify', 'banking',
    'payment', 'password', 'credential', 'confirm', 'suspend', 'unlock',
    'alert', 'warning', 'urgent', 'limited', 'expire', 'reward', 'prize',
    'winner', 'free', 'bonus', 'offer', 'click', 'support', 'help',
    'service', 'customer', 'billing', 'invoice', 'refund', 'upgrade',
}

BRAND_KEYWORDS = {
    # Sri Lankan
    'hnb', 'sampath', 'boc', 'commercial', 'dialog', 'mobitel', 'slt',
    'peoples', 'bank', 'lankabell',
    # Global
    'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
    'netflix', 'instagram', 'whatsapp', 'dhl', 'ebay', 'linkedin',
    'twitter', 'youtube', 'dropbox', 'adobe', 'office', 'outlook',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'tiny.cc', 'qr.ae', 'bc.vc', 'su.pr',
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def _count_special(s: str) -> int:
    return sum(1 for c in s if not c.isalnum() and c not in ('/', '.', '-', '_'))


def extract_features(url: str) -> Dict[str, float]:
    """
    Extract all 36 features from a URL.
    Feature #36 (domain_age_days) is always set to -1.0 here — filled at inference
    time by RDAP lookup in Kotlin.

    Returns a dict with keys in the exact column order expected by the scaler.
    """
    url = url.strip()
    url_lower = url.lower()

    # --- Parse URL ---
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        scheme = parsed.scheme or 'http'
        netloc = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        fragment = parsed.fragment or ''
    except Exception:
        parsed = None
        scheme = 'http'
        netloc = ''
        path = ''
        query = ''
        fragment = ''

    # --- Host / domain decomposition ---
    host = netloc.split(':')[0].lower() if netloc else ''
    # Remove www. prefix
    domain_no_www = re.sub(r'^www\.', '', host)
    parts = domain_no_www.split('.')
    tld = parts[-1] if len(parts) > 1 else ''
    sld = parts[-2] if len(parts) > 1 else domain_no_www
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

    # Detect IP address host
    is_ip = 0
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        pass

    full_url_len = len(url)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)

    # --- Feature 1: url_length ---
    f1 = float(full_url_len)

    # --- Feature 2: domain_length ---
    f2 = float(host_len)

    # --- Feature 3: path_length ---
    f3 = float(path_len)

    # --- Feature 4: query_length ---
    f4 = float(query_len)

    # --- Feature 5: num_dots ---
    f5 = float(url.count('.'))

    # --- Feature 6: num_hyphens (domain only — hyphens in path are common in legit URLs) ---
    f6 = float(host.count('-'))

    # --- Feature 7: num_underscores ---
    f7 = float(url.count('_'))

    # --- Feature 8: num_slashes ---
    f8 = float(url.count('/'))

    # --- Feature 9: num_at_signs ---
    f9 = float(url.count('@'))

    # --- Feature 10: num_question_marks ---
    f10 = float(url.count('?'))

    # --- Feature 11: num_equals ---
    f11 = float(url.count('='))

    # --- Feature 12: num_ampersands ---
    f12 = float(url.count('&'))

    # --- Feature 13: num_percent_signs (URL encoding) ---
    f13 = float(url.count('%'))

    # --- Feature 14: num_digits (in full URL) ---
    f14 = float(sum(c.isdigit() for c in url))

    # --- Feature 15: digit_ratio ---
    f15 = _digit_ratio(url)

    # --- Feature 16: url_entropy ---
    f16 = _entropy(url)

    # --- Feature 17: domain_entropy ---
    f17 = _entropy(host)

    # --- Feature 18: is_https (1 if https, else 0) ---
    f18 = 1.0 if scheme == 'https' else 0.0

    # --- Feature 19: is_ip_address ---
    f19 = float(is_ip)

    # --- Feature 20: num_subdomains ---
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    f20 = float(subdomain_count)

    # --- Feature 21: has_suspicious_tld ---
    f21 = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # --- Feature 22: has_trusted_tld ---
    f22 = 1.0 if tld in TRUSTED_TLDS else 0.0

    # --- Feature 23: phishing_keyword_count ---
    all_text = url_lower.replace('/', ' ').replace('-', ' ').replace('_', ' ').replace('.', ' ')
    words = set(re.split(r'\W+', all_text))
    f23 = float(len(PHISHING_KEYWORDS & words))

    # --- Feature 24: brand_keyword_count ---
    f24 = float(len(BRAND_KEYWORDS & words))

    # --- Feature 25: has_url_shortener ---
    f25 = 1.0 if any(s in host for s in URL_SHORTENERS) else 0.0

    # --- Feature 26: num_query_params ---
    if query:
        try:
            params = parse_qs(query)
            f26 = float(len(params))
        except Exception:
            f26 = 0.0
    else:
        f26 = 0.0

    # --- Feature 27: has_port_in_url ---
    f27 = 1.0 if (netloc and ':' in netloc.split('@')[-1]) else 0.0

    # --- Feature 28: has_double_slash_in_path ---
    f28 = 1.0 if '//' in path else 0.0

    # --- Feature 29: subdomain_length ---
    f29 = float(len(subdomain))

    # --- Feature 30: sld_length (second-level domain) ---
    f30 = float(len(sld))

    # --- Feature 31: num_special_chars_in_domain ---
    f31 = float(_count_special(host))

    # --- Feature 32: path_entropy ---
    f32 = _entropy(path)

    # --- Feature 33: has_hex_encoding ---
    f33 = 1.0 if re.search(r'%[0-9a-fA-F]{2}', url) else 0.0

    # --- Feature 34: consecutive_digits_in_domain ---
    digit_runs = re.findall(r'\d+', host)
    f34 = float(max((len(r) for r in digit_runs), default=0))

    # --- Feature 35: has_tld_in_path (TLD appearing inside path — common phishing trick) ---
    tld_in_path = bool(re.search(
        r'\.(com|net|org|gov|edu|bank|secure|login)\b', path, re.IGNORECASE
    ))
    f35 = 1.0 if tld_in_path else 0.0

    # --- Feature 36: domain_age_days (placeholder — filled by RDAP at inference time) ---
    f36 = -1.0

    return {
        'url_length': f1,
        'domain_length': f2,
        'path_length': f3,
        'query_length': f4,
        'num_dots': f5,
        'num_hyphens': f6,
        'num_underscores': f7,
        'num_slashes': f8,
        'num_at_signs': f9,
        'num_question_marks': f10,
        'num_equals': f11,
        'num_ampersands': f12,
        'num_percent_signs': f13,
        'num_digits': f14,
        'digit_ratio': f15,
        'url_entropy': f16,
        'domain_entropy': f17,
        'is_https': f18,
        'is_ip_address': f19,
        'num_subdomains': f20,
        'has_suspicious_tld': f21,
        'has_trusted_tld': f22,
        'phishing_keyword_count': f23,
        'brand_keyword_count': f24,
        'has_url_shortener': f25,
        'num_query_params': f26,
        'has_port_in_url': f27,
        'has_double_slash_in_path': f28,
        'subdomain_length': f29,
        'sld_length': f30,
        'num_special_chars_in_domain': f31,
        'path_entropy': f32,
        'has_hex_encoding': f33,
        'consecutive_digits_in_domain': f34,
        'has_tld_in_path': f35,
        'domain_age_days': f36,
    }


# Ordered list of feature column names — MUST match Kotlin FeatureExtractor.kt exactly
FEATURE_COLUMNS = [
    'url_length', 'domain_length', 'path_length', 'query_length',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_at_signs', 'num_question_marks', 'num_equals', 'num_ampersands',
    'num_percent_signs', 'num_digits', 'digit_ratio', 'url_entropy',
    'domain_entropy', 'is_https', 'is_ip_address', 'num_subdomains',
    'has_suspicious_tld', 'has_trusted_tld', 'phishing_keyword_count',
    'brand_keyword_count', 'has_url_shortener', 'num_query_params',
    'has_port_in_url', 'has_double_slash_in_path', 'subdomain_length',
    'sld_length', 'num_special_chars_in_domain', 'path_entropy',
    'has_hex_encoding', 'consecutive_digits_in_domain', 'has_tld_in_path',
    'domain_age_days',
]

assert len(FEATURE_COLUMNS) == 36, f"Expected 36 features, got {len(FEATURE_COLUMNS)}"


def extract_feature_vector(url: str) -> list:
    """Returns features as an ordered list matching FEATURE_COLUMNS."""
    d = extract_features(url)
    return [d[col] for col in FEATURE_COLUMNS]


if __name__ == '__main__':
    test_urls = [
        'https://www.google.com/search?q=python',
        'http://paypal-secure-login.xyz/verify?account=12345',
        'http://192.168.1.1/admin',
        'https://hnb.lk/personal/internet-banking',
        'http://bit.ly/3xAbc12',
        'https://www.amazon.com/dp/B08N5WRWNW',
    ]
    for url in test_urls:
        vec = extract_feature_vector(url)
        print(f"\n{url}")
        for name, val in zip(FEATURE_COLUMNS, vec):
            if val != 0.0:
                print(f"  {name}: {val}")
