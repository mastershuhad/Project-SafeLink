"""
SafeLink Feature Extractor v5.1 — 22 URL features (PRD v5.1).
n_features = 22 LOCKED — matches scaler_params.json and FeatureExtractor.kt exactly.
All features computed from URL string only — zero network requests.
"""

import re
import math
import ipaddress
import unicodedata
from urllib.parse import urlparse, parse_qs
from typing import Dict, List


# --- Constants ---

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'info', 'biz', 'tk', 'ml',
    'ga', 'cf', 'gq', 'click', 'link', 'download', 'win', 'loan', 'work',
    'review', 'stream', 'gdn', 'racing', 'accountant', 'science', 'date',
    'faith', 'party', 'trade', 'webcam', 'cricket', 'bid', 'rocks',
}

BRAND_KEYWORDS = {
    # Sri Lankan brands
    'hnb', 'sampath', 'boc', 'combank', 'commercial', 'dialog', 'mobitel', 'slt',
    'peoples', 'bank', 'lankabell',
    # Global brands
    'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
    'netflix', 'instagram', 'whatsapp', 'dhl', 'ebay', 'linkedin',
    'twitter', 'youtube', 'dropbox', 'adobe', 'office', 'outlook',
    # Apple services (targeted in typosquatting attacks)
    'icloud', 'appleid', 'itunes', 'appstore',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'tiny.cc', 'qr.ae', 'bc.vc', 'su.pr',
}

# Characters considered normal in URLs — anything outside this set counts as special
_NORMAL_URL_CHARS = frozenset(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '0123456789._-/:?=&#%+@~'
)

N_FEATURES = 22

# Ordered feature column names — index 0..21 MUST match FeatureExtractor.kt exactly
FEATURE_COLUMNS = [
    'host_length',         # 0   Length    — long hostnames signal brand spoofing
    'path_length',         # 1   Length    — long paths signal redirect chains
    'query_length',        # 2   Length    — long queries signal data harvesting
    'num_dots',            # 3   Count     — excessive dots signal subdomain stacking
    'num_hyphens',         # 4   Count     — hyphens in hostname signal brand spoofing
    'num_query_params',    # 5   Count     — many params signal tracking/redirect chains
    'num_subdomains',      # 6   Count     — deep subdomains bury the real domain
    'is_https',            # 7   Boolean   — HTTPS alone does not indicate safety
    'has_ip_host',         # 8   Boolean   — IP hostname is a strong malicious indicator
    'has_at_in_url',       # 9   Boolean   — @ tricks browser parsers for credential theft
    'has_homoglyphs',      # 10  Boolean   — Unicode lookalike chars for IDN homoglyph attacks
    'has_hex_encoding',    # 11  Boolean   — %xx encoding hides URL structure
    'is_url_shortener',    # 12  Boolean   — URL shorteners hide real destination
    'is_suspicious_tld',   # 13  Boolean   — .xyz .tk .ml heavily abused by phishing
    'digit_ratio',         # 14  Ratio     — high digits in hostname indicates DGA domain
    'special_char_ratio',  # 15  Ratio     — high special chars indicates obfuscation
    'host_entropy',        # 16  Entropy   — high entropy hostname indicates DGA
    'path_entropy',        # 17  Entropy   — random path indicates malware delivery
    'min_brand_distance',  # 18  Brand     — Levenshtein to nearest brand detects typosquatting
    'brand_in_subdomain',  # 19  Brand     — brand in subdomain is direct impersonation
    'url_depth',           # 20  Structure — deep paths indicate obfuscated delivery
    'has_punycode',        # 21  Obfuscation — xn-- prefix for IDN homoglyph attacks
]

assert len(FEATURE_COLUMNS) == N_FEATURES, f"Expected {N_FEATURES} features, got {len(FEATURE_COLUMNS)}"


# --- Internal helpers ---

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _levenshtein(a: str, b: str) -> int:
    """Standard dynamic-programming Levenshtein distance."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for c1 in a:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(b):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _min_brand_distance(host: str) -> float:
    """
    Minimum Levenshtein distance from any hostname token (split by . and -)
    to any brand keyword of length >= 4.
    Returns 10.0 when no meaningful tokens exist (safe signal).
    """
    tokens = [t for t in re.split(r'[.\-]', host.lower()) if len(t) >= 4]
    brands = [b for b in BRAND_KEYWORDS if len(b) >= 4]
    if not tokens or not brands:
        return 10.0
    return float(min(_levenshtein(t, b) for t in tokens for b in brands))


# --- Main extractor ---

def extract_features(url: str) -> Dict[str, float]:
    """Extract all 22 URL features. Returns dict with keys matching FEATURE_COLUMNS."""
    url = url.strip()

    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        scheme  = parsed.scheme or 'http'
        netloc  = parsed.netloc or ''
        path    = parsed.path or ''
        query   = parsed.query or ''
    except Exception:
        scheme, netloc, path, query = 'http', '', '', ''

    # Host decomposition
    host          = netloc.split(':')[0].lower() if netloc else ''
    domain_no_www = re.sub(r'^www\.', '', host)
    parts         = domain_no_www.split('.')
    tld           = parts[-1] if len(parts) > 1 else ''
    subdomain     = '.'.join(parts[:-2]) if len(parts) > 2 else ''

    # IP detection
    is_ip = 0
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        pass

    # --- Feature computation ---

    # 0: host_length
    f0 = float(len(host))

    # 1: path_length
    f1 = float(len(path))

    # 2: query_length
    f2 = float(len(query))

    # 3: num_dots (in full URL)
    f3 = float(url.count('.'))

    # 4: num_hyphens (in hostname only — hyphens in path are common in legit URLs)
    f4 = float(host.count('-'))

    # 5: num_query_params
    try:
        f5 = float(len(parse_qs(query))) if query else 0.0
    except Exception:
        f5 = 0.0

    # 6: num_subdomains
    f6 = float(len(subdomain.split('.')) if subdomain else 0)

    # 7: is_https
    f7 = 1.0 if scheme == 'https' else 0.0

    # 8: has_ip_host
    f8 = float(is_ip)

    # 9: has_at_in_url
    f9 = 1.0 if '@' in url else 0.0

    # 10: has_homoglyphs — non-ASCII Unicode letters in hostname (IDN homoglyph attacks)
    f10 = 1.0 if any(ord(c) > 127 and unicodedata.category(c).startswith('L') for c in host) else 0.0

    # 11: has_hex_encoding
    f11 = 1.0 if re.search(r'%[0-9a-fA-F]{2}', url) else 0.0

    # 12: is_url_shortener — exact domain match only (substring check causes false positives)
    f12 = 1.0 if any(host == s or host.endswith('.' + s) for s in URL_SHORTENERS) else 0.0

    # 13: is_suspicious_tld
    f13 = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 14: digit_ratio — digits in hostname / len(hostname) — high value signals DGA domain
    f14 = (sum(c.isdigit() for c in host) / len(host)) if host else 0.0

    # 15: special_char_ratio — chars outside normal URL charset / len(url)
    f15 = (sum(1 for c in url if c not in _NORMAL_URL_CHARS) / len(url)) if url else 0.0

    # 16: host_entropy — Shannon entropy of hostname
    f16 = _entropy(host)

    # 17: path_entropy — Shannon entropy of path
    f17 = _entropy(path)

    # 18: min_brand_distance — Levenshtein distance to nearest brand keyword
    f18 = _min_brand_distance(host)

    # 19: brand_in_subdomain — brand keyword found in subdomain tokens
    if subdomain:
        subdomain_tokens: set = set()
        for part in subdomain.lower().split('.'):
            if part:
                subdomain_tokens.add(part)
                if '-' in part:
                    subdomain_tokens.update(p for p in part.split('-') if p)
        f19 = 1.0 if BRAND_KEYWORDS & subdomain_tokens else 0.0
    else:
        f19 = 0.0

    # 20: url_depth — number of non-empty path segments
    f20 = float(len([seg for seg in path.split('/') if seg]))

    # 21: has_punycode — xn-- prefix indicates IDN encoding used in homoglyph attacks
    f21 = 1.0 if 'xn--' in host.lower() else 0.0

    return {
        'host_length':        f0,
        'path_length':        f1,
        'query_length':       f2,
        'num_dots':           f3,
        'num_hyphens':        f4,
        'num_query_params':   f5,
        'num_subdomains':     f6,
        'is_https':           f7,
        'has_ip_host':        f8,
        'has_at_in_url':      f9,
        'has_homoglyphs':     f10,
        'has_hex_encoding':   f11,
        'is_url_shortener':   f12,
        'is_suspicious_tld':  f13,
        'digit_ratio':        f14,
        'special_char_ratio': f15,
        'host_entropy':       f16,
        'path_entropy':       f17,
        'min_brand_distance': f18,
        'brand_in_subdomain': f19,
        'url_depth':          f20,
        'has_punycode':       f21,
    }


def extract_feature_vector(url: str) -> List[float]:
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
        'http://paypa1.com/login',
        'http://xn--pypal-4ve.com/',
        'http://paypal.secure-verify.evil.com/update',
    ]
    for url in test_urls:
        vec = extract_feature_vector(url)
        print(f"\n{url}")
        for name, val in zip(FEATURE_COLUMNS, vec):
            if val != 0.0:
                print(f"  {name}: {val:.4f}")
