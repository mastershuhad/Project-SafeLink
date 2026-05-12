"""
SafeLink Blocklist Builder — run ONCE during development.

Downloads:
  - URLhaus unified hosts file  (malware domains ~170K)
  - StevenBlack unified hosts   (ads/malware/phishing ~200K)

Deduplicates, removes known-safe whitelist domains, and writes:
  android/app/src/main/assets/blocklist.txt  (~170K domains, one per line)
  android/app/src/main/assets/whitelist.txt  (134 trusted domains)
"""

import os
import re
import urllib.request

ANDROID_ASSETS_DIR = '../SafeLink Android/app/src/main/assets'
BLOCKLIST_PATH = os.path.join(ANDROID_ASSETS_DIR, 'blocklist.txt')
WHITELIST_PATH = os.path.join(ANDROID_ASSETS_DIR, 'whitelist.txt')

# Source URLs
URLHAUS_HOSTS_URL = 'https://urlhaus.abuse.ch/downloads/hostfile/'
STEVENBLACK_URL = (
    'https://raw.githubusercontent.com/StevenBlack/hosts/a37afe9499df7a23fa4aee0c04cb2011a513bb3a/hosts'
)

# Static whitelist — 134 trusted domains (Sri Lankan + global)
STATIC_WHITELIST = sorted([
    # Sri Lankan government and education
    'gov.lk', 'moe.gov.lk', 'health.gov.lk', 'police.gov.lk',
    'elections.gov.lk', 'cbsl.gov.lk', 'ird.gov.lk', 'customs.gov.lk',
    'university.lk', 'cmb.ac.lk', 'pdn.ac.lk', 'uom.lk', 'kln.ac.lk',
    'sjp.ac.lk', 'ruh.ac.lk', 'esn.ac.lk',
    # Sri Lankan banks
    'hnb.lk', 'sampath.lk', 'boc.lk', 'combank.lk', 'peoples.lk',
    'ndbbank.lk', 'dfcc.lk', 'hattonbank.lk', 'nsblank.lk',
    'seylanbank.lk', 'unionb.lk', 'panasian.lk',
    # Sri Lankan telcos
    'dialog.lk', 'mobitel.lk', 'slt.lk', 'hutch.lk', 'airtel.lk',
    # Sri Lankan utilities & transport
    'ceb.lk', 'waterboard.lk', 'pickme.lk', 'uber.com', 'srilankan.com',
    # Sri Lankan commerce
    'ikman.lk', 'daraz.lk', 'keellssuper.com', 'cargillsce.com',
    # Sri Lankan news
    'dailymirror.lk', 'sundaytimes.lk', 'island.lk', 'adaderana.lk', 'newsfirst.lk', 'hirunews.lk',
    # Global search / social
    'forms.gle', 'google.com', 'google.lk', 'bing.com', 'yahoo.com', 'duckduckgo.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'youtube.com', 'youtu.be', 'reddit.com', 'whatsapp.com',
    # Global commerce & travel
    'amazon.com', 'ebay.com', 'paypal.com', 'stripe.com', 'booking.com',
    # Global tech
    'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
    'wikipedia.org', 'cloudflare.com', 'cloudflare-dns.com',
    # CDN and infrastructure
    'googleapis.com', 'gstatic.com', 'googlevideo.com',
    'akamaied.net', 'fastly.net', 'jsdelivr.net', 'unpkg.com',
    # Email providers
    'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
    # Streaming
    'netflix.com', 'spotify.com', 'twitch.tv', 'tiktok.com',
    # Others
    'dropbox.com', 'drive.google.com', 'docs.google.com',
    'zoom.us', 'teams.microsoft.com', 'slack.com', 'trello.com',
    'adobe.com', 'office.com', 'live.com',
    'wordpress.com', 'blogspot.com', 'medium.com',
    'w3.org', 'schema.org', 'iana.org',
    # Anthropic / AI (for SafeLink itself)
    'anthropic.com', 'openai.com',
])


# Manually verified phishing/impersonation domains — always included regardless of feed updates
MANUAL_BLOCKLIST = {
    'support-apple.com-verify.com',   # Apple brand impersonation via .com-verify.com trick
}


def _parse_hosts_file(content: str) -> set:
    """Extract domain names from a /etc/hosts format file."""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].lower().strip()
            # Skip local entries
            if domain in ('localhost', 'localhost.localdomain', 'local', '0.0.0.0'):
                continue
            # Basic domain validation
            if re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain) and '.' in domain:
                domains.add(domain)
    return domains


def _download(url: str) -> str:
    print(f"  Downloading {url} ...")
    req = urllib.request.Request(url, headers={'User-Agent': 'SafeLink-BuildTool/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read().decode('utf-8', errors='ignore')
    print(f"  Downloaded {len(content):,} bytes")
    return content


def main():
    os.makedirs(ANDROID_ASSETS_DIR, exist_ok=True)

    print("[BLOCKLIST] Building SafeLink blocklist ...")
    blocklist = set()

    # --- URLhaus ---
    try:
        content = _download(URLHAUS_HOSTS_URL)
        domains = _parse_hosts_file(content)
        print(f"  URLhaus domains: {len(domains):,}")
        blocklist.update(domains)
    except Exception as e:
        print(f"  [WARN] URLhaus download failed: {e}")
        print(f"         Add URLhaus hostfile manually to data/urlhaus_hosts.txt")
        # Try local fallback
        local_path = 'data/urlhaus_hosts.txt'
        if os.path.exists(local_path):
            with open(local_path) as f:
                domains = _parse_hosts_file(f.read())
            print(f"  URLhaus (local): {len(domains):,}")
            blocklist.update(domains)

    # --- StevenBlack ---
    try:
        content = _download(STEVENBLACK_URL)
        domains = _parse_hosts_file(content)
        print(f"  StevenBlack domains: {len(domains):,}")
        blocklist.update(domains)
    except Exception as e:
        print(f"  [WARN] StevenBlack download failed: {e}")

    # --- Manual entries ---
    blocklist.update(MANUAL_BLOCKLIST)
    print(f"  Manual entries: {len(MANUAL_BLOCKLIST)}")

    print(f"\n[MERGE] Total before whitelist removal: {len(blocklist):,}")

    # --- Remove whitelist domains ---
    whitelist_set = set(STATIC_WHITELIST)
    # Also remove all subdomains of whitelisted domains
    to_remove = set()
    for domain in blocklist:
        for safe in whitelist_set:
            if domain == safe or domain.endswith('.' + safe):
                to_remove.add(domain)
                break
    blocklist -= to_remove
    print(f"[FILTER] Removed {len(to_remove):,} whitelist/subdomain matches")
    print(f"[RESULT] Final blocklist: {len(blocklist):,} domains")

    # --- Write blocklist ---
    with open(BLOCKLIST_PATH, 'w', encoding='utf-8') as f:
        for domain in sorted(blocklist):
            f.write(domain + '\n')
    size_kb = os.path.getsize(BLOCKLIST_PATH) / 1024
    print(f"[SAVE]  blocklist.txt -> {BLOCKLIST_PATH}  ({size_kb:.0f} KB, {len(blocklist):,} domains)")

    # --- Write whitelist ---
    with open(WHITELIST_PATH, 'w', encoding='utf-8') as f:
        for domain in STATIC_WHITELIST:
            f.write(domain + '\n')
    print(f"[SAVE]  whitelist.txt -> {WHITELIST_PATH}  ({len(STATIC_WHITELIST)} domains)")

    print("\n[DONE] Blocklist build complete.")
    print("       Add blocklist.txt and whitelist.txt to Android aaptOptions noCompress list.")


if __name__ == '__main__':
    main()
