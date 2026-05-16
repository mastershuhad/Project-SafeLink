"""
SafeLink Data Collector — merges all training data sources, maps labels,
extracts features in parallel, and outputs safelink_dataset.csv.

Label mapping:
  benign     -> 0 (SAFE)
  phishing   -> 2 (MALICIOUS)
  malware    -> 2 (MALICIOUS)
  defacement -> DROP (excluded from training)

WARNING class (1) is NEVER in training data — reserved for Fusion Engine only.

Data sources:
  1. malicious_phish_2021.csv  (651K rows — drop defacement ~96K)
  2. PhiUSIIL.csv              (235K rows — URL + label only, drop HTML features)
  3. phishtank_openphish.csv   (~7K  rows — all phishing)
  4. tranco_top1m.csv          (~10K rows — all benign)
  5. urlhaus.csv               (~170K rows — all malware)

Output: data/safelink_dataset.csv  (url, label, + 22 feature columns)
"""

import os
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from feature_extractor import extract_feature_vector, FEATURE_COLUMNS

DATA_DIR = '../Datasets'      # Folder containing raw dataset CSV files
OUTPUT_DIR = 'data'           # Output folder for processed dataset
OUTPUT_PATH = os.path.join(OUTPUT_DIR, 'safelink_dataset.csv')
N_WORKERS = 8
CHUNK_SIZE = 5000


def _load_malicious_phish() -> pd.DataFrame:
    path = os.path.join(DATA_DIR, 'malicious_phish_2021.csv')
    if not os.path.exists(path):
        print(f"[SKIP] {path} not found")
        return pd.DataFrame()
    df = pd.read_csv(path, usecols=['url', 'type'], low_memory=False)
    df.columns = ['url', 'raw_label']
    # Drop defacement rows
    df = df[df['raw_label'] != 'defacement'].copy()
    df['label'] = df['raw_label'].map({'benign': 0, 'phishing': 2, 'malware': 2})
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)
    df['source'] = 'malicious_phish_2021'
    print(f"[LOAD] malicious_phish_2021: {len(df):,} rows after dropping defacement")
    return df[['url', 'label', 'source']]


def _load_phiusiil() -> pd.DataFrame:
    for name in ['PhiUSIIL_Phishing_URL_Dataset.csv', 'PhiUSIIL.csv']:
        candidate = os.path.join(DATA_DIR, name)
        if os.path.exists(candidate):
            path = candidate
            break
    else:
        path = os.path.join(DATA_DIR, 'PhiUSIIL.csv')
    if not os.path.exists(path):
        print(f"[SKIP] {path} not found")
        return pd.DataFrame()
    # PhiUSIIL has many HTML features — keep URL and label only
    # encoding='utf-8-sig' strips the BOM (﻿) from column names
    df = pd.read_csv(path, usecols=lambda c: c.strip('﻿') in ('URL', 'label'),
                     encoding='utf-8-sig', low_memory=False)
    df.columns = [c.strip('﻿') for c in df.columns]
    df = df.rename(columns={'URL': 'url'})
    if 'url' not in df.columns:
        df.columns = ['url', 'label']
    # PhiUSIIL label: 1=legitimate(benign), 0=phishing
    df['label'] = df['label'].map({1: 0, 0: 2})
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)
    df['source'] = 'PhiUSIIL'
    print(f"[LOAD] PhiUSIIL: {len(df):,} rows")
    return df[['url', 'label', 'source']]


def _load_phishtank_openphish() -> pd.DataFrame:
    rows = []
    for fname in ['phishtank.csv', 'openphish.txt']:
        path = os.path.join(DATA_DIR, fname)
        if not os.path.exists(path):
            print(f"[SKIP] {path} not found")
            continue
        if fname.endswith('.txt'):
            with open(path) as f:
                urls = [line.strip() for line in f if line.strip()]
            rows.extend({'url': u, 'label': 2, 'source': 'openphish'} for u in urls)
        else:
            df = pd.read_csv(path, usecols=['url'], low_memory=False)
            rows.extend({'url': r['url'], 'label': 2, 'source': 'phishtank'} for _, r in df.iterrows())
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    print(f"[LOAD] PhishTank+OpenPhish: {len(df):,} rows")
    return df


def _load_tranco() -> pd.DataFrame:
    import random
    path = os.path.join(DATA_DIR, 'tranco_top1m.csv')
    if not os.path.exists(path):
        print(f"[SKIP] {path} not found")
        return pd.DataFrame()
    df = pd.read_csv(path, header=None, names=['rank', 'domain'], low_memory=False)
    df = df.head(10000)
    
    # Data Augmentation: Force a trailing slash on ALL Tranco domains.
    # This teaches the CNN that a trailing slash is the normal baseline for safe URLs.
    def augment_url(domain):
        base = 'https://' + domain + '/'
        return base

    df['url'] = df['domain'].apply(augment_url)
    df['label'] = 0
    df['source'] = 'tranco'
    print(f"[LOAD] Tranco: {len(df):,} rows")
    return df[['url', 'label', 'source']]


def _load_urlhaus() -> pd.DataFrame:
    path = os.path.join(DATA_DIR, 'urlhaus.csv')
    if not os.path.exists(path):
        print(f"[SKIP] {path} not found")
        return pd.DataFrame()
    # URLhaus: ALL lines starting with # are comments, including the header row
    # (e.g. "# id,dateadded,url,..."). Extract column names from that line first.
    header_cols = None
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('#'):
                stripped = line.lstrip('#').strip()
                if stripped and ',' in stripped and 'url' in stripped.lower():
                    header_cols = [c.strip() for c in stripped.split(',')]
                    break
    if not header_cols:
        header_cols = ['id', 'dateadded', 'url', 'url_status',
                       'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter']
    df = pd.read_csv(path, comment='#', header=None, names=header_cols, low_memory=False)
    df = df[['url']].copy()
    df['label'] = 2
    df['source'] = 'urlhaus'
    print(f"[LOAD] URLhaus: {len(df):,} rows")
    return df[['url', 'label', 'source']]


def _extract_chunk(chunk_urls):
    results = []
    for url in chunk_urls:
        try:
            vec = extract_feature_vector(str(url))
            results.append(vec)
        except Exception:
            results.append([0.0] * 22)
    return results


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # --- Load all sources ---
    frames = []
    for loader in [_load_malicious_phish, _load_phiusiil,
                   _load_phishtank_openphish, _load_tranco, _load_urlhaus]:
        df = loader()
        if not df.empty:
            frames.append(df)

    if not frames:
        print("[ERROR] No data files found in data/. Place source CSVs in data/ and re-run.")
        return

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n[MERGE] Combined: {len(combined):,} rows")

    # --- Clean ---
    combined['url'] = combined['url'].astype(str).str.strip()
    combined = combined[combined['url'].str.len() >= 4]
    combined = combined[combined['url'].notna()]

    # --- Deduplicate ---
    before = len(combined)
    combined = combined.drop_duplicates(subset='url')
    print(f"[DEDUP] {before - len(combined):,} duplicates removed -> {len(combined):,} rows")

    # --- Parallel feature extraction ---
    urls = combined['url'].tolist()
    chunks = [urls[i:i + CHUNK_SIZE] for i in range(0, len(urls), CHUNK_SIZE)]

    print(f"\n[FEATURES] Extracting 22 features from {len(urls):,} URLs using {N_WORKERS} workers...")
    all_features = []

    with ThreadPoolExecutor(max_workers=N_WORKERS) as executor:
        futures = {executor.submit(_extract_chunk, chunk): i for i, chunk in enumerate(chunks)}
        chunk_results = [None] * len(chunks)
        for future in tqdm(as_completed(futures), total=len(chunks), desc="Chunks"):
            idx = futures[future]
            chunk_results[idx] = future.result()

    for chunk in chunk_results:
        all_features.extend(chunk)

    feature_df = pd.DataFrame(all_features, columns=FEATURE_COLUMNS)

    # --- Assemble final dataset ---
    combined = combined.reset_index(drop=True)
    result = pd.concat([combined[['url', 'label']], feature_df], axis=1)

    # --- Class distribution report ---
    dist = result['label'].value_counts()
    print(f"\n[DISTRIBUTION]")
    print(f"  SAFE (0):      {dist.get(0, 0):>10,}")
    print(f"  MALICIOUS (2): {dist.get(2, 0):>10,}")
    print(f"  Total:         {len(result):>10,}")

    # --- Save ---
    result.to_csv(OUTPUT_PATH, index=False)
    print(f"\n[DONE] Saved {len(result):,} rows -> {OUTPUT_PATH}")
    print(f"       Columns: {list(result.columns)}")


if __name__ == '__main__':
    main()
