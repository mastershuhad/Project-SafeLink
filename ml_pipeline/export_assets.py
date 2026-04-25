"""
SafeLink Asset Exporter — copies all .tflite and .json model files to
Android assets/ directory and validates sizes against PRD targets.

Run this after trainer.py, autoencoder.py, and convert_urlbert.py are complete.
"""

import os
import json
import shutil
import sys

MODELS_DIR = 'models'
ANDROID_ASSETS_DIR = '../android/app/src/main/assets'

# (filename, max_size_kb, required)
ASSET_SPECS = [
    ('safelink_model.tflite', 200,   True),
    ('autoencoder.tflite',    300,   True),
    ('urlbert.tflite',        6144,  False),   # Optional — may use ONNX fallback
    ('urlbert.onnx',          6144,  False),   # Alternative to urlbert.tflite
    ('scaler_params.json',    10,    True),
    ('anomaly_threshold.json', 5,    True),
    ('urlbert_meta.json',     5,     False),
]


def validate_scaler(path: str):
    with open(path) as f:
        params = json.load(f)
    n = params.get('n_features')
    assert n == 36, f"scaler_params.json n_features must be 36, got {n}"
    assert len(params.get('mean', [])) == 36, "scaler mean must have 36 elements"
    assert len(params.get('scale', [])) == 36, "scaler scale must have 36 elements"
    print(f"  [OK] scaler n_features={n}, mean[0]={params['mean'][0]:.4f}")


def validate_anomaly_threshold(path: str):
    with open(path) as f:
        data = json.load(f)
    thresholds = data.get('thresholds', {})
    for cat in ['short', 'medium', 'long']:
        assert cat in thresholds, f"anomaly_threshold.json missing '{cat}' category"
    print(f"  [OK] thresholds: short={thresholds['short']:.6f}, "
          f"medium={thresholds['medium']:.6f}, long={thresholds['long']:.6f}")


def main():
    os.makedirs(ANDROID_ASSETS_DIR, exist_ok=True)

    print("=" * 60)
    print("SafeLink Asset Export & Validation")
    print("=" * 60)

    errors = []
    warnings = []

    # Check at least one URLBert model exists
    has_urlbert = (
        os.path.exists(os.path.join(MODELS_DIR, 'urlbert.tflite')) or
        os.path.exists(os.path.join(MODELS_DIR, 'urlbert.onnx'))
    )
    if not has_urlbert:
        warnings.append("Neither urlbert.tflite nor urlbert.onnx found — run convert_urlbert.py")

    for filename, max_kb, required in ASSET_SPECS:
        src = os.path.join(MODELS_DIR, filename)

        if not os.path.exists(src):
            if required:
                errors.append(f"MISSING (required): {filename}")
            else:
                print(f"  [SKIP] {filename} (optional, not found)")
            continue

        size_bytes = os.path.getsize(src)
        size_kb = size_bytes / 1024

        if size_kb > max_kb:
            warnings.append(f"{filename}: {size_kb:.1f} KB exceeds {max_kb} KB target")

        # Validate JSON files
        if filename == 'scaler_params.json':
            try:
                validate_scaler(src)
            except Exception as e:
                errors.append(f"scaler_params.json validation failed: {e}")
        elif filename == 'anomaly_threshold.json':
            try:
                validate_anomaly_threshold(src)
            except Exception as e:
                errors.append(f"anomaly_threshold.json validation failed: {e}")

        # Copy to Android assets
        dst = os.path.join(ANDROID_ASSETS_DIR, filename)
        shutil.copy2(src, dst)
        print(f"  [COPY] {filename}  ({size_kb:.1f} KB)  -> {dst}")

    print()

    if warnings:
        print("WARNINGS:")
        for w in warnings:
            print(f"  [!]  {w}")
        print()

    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  [X]  {e}")
        print()
        print("[FAIL] Asset export completed with errors.")
        sys.exit(1)
    else:
        print("[OK] All required assets exported successfully.")
        print(f"     Destination: {os.path.abspath(ANDROID_ASSETS_DIR)}")

    # Summary
    print("\nAssets in Android assets/:")
    for f in sorted(os.listdir(ANDROID_ASSETS_DIR)):
        size = os.path.getsize(os.path.join(ANDROID_ASSETS_DIR, f)) / 1024
        print(f"  {f:<35} {size:>8.1f} KB")


if __name__ == '__main__':
    main()
