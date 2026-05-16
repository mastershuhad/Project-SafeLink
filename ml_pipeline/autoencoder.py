"""
SafeLink Autoencoder — Zero-day anomaly detector.

Trained ONLY on benign URLs (label=0) from safelink_dataset.csv (~539K rows).
At inference time, MSE reconstruction error is compared against adaptive
per-category thresholds (95th percentile of benign MSE on val set).

Length categories:
  short:  url_length < 30
  medium: 30 <= url_length <= 80
  long:   url_length > 80

Output files:
  models/autoencoder.tflite     (~170KB target)
  models/anomaly_threshold.json
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras

from feature_extractor import FEATURE_COLUMNS, N_FEATURES

DATA_PATH = 'data/safelink_dataset.csv'
OUTPUT_DIR = 'models'
TFLITE_PATH = os.path.join(OUTPUT_DIR, 'autoencoder.tflite')
THRESHOLD_PATH = os.path.join(OUTPUT_DIR, 'anomaly_threshold.json')

# Reuse the same scaler params saved by trainer.py
SCALER_PATH = os.path.join(OUTPUT_DIR, 'scaler_params.json')

RANDOM_SEED = 42
BATCH_SIZE = 256
EPOCHS = 30
LATENT_DIM = 10

# Length category thresholds (mirrors Kotlin AutoencoderDetector.kt)
SHORT_MAX = 30
LONG_MIN = 80


def _length_category(url_length: float) -> str:
    if url_length < SHORT_MAX:
        return 'short'
    elif url_length <= LONG_MIN:
        return 'medium'
    else:
        return 'long'


def build_autoencoder(input_dim: int = N_FEATURES) -> keras.Model:
    inp = keras.Input(shape=(input_dim,), name='ae_input')
    # Encoder
    x = keras.layers.Dense(16, activation='relu')(inp)
    x = keras.layers.Dense(LATENT_DIM, activation='relu', name='latent')(x)
    # Decoder
    x = keras.layers.Dense(16, activation='relu')(x)
    out = keras.layers.Dense(input_dim, activation='linear', name='ae_output')(x)
    model = keras.Model(inputs=inp, outputs=out, name='autoencoder')
    return model


def representative_dataset_gen(data, n_samples=200):
    indices = np.random.choice(len(data), min(n_samples, len(data)), replace=False)
    def gen():
        for i in indices:
            yield [data[i:i+1].astype(np.float32)]
    return gen


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    np.random.seed(RANDOM_SEED)
    tf.random.set_seed(RANDOM_SEED)

    # --- Load dataset ---
    print(f"[LOAD] Reading {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, low_memory=False)

    # Keep BENIGN only for training
    benign_df = df[df['label'] == 0].copy()
    print(f"[FILTER] Benign URLs: {len(benign_df):,}")

    # Load scaler params (fit by trainer.py)
    if not os.path.exists(SCALER_PATH):
        print(f"[ERROR] {SCALER_PATH} not found — run trainer.py first to generate scaler params")
        return

    with open(SCALER_PATH) as f:
        scaler_params = json.load(f)
    assert scaler_params['n_features'] == N_FEATURES, \
        f"Scaler n_features must be {N_FEATURES}, got {scaler_params['n_features']}"

    mean_  = np.array(scaler_params['mean']).astype(np.float32)
    scale_ = np.array(scaler_params['scale']).astype(np.float32)

    # --- Extract and scale features ---
    X = benign_df[FEATURE_COLUMNS].values.astype(np.float32)
    # URL length for length-category thresholds — computed directly from URL string
    url_lengths = benign_df['url'].str.len().values

    X_scaled = ((X - mean_) / scale_).astype(np.float32)

    # --- Train/val split (stratified by length category) ---
    from sklearn.model_selection import train_test_split
    X_train, X_val, ul_train, ul_val = train_test_split(
        X_scaled, url_lengths, test_size=0.1, random_state=RANDOM_SEED
    )
    print(f"[SPLIT] Train: {len(X_train):,}  Val: {len(X_val):,}")

    # --- Build and train autoencoder ---
    ae = build_autoencoder(input_dim=N_FEATURES)
    ae.summary()
    ae.compile(optimizer=keras.optimizers.Adam(1e-3), loss='mse')

    callbacks = [
        keras.callbacks.EarlyStopping(patience=4, restore_best_weights=True, monitor='val_loss'),
        keras.callbacks.ReduceLROnPlateau(patience=2, factor=0.5, monitor='val_loss'),
    ]

    print(f"\n[TRAIN] Training autoencoder for up to {EPOCHS} epochs ...")
    ae.fit(
        X_train, X_train,
        validation_data=(X_val, X_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=callbacks,
        verbose=1,
    )

    # --- Compute per-category adaptive thresholds on val set ---
    print("\n[THRESHOLD] Computing 95th-percentile MSE thresholds per URL length category ...")
    val_recon = ae.predict(X_val, verbose=0)
    mse_per_sample = np.mean((X_val - val_recon) ** 2, axis=1)

    thresholds = {}
    for cat in ['short', 'medium', 'long']:
        mask = np.array([_length_category(l) == cat for l in ul_val])
        if mask.sum() == 0:
            thresholds[cat] = float(np.percentile(mse_per_sample, 95))
        else:
            thresholds[cat] = float(np.percentile(mse_per_sample[mask], 95))
        count = int(mask.sum())
        print(f"  {cat:6s}: {count:6,} samples  threshold={thresholds[cat]:.6f}")

    with open(THRESHOLD_PATH, 'w') as f:
        json.dump({
            'thresholds': thresholds,
            'short_max': SHORT_MAX,
            'long_min': LONG_MIN,
            'description': 'Adaptive 95th-percentile MSE thresholds per URL length category',
        }, f, indent=2)
    print(f"[THRESHOLD] Saved -> {THRESHOLD_PATH}")

    # --- Convert to TFLite INT8 ---
    print("\n[TFLITE] Converting autoencoder to TFLite INT8 ...")
    converter = tf.lite.TFLiteConverter.from_keras_model(ae)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    converter.representative_dataset = representative_dataset_gen(X_train)
    converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
    converter.inference_input_type = tf.float32
    converter.inference_output_type = tf.float32

    tflite_bytes = converter.convert()
    with open(TFLITE_PATH, 'wb') as f:
        f.write(tflite_bytes)

    size_kb = os.path.getsize(TFLITE_PATH) / 1024
    print(f"[TFLITE] Saved -> {TFLITE_PATH}  ({size_kb:.1f} KB)")
    if size_kb > 300:
        print(f"[WARN]  Exceeds 300KB target ({size_kb:.1f} KB)")
    else:
        print(f"[OK]    Within 300KB target")

    # --- Validate TFLite inference ---
    print("\n[VALIDATE] TFLite autoencoder check ...")
    try:
        from ai_edge_litert.interpreter import Interpreter as LiteRTInterpreter
        interp = LiteRTInterpreter(model_path=TFLITE_PATH)
    except ImportError:
        interp = tf.lite.Interpreter(model_path=TFLITE_PATH)
    interp.allocate_tensors()
    inp_d = interp.get_input_details()[0]
    out_d = interp.get_output_details()[0]
    print(f"  Input:  {inp_d['name']}  shape={inp_d['shape']}  dtype={inp_d['dtype']}")
    print(f"  Output: {out_d['name']}  shape={out_d['shape']}  dtype={out_d['dtype']}")

    sample = X_val[0:1].astype(np.float32)
    interp.set_tensor(inp_d['index'], sample)
    interp.invoke()
    recon = interp.get_tensor(out_d['index'])
    mse = float(np.mean((sample - recon) ** 2))
    cat = _length_category(ul_val[0])
    is_anomaly = mse > thresholds[cat]
    print(f"  Sample MSE: {mse:.6f}  Category: {cat}  Threshold: {thresholds[cat]:.6f}  Anomaly: {is_anomaly}")
    print("\n[DONE] Autoencoder training complete.")


if __name__ == '__main__':
    main()
