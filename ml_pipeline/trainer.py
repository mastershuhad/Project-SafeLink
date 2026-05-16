"""
SafeLink CNN+Dense Trainer v5.1 — PRD-compliant dual-stream hybrid model.

Architecture (PRD v5.1):
  Stream A (Character CNN): Input int[200]
    -> Embedding(100, 32)
    -> Conv1D(128, k=2, relu) -> Conv1D(128, k=3, relu) -> Conv1D(64, k=5, relu)
    -> GlobalMaxPooling1D -> Dense(128, relu) -> Dropout(0.3)
  Stream B (Dense numeric):  Input float[22]
    -> BatchNormalization -> Dense(128, relu) -> Dense(64, relu) -> Dropout(0.2)
  Fusion: Concatenate -> Dense(256, relu) -> Dropout(0.3)
                      -> Dense(128, relu) -> Dropout(0.2)
                      -> Dense(64, relu) -> Softmax(3)

Output classes: SAFE=0, WARNING=1 (never trained), MALICIOUS=2
n_features: 22 LOCKED
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix
from urllib.parse import urlparse
import re
import tensorflow as tf
from tensorflow import keras

from feature_extractor import FEATURE_COLUMNS, N_FEATURES

DATA_PATH   = 'data/safelink_dataset.csv'
OUTPUT_DIR  = 'models'
TFLITE_PATH = os.path.join(OUTPUT_DIR, 'safelink_model.tflite')
SCALER_PATH = os.path.join(OUTPUT_DIR, 'scaler_params.json')

SEQ_LEN    = 200
VOCAB_SIZE = 100
EMBED_DIM  = 32

BATCH_SIZE    = 128
EPOCHS        = 30
LEARNING_RATE = 1e-3
RANDOM_SEED   = 42


def encode_url(url: str, seq_len: int = SEQ_LEN) -> list:
    """Mirrors UrlTokenizer.kt: char -> (code - 31).coerceIn(1, 99), pad to seq_len."""
    encoded = []
    for c in url[:seq_len]:
        code  = ord(c)
        token = max(1, min(99, code - 31))
        encoded.append(token)
    while len(encoded) < seq_len:
        encoded.append(0)
    return encoded


def build_model() -> keras.Model:
    # --- Stream A: Character CNN Branch (PRD v5.1 §4.1) ---
    seq_input = keras.Input(shape=(SEQ_LEN,), dtype='int32', name='seq_input')
    x = keras.layers.Embedding(VOCAB_SIZE + 1, EMBED_DIM, mask_zero=True)(seq_input)
    x = keras.layers.Conv1D(128, kernel_size=2, activation='relu', padding='same')(x)
    x = keras.layers.Conv1D(128, kernel_size=3, activation='relu', padding='same')(x)
    x = keras.layers.Conv1D(64,  kernel_size=5, activation='relu', padding='same')(x)
    x = keras.layers.GlobalMaxPooling1D()(x)
    x = keras.layers.Dense(128, activation='relu')(x)
    x = keras.layers.Dropout(0.3)(x)

    # --- Stream B: Dense Numeric Branch (PRD v5.1 §4.1) ---
    num_input = keras.Input(shape=(N_FEATURES,), dtype='float32', name='num_input')
    y = keras.layers.BatchNormalization()(num_input)
    y = keras.layers.Dense(128, activation='relu')(y)
    y = keras.layers.Dense(64,  activation='relu')(y)
    y = keras.layers.Dropout(0.2)(y)

    # --- Fusion (PRD v5.1 §4.1) ---
    merged = keras.layers.Concatenate()([x, y])
    z = keras.layers.Dense(256, activation='relu')(merged)
    z = keras.layers.Dropout(0.3)(z)
    z = keras.layers.Dense(128, activation='relu')(z)
    z = keras.layers.Dropout(0.2)(z)
    z = keras.layers.Dense(64,  activation='relu')(z)
    output = keras.layers.Dense(3, activation='softmax', name='output')(z)

    return keras.Model(inputs=[seq_input, num_input], outputs=output)


def representative_dataset_gen(seq_data, num_data, n_samples=200):
    """Generator for INT8 calibration."""
    indices = np.random.choice(len(seq_data), min(n_samples, len(seq_data)), replace=False)
    def gen():
        for i in indices:
            yield [seq_data[i:i+1].astype(np.int32), num_data[i:i+1].astype(np.float32)]
    return gen


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    np.random.seed(RANDOM_SEED)
    tf.random.set_seed(RANDOM_SEED)

    # --- Load dataset ---
    print(f"[LOAD] Reading {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    print(f"       {len(df):,} rows, columns: {list(df.columns[:5])} ...")

    # Keep only SAFE (0) and MALICIOUS (2) — WARNING (1) never trained
    df = df[df['label'].isin([0, 2])].copy()
    print(f"[FILTER] After keeping SAFE+MALICIOUS: {len(df):,} rows")

    # --- Feature matrix and labels ---
    X_num = df[FEATURE_COLUMNS].values.astype(np.float32)

    print("[ENCODE] Tokenizing URLs ...")
    X_seq = np.array([encode_url(str(url)) for url in df['url']], dtype=np.int32)

    y = df['label'].values.astype(np.int32)

    # --- GroupShuffleSplit: 80% train / 10% val / 10% test (no domain leakage) ---
    print("[SPLIT] Extracting domains for GroupShuffleSplit ...")

    def get_host(u):
        try:
            h = urlparse(u if '://' in u else 'http://' + u).netloc.split(':')[0].lower()
            return re.sub(r'^www\.', '', h)
        except Exception:
            return str(u)

    groups = np.array([get_host(str(u)) for u in df['url']])

    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_SEED)
    train_idx, tmp_idx = next(gss1.split(X_seq, y, groups))

    X_seq_train, X_seq_tmp = X_seq[train_idx], X_seq[tmp_idx]
    X_num_train, X_num_tmp = X_num[train_idx], X_num[tmp_idx]
    y_train, y_tmp         = y[train_idx], y[tmp_idx]
    groups_tmp             = groups[tmp_idx]

    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=RANDOM_SEED)
    val_idx, test_idx = next(gss2.split(X_seq_tmp, y_tmp, groups_tmp))

    X_seq_val,  X_seq_test  = X_seq_tmp[val_idx],  X_seq_tmp[test_idx]
    X_num_val,  X_num_test  = X_num_tmp[val_idx],  X_num_tmp[test_idx]
    y_val,      y_test      = y_tmp[val_idx],       y_tmp[test_idx]
    print(f"[SPLIT] Train: {len(y_train):,}  Val: {len(y_val):,}  Test: {len(y_test):,}")

    # --- Fit scaler on TRAINING set only ---
    print("[SCALER] Fitting StandardScaler on training features ...")
    scaler = StandardScaler()
    X_num_train = scaler.fit_transform(X_num_train).astype(np.float32)
    X_num_val   = scaler.transform(X_num_val).astype(np.float32)
    X_num_test  = scaler.transform(X_num_test).astype(np.float32)

    scaler_params = {
        'n_features':    N_FEATURES,
        'feature_names': FEATURE_COLUMNS,
        'mean':          scaler.mean_.tolist(),
        'scale':         scaler.scale_.tolist(),
    }
    with open(SCALER_PATH, 'w') as f:
        json.dump(scaler_params, f, indent=2)
    print(f"[SCALER] Saved -> {SCALER_PATH}  (n_features={N_FEATURES})")

    # --- Class weights (PRD v5.1 §4.2 — compute_class_weight balanced) ---
    classes_present = np.unique(y_train)
    raw_weights     = compute_class_weight('balanced', classes=classes_present, y=y_train)
    class_weight    = dict(zip(classes_present.tolist(), raw_weights.tolist()))
    if 1 not in class_weight:
        class_weight[1] = 1.0   # WARNING class absent from training — neutral weight
    print(f"[WEIGHTS] class_weight = {class_weight}")

    # --- Build and train model ---
    model = build_model()
    model.summary()

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy'],
    )

    callbacks = [
        keras.callbacks.EarlyStopping(
            patience=5, restore_best_weights=True, monitor='val_loss'
        ),
        keras.callbacks.ReduceLROnPlateau(
            patience=2, factor=0.5, monitor='val_loss', min_lr=1e-6
        ),
        keras.callbacks.ModelCheckpoint(
            os.path.join(OUTPUT_DIR, 'best_model.keras'),
            save_best_only=True, monitor='val_accuracy',
        ),
    ]

    print(f"\n[TRAIN] Training for up to {EPOCHS} epochs (batch={BATCH_SIZE}) ...")
    model.fit(
        x={'seq_input': X_seq_train, 'num_input': X_num_train},
        y=y_train,
        validation_data=(
            {'seq_input': X_seq_val, 'num_input': X_num_val},
            y_val,
        ),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=1,
    )

    # --- Evaluate ---
    print("\n[EVAL] Test set evaluation:")
    test_loss, test_acc = model.evaluate(
        x={'seq_input': X_seq_test, 'num_input': X_num_test},
        y=y_test, verbose=0,
    )
    print(f"  Loss: {test_loss:.4f}  Accuracy: {test_acc:.4f}")

    y_pred = np.argmax(model.predict(
        {'seq_input': X_seq_test, 'num_input': X_num_test}, verbose=0
    ), axis=1)
    print("\n[REPORT]")
    print(classification_report(y_test, y_pred,
                                 target_names=['SAFE', 'WARNING', 'MALICIOUS'],
                                 labels=[0, 1, 2]))
    print("[CONFUSION MATRIX]")
    print(confusion_matrix(y_test, y_pred, labels=[0, 2]))

    # --- Convert to TFLite (dynamic range quantization) ---
    # Full INT8 is incompatible with Embedding(int32) + Keras 3 MLIR lowering.
    # Dynamic range quantization quantizes weights to int8, keeps activations float32,
    # and is fully compatible with int32 sequence inputs in SafeLinkClassifier.kt.
    print("\n[TFLITE] Converting to TFLite (dynamic range quantization) ...")
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]

    tflite_model = converter.convert()
    with open(TFLITE_PATH, 'wb') as f:
        f.write(tflite_model)

    size_kb = os.path.getsize(TFLITE_PATH) / 1024
    print(f"[TFLITE] Saved -> {TFLITE_PATH}  ({size_kb:.1f} KB)")
    if size_kb > 300:
        print(f"[WARN]  Model exceeds 300 KB — consider pruning Conv1D filters")
    else:
        print(f"[OK]    Model within 300 KB target")

    # --- Quick TFLite validation ---
    print("\n[VALIDATE] TFLite inference check ...")
    interp = tf.lite.Interpreter(model_path=TFLITE_PATH)
    interp.allocate_tensors()
    inp_details = interp.get_input_details()
    out_details = interp.get_output_details()
    print(f"  Inputs:  {[(d['name'], d['shape'].tolist(), d['dtype'].__name__) for d in inp_details]}")
    print(f"  Outputs: {[(d['name'], d['shape'].tolist(), d['dtype'].__name__) for d in out_details]}")

    sample_seq = X_seq_test[0:1].astype(np.int32)
    sample_num = X_num_test[0:1].astype(np.float32)
    for d in inp_details:
        if 'seq' in d['name']:
            interp.set_tensor(d['index'], sample_seq)
        else:
            interp.set_tensor(d['index'], sample_num)
    interp.invoke()
    out = interp.get_tensor(out_details[0]['index'])
    print(f"  Sample output (3-class softmax): {out[0]}")
    print(f"  Predicted class: {np.argmax(out[0])}  True: {y_test[0]}")
    print("\n[DONE] Training complete.")


if __name__ == '__main__':
    main()
