"""
SafeLink CNN+Dense Trainer — Dual-stream hybrid model.

Architecture:
  Stream A (Character CNN): Input int[200] -> Embedding(100, 32) -> Conv1D(64,3) ->
                             GlobalMaxPool -> Dense(64) -> Dropout(0.3)
  Stream B (Dense features): Input float[36] -> Dense(64) -> ReLU -> Dense(32) -> Dropout(0.2)
  Fusion: Concatenate -> Dense(64) -> ReLU -> Dense(3, softmax)

Output: 3-class [p_safe, p_warning, p_malicious]
  Class 0 = SAFE, Class 1 = WARNING (never in training), Class 2 = MALICIOUS

Int8 post-training quantization -> safelink_model.tflite (~100KB target)
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow import keras

from feature_extractor import FEATURE_COLUMNS

DATA_PATH = 'data/safelink_dataset.csv'
OUTPUT_DIR = 'models'
TFLITE_PATH = os.path.join(OUTPUT_DIR, 'safelink_model.tflite')
SCALER_PATH = os.path.join(OUTPUT_DIR, 'scaler_params.json')

SEQ_LEN = 200
VOCAB_SIZE = 100
EMBED_DIM = 32

# Use smaller batch size on laptop, larger on GPU
BATCH_SIZE = 64
EPOCHS = 15
LEARNING_RATE = 1e-3

RANDOM_SEED = 42


def encode_url(url: str, seq_len: int = SEQ_LEN) -> list:
    """Mirrors UrlTokenizer.kt: char -> (code - 31).coerceIn(1, 99), pad to seq_len."""
    encoded = []
    for c in url[:seq_len]:
        code = ord(c)
        token = max(1, min(99, code - 31))
        encoded.append(token)
    while len(encoded) < seq_len:
        encoded.append(0)
    return encoded


def build_model() -> keras.Model:
    # --- Stream A: Character CNN ---
    seq_input = keras.Input(shape=(SEQ_LEN,), dtype='int32', name='seq_input')
    x = keras.layers.Embedding(VOCAB_SIZE + 1, EMBED_DIM, mask_zero=True)(seq_input)
    x = keras.layers.Conv1D(64, 3, activation='relu', padding='same')(x)
    x = keras.layers.GlobalMaxPooling1D()(x)
    x = keras.layers.Dense(64, activation='relu')(x)
    x = keras.layers.Dropout(0.3)(x)

    # --- Stream B: Dense numeric features ---
    num_input = keras.Input(shape=(36,), dtype='float32', name='num_input')
    y = keras.layers.Dense(64, activation='relu')(num_input)
    y = keras.layers.Dense(32, activation='relu')(y)
    y = keras.layers.Dropout(0.2)(y)

    # --- Fusion ---
    merged = keras.layers.Concatenate()([x, y])
    z = keras.layers.Dense(64, activation='relu')(merged)
    output = keras.layers.Dense(3, activation='softmax', name='output')(z)

    model = keras.Model(inputs=[seq_input, num_input], outputs=output)
    return model


def representative_dataset_gen(seq_data, num_data, n_samples=200):
    """Generator for INT8 calibration."""
    indices = np.random.choice(len(seq_data), n_samples, replace=False)
    def gen():
        for i in indices:
            yield [
                seq_data[i:i+1].astype(np.int32),
                num_data[i:i+1].astype(np.float32),
            ]
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

    # Labels: map {0->0, 2->2}  (class indices for 3-class softmax — class 1 left empty)
    y = df['label'].values.astype(np.int32)

    # --- Train/val/test split ---
    (X_seq_train, X_seq_tmp, X_num_train, X_num_tmp, y_train, y_tmp) = train_test_split(
        X_seq, X_num, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )
    (X_seq_val, X_seq_test, X_num_val, X_num_test, y_val, y_test) = train_test_split(
        X_seq_tmp, X_num_tmp, y_tmp, test_size=0.5, random_state=RANDOM_SEED, stratify=y_tmp
    )
    print(f"[SPLIT] Train: {len(y_train):,}  Val: {len(y_val):,}  Test: {len(y_test):,}")

    # --- Fit scaler on TRAINING set only ---
    print("[SCALER] Fitting StandardScaler on training features ...")
    scaler = StandardScaler()
    X_num_train = scaler.fit_transform(X_num_train).astype(np.float32)
    X_num_val = scaler.transform(X_num_val).astype(np.float32)
    X_num_test = scaler.transform(X_num_test).astype(np.float32)

    # Export scaler params for Kotlin FeatureScaler.kt
    scaler_params = {
        'n_features': 36,
        'feature_names': FEATURE_COLUMNS,
        'mean': scaler.mean_.tolist(),
        'scale': scaler.scale_.tolist(),
    }
    with open(SCALER_PATH, 'w') as f:
        json.dump(scaler_params, f, indent=2)
    print(f"[SCALER] Saved -> {SCALER_PATH}  (n_features={scaler_params['n_features']})")

    # --- Build and train model ---
    model = build_model()
    model.summary()

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy'],
    )

    callbacks = [
        keras.callbacks.EarlyStopping(patience=3, restore_best_weights=True, monitor='val_loss'),
        keras.callbacks.ReduceLROnPlateau(patience=2, factor=0.5, monitor='val_loss'),
        keras.callbacks.ModelCheckpoint(
            os.path.join(OUTPUT_DIR, 'best_model.keras'),
            save_best_only=True, monitor='val_accuracy'
        ),
    ]

    print(f"\n[TRAIN] Training for up to {EPOCHS} epochs (batch={BATCH_SIZE}) ...")
    history = model.fit(
        x={'seq_input': X_seq_train, 'num_input': X_num_train},
        y=y_train,
        validation_data=(
            {'seq_input': X_seq_val, 'num_input': X_num_val},
            y_val,
        ),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=callbacks,
        verbose=1,
    )

    # --- Evaluate ---
    print("\n[EVAL] Test set evaluation:")
    test_loss, test_acc = model.evaluate(
        x={'seq_input': X_seq_test, 'num_input': X_num_test},
        y=y_test, verbose=0
    )
    print(f"  Loss: {test_loss:.4f}  Accuracy: {test_acc:.4f}")

    y_pred = np.argmax(model.predict(
        {'seq_input': X_seq_test, 'num_input': X_num_test}, verbose=0
    ), axis=1)
    print("\n[REPORT]")
    print(classification_report(y_test, y_pred, target_names=['SAFE', 'WARNING', 'MALICIOUS'], labels=[0, 1, 2]))
    print("[CONFUSION MATRIX]")
    print(confusion_matrix(y_test, y_pred, labels=[0, 2]))

    # --- Convert to TFLite with dynamic range quantization ---
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
    if size_kb > 200:
        print(f"[WARN]  Model exceeds 200KB target ({size_kb:.1f} KB) — consider pruning")
    else:
        print(f"[OK]    Model within 200KB target")

    # --- Quick TFLite validation ---
    print("\n[VALIDATE] TFLite inference check ...")
    interp = tf.lite.Interpreter(model_path=TFLITE_PATH)
    interp.allocate_tensors()
    inp_details = interp.get_input_details()
    out_details = interp.get_output_details()
    print(f"  Inputs: {[(d['name'], d['shape'], d['dtype']) for d in inp_details]}")
    print(f"  Outputs: {[(d['name'], d['shape'], d['dtype']) for d in out_details]}")

    # Run one sample
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
