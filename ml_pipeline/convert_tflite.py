"""
Loads best_model.keras (trained with Keras 3) and converts to TFLite.

Root cause of TFLite failure: Keras 3's Conv1D uses backend ops the MLIR converter
can't lower ('missing attribute value' / LLVM error).
Fix: rebuild model using tf_keras (Keras 2) which uses tf.nn.conv1d directly.
Copy weights from the Keras 3 model into the tf_keras model, then convert.
"""

import os
import numpy as np
import tensorflow as tf
import tf_keras
from tensorflow import keras  # Keras 3 — used only to load the saved weights

OUTPUT_DIR = 'models'
KERAS_PATH = os.path.join(OUTPUT_DIR, 'best_model.keras')
TFLITE_PATH = os.path.join(OUTPUT_DIR, 'safelink_model.tflite')

SEQ_LEN = 200
VOCAB_SIZE = 100
EMBED_DIM = 32


def build_tf_keras_model():
    """Identical architecture to trainer.py but built with tf_keras (Keras 2)."""
    seq_input = tf_keras.Input(shape=(SEQ_LEN,), dtype='int32', name='seq_input')
    x = tf_keras.layers.Embedding(VOCAB_SIZE + 1, EMBED_DIM, mask_zero=False)(seq_input)
    x = tf_keras.layers.Conv1D(64, 3, activation='relu', padding='same')(x)
    x = tf_keras.layers.GlobalMaxPooling1D()(x)
    x = tf_keras.layers.Dense(64, activation='relu')(x)
    x = tf_keras.layers.Dropout(0.3)(x)

    num_input = tf_keras.Input(shape=(36,), dtype='float32', name='num_input')
    y = tf_keras.layers.Dense(64, activation='relu')(num_input)
    y = tf_keras.layers.Dense(32, activation='relu')(y)
    y = tf_keras.layers.Dropout(0.2)(y)

    merged = tf_keras.layers.Concatenate()([x, y])
    z = tf_keras.layers.Dense(64, activation='relu')(merged)
    output = tf_keras.layers.Dense(3, activation='softmax', name='output')(z)
    return tf_keras.Model(inputs=[seq_input, num_input], outputs=output)


def main():
    print(f"[LOAD] Loading Keras 3 model from {KERAS_PATH} ...")
    original = keras.models.load_model(KERAS_PATH)

    print("[REBUILD] Creating tf_keras (Keras 2) export model ...")
    export_model = build_tf_keras_model()

    # Trigger a forward pass to build the tf_keras model before setting weights
    dummy_seq = np.zeros((1, SEQ_LEN), dtype=np.int32)
    dummy_num = np.zeros((1, 36), dtype=np.float32)
    _ = export_model.predict({'seq_input': dummy_seq, 'num_input': dummy_num}, verbose=0)

    # Copy weights layer-by-layer (same architecture, same weight shapes)
    copied = 0
    for orig_layer, exp_layer in zip(original.layers, export_model.layers):
        w = orig_layer.get_weights()
        if w:
            exp_layer.set_weights(w)
            copied += 1
    print(f"[WEIGHTS] Copied weights for {copied} layers.")

    # Sanity check: outputs should match
    rng_seq = np.random.randint(0, 100, (1, SEQ_LEN), dtype=np.int32)
    rng_num = np.random.randn(1, 36).astype(np.float32)
    out_orig = original.predict({'seq_input': rng_seq, 'num_input': rng_num}, verbose=0)
    out_exp  = export_model.predict({'seq_input': rng_seq, 'num_input': rng_num}, verbose=0)
    max_diff = float(np.max(np.abs(out_orig - out_exp)))
    print(f"[CHECK]  Max output diff Keras3 vs tf_keras: {max_diff:.6f}  (should be ~0)")
    if max_diff > 1e-3:
        raise ValueError(f"Large divergence between Keras 3 and TFLite output: {max_diff}. Weight copy may have failed.")

    print("\n[TFLITE] Converting tf_keras model (dynamic range quantization) ...")
    converter = tf.lite.TFLiteConverter.from_keras_model(export_model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()

    with open(TFLITE_PATH, 'wb') as f:
        f.write(tflite_model)

    size_kb = os.path.getsize(TFLITE_PATH) / 1024
    print(f"[TFLITE] Saved -> {TFLITE_PATH}  ({size_kb:.1f} KB)")
    if size_kb > 200:
        print(f"[WARN]  Model exceeds 200KB target ({size_kb:.1f} KB)")
    else:
        print(f"[OK]    Model within 200KB target")

    print("\n[VALIDATE] TFLite inference check ...")
    try:
        from ai_edge_litert.interpreter import Interpreter as LiteRTInterpreter
        interp = LiteRTInterpreter(model_path=TFLITE_PATH)
    except ImportError:
        interp = tf.lite.Interpreter(model_path=TFLITE_PATH)
    interp.allocate_tensors()
    inp_details = interp.get_input_details()
    out_details = interp.get_output_details()
    print(f"  Inputs:  {[(d['name'], d['shape'], d['dtype'].__name__) for d in inp_details]}")
    print(f"  Outputs: {[(d['name'], d['shape'], d['dtype'].__name__) for d in out_details]}")

    for d in inp_details:
        if d['dtype'] == np.int32:
            interp.set_tensor(d['index'], rng_seq)
        else:
            interp.set_tensor(d['index'], rng_num)
    interp.invoke()
    out = interp.get_tensor(out_details[0]['index'])
    print(f"  TFLite output (3-class softmax): {out[0]}")
    print(f"  Predicted class: {np.argmax(out[0])}")
    print("\n[DONE] TFLite conversion complete.")


if __name__ == '__main__':
    main()
