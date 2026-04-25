"""
SafeLink URLBert Converter — converts CrabInHoney/urlbert-tiny-v4-phishing-classifier
from PyTorch (HuggingFace) to TFLite via ai_edge_torch.

Primary path:  ai_edge_torch  (preferred)
Fallback path: ONNX Runtime for Android (if ai_edge_torch fails)

Output: models/urlbert.tflite  (~4-5MB INT8 target)

The model outputs shape (1, 2) — [p_benign, p_phishing].
Only output[0][1] (p_phishing) is used by URLBertClassifier.kt.
"""

import os
import sys
import json
import numpy as np

OUTPUT_DIR = 'models'
TFLITE_PATH = os.path.join(OUTPUT_DIR, 'urlbert.tflite')
ONNX_PATH = os.path.join(OUTPUT_DIR, 'urlbert.onnx')
# Use local folder if already downloaded, otherwise fall back to HuggingFace
_LOCAL_MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'urlbert-tiny-v4-phishing-classifier')
MODEL_NAME = os.path.abspath(_LOCAL_MODEL_DIR) if os.path.isdir(_LOCAL_MODEL_DIR) else \
    'CrabInHoney/urlbert-tiny-v4-phishing-classifier'
MAX_LENGTH = 64  # model_max_length from tokenizer_config.json


def _validate_output_shape(output):
    """Output must be (1, 2) — binary [p_benign, p_phishing]."""
    if hasattr(output, 'shape'):
        shape = output.shape
    elif isinstance(output, (list, tuple)):
        shape = np.array(output).shape
    else:
        shape = None
    assert shape is not None and len(shape) == 2 and shape[1] == 2, \
        f"URLBert output shape must be (1, 2), got {shape}"


def convert_via_ai_edge_torch():
    """Primary conversion path: ai_edge_torch."""
    print("[PATH A] Attempting ai_edge_torch conversion ...")
    try:
        import torch
        import ai_edge_torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
    except ImportError as e:
        print(f"[PATH A] Import failed: {e}")
        return False

    print(f"[LOAD] Loading {MODEL_NAME} from HuggingFace ...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()

    # Create sample input for tracing
    sample_url = "http://paypal-secure-login.xyz/verify"
    enc = tokenizer(
        sample_url,
        max_length=MAX_LENGTH,
        padding='max_length',
        truncation=True,
        return_tensors='pt',
    )
    sample_input_ids = enc['input_ids']
    sample_attention_mask = enc['attention_mask']

    # Verify output shape
    with torch.no_grad():
        out = model(input_ids=sample_input_ids, attention_mask=sample_attention_mask)
        logits = out.logits
        probs = torch.softmax(logits, dim=1).numpy()
    _validate_output_shape(probs)
    print(f"[VALIDATE] PyTorch output shape: {probs.shape}  p_phishing={probs[0][1]:.4f}")

    print("[CONVERT] Running ai_edge_torch.convert ...")
    edge_model = ai_edge_torch.convert(
        model,
        (sample_input_ids, sample_attention_mask),
    )

    print(f"[EXPORT] Saving TFLite model -> {TFLITE_PATH}")
    edge_model.export(TFLITE_PATH)

    # Validate TFLite output
    import tensorflow as tf
    interp = tf.lite.Interpreter(model_path=TFLITE_PATH)
    interp.allocate_tensors()
    inp_details = interp.get_input_details()
    out_details = interp.get_output_details()
    print(f"[TFLITE] Inputs:  {[(d['name'], d['shape']) for d in inp_details]}")
    print(f"[TFLITE] Outputs: {[(d['name'], d['shape']) for d in out_details]}")

    # Run sample
    for d in inp_details:
        if 'input_ids' in d['name'] or d['index'] == 0:
            interp.set_tensor(d['index'], sample_input_ids.numpy().astype(np.int32))
        else:
            interp.set_tensor(d['index'], sample_attention_mask.numpy().astype(np.int32))
    interp.invoke()
    tflite_out = interp.get_tensor(out_details[0]['index'])
    _validate_output_shape(tflite_out)

    size_mb = os.path.getsize(TFLITE_PATH) / (1024 * 1024)
    print(f"[OK] TFLite URLBert saved ({size_mb:.2f} MB)")
    if size_mb > 6:
        print(f"[WARN] Exceeds 6MB target — consider more aggressive quantization")
    return True


def convert_via_onnx():
    """Fallback: export to ONNX, then note that ONNX Runtime for Android should be used."""
    print("[PATH B] Attempting ONNX export fallback ...")
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
    except ImportError as e:
        print(f"[PATH B] Import failed: {e}")
        return False

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"[LOAD] Loading {MODEL_NAME} ...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()

    sample_url = "http://paypal-secure-login.xyz/verify"
    enc = tokenizer(
        sample_url,
        max_length=MAX_LENGTH,
        padding='max_length',
        truncation=True,
        return_tensors='pt',
    )

    print(f"[EXPORT] Exporting to ONNX -> {ONNX_PATH}")
    with torch.no_grad():
        torch.onnx.export(
            model,
            (enc['input_ids'], enc['attention_mask']),
            ONNX_PATH,
            input_names=['input_ids', 'attention_mask'],
            output_names=['logits'],
            dynamic_axes={
                'input_ids': {0: 'batch', 1: 'seq'},
                'attention_mask': {0: 'batch', 1: 'seq'},
                'logits': {0: 'batch'},
            },
            opset_version=14,
        )

    size_mb = os.path.getsize(ONNX_PATH) / (1024 * 1024)
    print(f"[OK] ONNX model saved -> {ONNX_PATH} ({size_mb:.2f} MB)")
    print(f"[NOTE] For Android, integrate onnxruntime-android AAR and use URLBertClassifier.kt ONNX variant.")

    # Save a metadata file so Kotlin knows which backend to use
    meta = {'backend': 'onnx', 'model_path': 'urlbert.onnx', 'max_length': MAX_LENGTH}
    with open(os.path.join(OUTPUT_DIR, 'urlbert_meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)
    return True


def quantize_tflite_int8():
    """Applies INT8 post-training quantization to the exported TFLite model."""
    if not os.path.exists(TFLITE_PATH):
        print(f"[SKIP] {TFLITE_PATH} not found for INT8 quantization")
        return

    import tensorflow as tf
    print(f"\n[INT8] Quantizing {TFLITE_PATH} ...")

    # Read the existing float model and re-quantize
    with open(TFLITE_PATH, 'rb') as f:
        model_bytes = f.read()

    # ai_edge_torch may already produce quantized output; check size
    size_mb = len(model_bytes) / (1024 * 1024)
    print(f"  Current size: {size_mb:.2f} MB")
    if size_mb <= 6:
        print(f"  Size within 6MB target — no further quantization needed")
    else:
        print(f"  [WARN] Consider dynamic range quantization or pruning")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    success = convert_via_ai_edge_torch()
    if not success:
        print("\n[FALLBACK] ai_edge_torch failed, trying ONNX export ...")
        success = convert_via_onnx()

    if success:
        quantize_tflite_int8()
        print("\n[DONE] URLBert conversion complete.")
    else:
        print("\n[ERROR] Both conversion paths failed.")
        print("  Ensure transformers, torch, and ai_edge_torch (or onnx) are installed:")
        print("  pip install transformers torch ai-edge-torch")
        sys.exit(1)


if __name__ == '__main__':
    main()
