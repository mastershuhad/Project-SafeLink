"""
SafeLink CNN Fine-tuner -- corrects false-positive classifications.

Loads best_model.keras and fine-tunes ALL layers (very low LR) on a small set
of known-safe URLs that the CNN misclassifies, balanced with real phishing URLs.
Uses LR=2e-5 to prevent catastrophic forgetting while allowing the embedding and
conv layers to adjust to the clean-URL feature distribution.

Workflow:
  1. python finetune.py          -> updates models/best_model.keras
  2. python convert_tflite.py    -> produces new models/safelink_model.tflite
  3. Copy safelink_model.tflite  -> android/app/src/main/assets/

Requires the venv_train environment (TensorFlow):
  venv_train\\Scripts\\activate
  python finetune.py
"""

import os, sys, json
import numpy as np
import tensorflow as tf
from tensorflow import keras

sys.path.insert(0, os.path.abspath('.'))
from feature_extractor import extract_feature_vector

SEQ_LEN       = 200
LEARNING_RATE = 2e-5   # low -- prevents catastrophic forgetting while allowing full adjustment
EPOCHS        = 30
BATCH_SIZE    = 8

MODEL_PATH  = 'models/best_model.keras'
SCALER_PATH = 'models/scaler_params.json'

# -- Safe URLs the CNN incorrectly flags as MALICIOUS ------------------
# Add any new false positives here and re-run the script.
SAFE_URLS = [
    # Image / media platforms
    'https://pixabay.com/',
    'https://pixabay.com/photos/',
    'https://pixabay.com/vectors/',
    'https://unsplash.com/',
    'https://pexels.com/',
    'https://freepik.com/',
    'https://flaticon.com/',
    # Productivity / collaboration
    'https://canva.com/',
    'https://figma.com/',
    'https://notion.so/',
    'https://trello.com/',
    'https://airtable.com/',
    'https://miro.com/',
    'https://prezi.com/',
    'https://slideshare.net/',
    # Presentation / classroom
    'https://www.menti.com/',
    'https://menti.com/',
    'https://mentimeter.com/',
    'https://kahoot.com/',
    'https://padlet.com/',
    'https://quizlet.com/',
    'https://wordwall.net/',
    # General clean short domains
    'https://github.io/',
    'https://medium.com/',
    'https://hashnode.com/',
    'https://dev.to/',
]

# -- Real phishing URLs for balance (prevents forgetting) --------------
MALICIOUS_URLS = [
    'http://paypal-secure-login.xyz/verify',
    'http://amazon-account-update.net/login?id=123',
    'http://evil.xyz/www.paypal.com/account/login',
    'https://paypal.com.verify-account.ru',
    'https://amazon-delivery-issue-secure.com/confirm-shipment',
    'https://microsoft365-verify-account.net/login-secure',
    'https://appleid-icloud-security-update.com/verify-device',
    'https://paypal-account-confirmation-urgent.live/secure-login',
    'https://accounts-google-security-alert.com/reset-password',
    'https://irs-gov-tax-refund-claim.com/verify-identity',
    'https://paypa1-secure.com/login',
    'https://arnazon-order-confirm.co',
    'https://g00gle-accounts.com/verify',
    'https://micr0soft-support.net',
    'https://app1e-id.com/icloud',
    'https://faceb00k-security-alert.com',
    'https://amaz0n-prime-delivery.net',
    'https://secure-login-paypal-verification.com/account',
    'https://amazon-package-delay-claim.com/track',
    'https://support-apple.com-verify.com',
    'https://crypto-elon-giveaway.live/claim-reward',
    'https://bankofamerica-login-secure.net',
    'https://whatsapp-verification-update.com',
    'https://netflix-account-verification.com/renew-subscription',
    'https://free-bitcoin-airdrop-bonus.net/claim-now',
    'https://fedex-tracking-update-secure.com/package/confirm',
]


def encode_url(url: str) -> list:
    ids = [max(1, min(99, ord(c) - 31)) for c in url[:SEQ_LEN]]
    ids += [0] * (SEQ_LEN - len(ids))
    return ids


def main():
    tf.random.set_seed(42)
    np.random.seed(42)

    # -- Load scaler ---------------------------------------------------
    with open(SCALER_PATH) as f:
        sp = json.load(f)
    mean_  = np.array(sp['mean'],  dtype=np.float32)
    scale_ = np.array(sp['scale'], dtype=np.float32)

    def scale(raw):
        return (np.array(raw, dtype=np.float32) - mean_) / scale_

    # -- Build fine-tune dataset ---------------------------------------
    print('[DATA] Extracting features...')
    seq_data, num_data, labels = [], [], []

    for url, label in [(u, 0) for u in SAFE_URLS] + [(u, 2) for u in MALICIOUS_URLS]:
        try:
            raw = extract_feature_vector(url)
            seq_data.append(encode_url(url))
            num_data.append(scale(raw))
            labels.append(label)
        except Exception as e:
            print(f'  [SKIP] {url[:60]}: {e}')

    X_seq = np.array(seq_data, dtype=np.int32)
    X_num = np.array(num_data, dtype=np.float32)
    y     = np.array(labels,   dtype=np.int32)
    print(f'       {len(y)} samples: {(y==0).sum()} SAFE  {(y==2).sum()} MALICIOUS')

    # -- Load model ----------------------------------------------------
    if not os.path.exists(MODEL_PATH):
        print(f'[ERROR] {MODEL_PATH} not found. Run trainer.py first.')
        sys.exit(1)

    print(f'[LOAD] {MODEL_PATH}')
    model = keras.models.load_model(MODEL_PATH)

    # -- All layers trainable (very low LR prevents forgetting) --------
    # Frozen backbone was unable to correct false-positive predictions
    # because the dense layers alone can't override the CNN activations.
    # Full fine-tuning with LR=2e-5 allows the embedding + conv to adapt.
    for layer in model.layers:
        layer.trainable = True

    total_params = model.count_params()
    print(f'[TRAIN] All {len(model.layers)} layers trainable  ({total_params:,} params)')

    # -- Compile with very low LR --------------------------------------
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy'],
    )

    # -- Quick pre-training check --------------------------------------
    print('\n[BEFORE] Predictions on false-positive URLs:')
    for url in ['https://pixabay.com/', 'https://www.menti.com/', 'https://canva.com/']:
        raw  = extract_feature_vector(url)
        seq  = np.array([encode_url(url)], dtype=np.int32)
        num  = np.array([scale(raw)],      dtype=np.float32)
        pred = model.predict({'seq_input': seq, 'num_input': num}, verbose=0)[0]
        tag  = 'SAFE' if pred[0] > pred[2] else 'MALICIOUS'
        print(f'  {tag:<9}  p_safe={pred[0]:.3f}  p_mal={pred[2]:.3f}  {url}')

    # -- Fine-tune -----------------------------------------------------
    print(f'\n[TRAIN] Fine-tuning {EPOCHS} epochs  lr={LEARNING_RATE}')
    model.fit(
        {'seq_input': X_seq, 'num_input': X_num},
        y,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.2,
        verbose=1,
    )

    # -- Post-training check -------------------------------------------
    print('\n[AFTER] Predictions on false-positive URLs:')
    for url in ['https://pixabay.com/', 'https://www.menti.com/', 'https://canva.com/',
                # Also verify real phishing still detected
                'http://paypal-secure-login.xyz/verify',
                'https://amazon-package-delay-claim.com/track']:
        raw  = extract_feature_vector(url)
        seq  = np.array([encode_url(url)], dtype=np.int32)
        num  = np.array([scale(raw)],      dtype=np.float32)
        pred = model.predict({'seq_input': seq, 'num_input': num}, verbose=0)[0]
        tag  = 'SAFE' if pred[0] > pred[2] else 'MALICIOUS'
        print(f'  {tag:<9}  p_safe={pred[0]:.3f}  p_mal={pred[2]:.3f}  {url}')

    # -- Save ----------------------------------------------------------
    model.save(MODEL_PATH)
    print(f'\n[SAVE] Updated model -> {MODEL_PATH}')
    print('[NEXT] Run:  python convert_tflite.py')
    print('       Then copy models/safelink_model.tflite -> android/app/src/main/assets/')


if __name__ == '__main__':
    main()
