"""
SafeLink CNN Fine-tuner -- corrects false-positive classifications.

Loads best_model.keras and fine-tunes layers (freezing the Embedding layer) on a
set of known-safe URLs that the CNN misclassifies, balanced with real phishing URLs.
It also reconstructs the original test set to perform a strict regression check,
ensuring that fixing a few FPs doesn't destroy overall model recall.

Workflow:
  1. python finetune.py          -> updates models/best_model.keras
  2. python convert_tflite.py    -> produces new models/safelink_model.tflite
  3. Copy safelink_model.tflite  -> android/app/src/main/assets/

Requires the venv_train environment (TensorFlow):
  venv_train\\Scripts\\activate
  python finetune.py
"""

import os, sys, json, re
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import GroupShuffleSplit
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath('.'))
from feature_extractor import extract_feature_vector, FEATURE_COLUMNS

SEQ_LEN       = 200
LEARNING_RATE = 2e-5   # low -- prevents catastrophic forgetting
EPOCHS        = 30
BATCH_SIZE    = 8

DATA_PATH   = 'data/safelink_dataset.csv'
MODEL_PATH  = 'models/best_model.keras'
SCALER_PATH = 'models/scaler_params.json'

# -- Finetuning Corpus -------------------------------------------------
# Ideally, this should be dynamically loaded from a production false-positive log
# database (e.g., mined from user reports).
SAFE_URLS = [
    'https://pixabay.com/', 'https://pixabay.com/photos/', 'https://pixabay.com/vectors/',
    'https://unsplash.com/', 'https://pexels.com/', 'https://freepik.com/', 'https://flaticon.com/',
    'https://canva.com/', 'https://figma.com/', 'https://notion.so/', 'https://trello.com/',
    'https://airtable.com/', 'https://miro.com/', 'https://prezi.com/', 'https://slideshare.net/',
    'https://www.menti.com/', 'https://menti.com/', 'https://mentimeter.com/', 'https://kahoot.com/',
    'https://padlet.com/', 'https://quizlet.com/', 'https://wordwall.net/',
    'https://github.io/', 'https://medium.com/', 'https://hashnode.com/', 'https://dev.to/',

    # Sri Lankan e-commerce — product paths with model numbers (high path_entropy + digits)
    'https://gqmobiles.lk/', 'https://gqmobiles.lk',
    'https://gqmobiles.lk/xiaomi/xiaomi-15-5g',
    'https://gqmobiles.lk/samsung/samsung-galaxy-a55-5g',
    'https://ikman.lk/', 'https://daraz.lk/', 'https://daraz.lk/products/',
    'https://smartmobile.lk', 'https://smartmobile.lk/',
    'https://ideabeam.com/mobile/', 'https://www.ideabeam.com/mobile/',

    # Tech specs / review sites — model number slugs (samsung_galaxy_a05-12583)
    'https://www.gsmarena.com/', 'https://gsmarena.com/',
    'https://www.gsmarena.com/samsung_galaxy_a05-12583.php',
    'https://www.gsmarena.com/xiaomi_redmi_note_13-12345.php',
    'https://www.phonearena.com/', 'https://www.techradar.com/',

    # Learning platforms — deep paths like /home/my-courses/learning raise path_entropy
    'https://www.udemy.com/', 'https://udemy.com/',
    'https://www.udemy.com/home/my-courses/learning/',
    'https://www.udemy.com/home/my-courses/wishlist/',
    'https://www.udemy.com/course/python-bootcamp/',
    'https://www.coursera.org/', 'https://www.coursera.org/learn/machine-learning',
    'https://www.edx.org/', 'https://www.khanacademy.org/',
    'https://codegym.cc', 'https://codegym.cc/', 'https://codegym.cc/progress',
    'https://codegym.cc/quests/lectures/', 'https://codegym.cc/groups/posts/',

    # Math / developer tools — alphanumeric query params (MG0AV3) spike digit_ratio + entropy
    'https://www.desmos.com/', 'https://www.desmos.com/calculator',
    'https://www.desmos.com/calculator?form=MG0AV3',
    'https://www.wolframalpha.com/', 'https://www.geogebra.org/',
    'https://replit.com/', 'https://codesandbox.io/', 'https://jsfiddle.net/',

    # Hosting / deployment — project hash slugs like /shuhads-projects-4c112c3a
    'https://vercel.com/', 'https://vercel.com/dashboard',
    'https://vercel.com/shuhads-projects-4c112c3a',
    'https://app.netlify.com/', 'https://app.netlify.com/teams/mastershuhadh/projects',
    'https://netlify.app/', 'https://render.com/', 'https://railway.app/',

    # AI / chat tools — short newer domains that look high-entropy to CNN
    'https://chat.deepseek.com', 'https://chat.deepseek.com/',
    'https://deepseek.com/', 'https://claude.ai/', 'https://gemini.google.com/',
    'https://chat.mistral.ai/', 'https://perplexity.ai/',

    # Sri Lankan university portals — .lk paths
    'https://ekel.kln.ac.lk/', 'https://ekel.kln.ac.lk/my/courses.php',
    'https://sis.fct.kln.ac.lk/', 'http://sis.fct.kln.ac.lk/admin/results',
    'https://www.cmb.ac.lk/', 'https://www.pdn.ac.lk/', 'https://www.uom.lk/',

    # SPA banking portals — #/login fragment triggers "login" keyword in CNN char sequence
    'https://www.combankdigital.com/', 'https://www.combankdigital.com/#/login',
    'https://www.combankdigital.com/#/dashboard',

    # ── Sri Lankan Telecom ────────────────────────────────────────────────────
    'https://www.dialog.lk', 'https://www.mobitel.lk', 'https://www.slt.lk',
    'https://www.hutch.lk', 'https://www.airtel.lk',

    # ── Sri Lankan Banks & Fintech ────────────────────────────────────────────
    'https://www.boc.lk', 'https://www.hnb.lk', 'https://www.sampath.lk',
    'https://www.combank.lk', 'https://www.seylan.lk', 'https://www.dfcc.lk',
    'https://www.nsb.lk', 'https://www.lolc.com', 'https://www.amana.lk',
    'https://www.frimi.lk', 'https://www.genie.lk', 'https://www.payhere.lk',
    'https://www.ndbbank.com/', 'https://www.peoplesbank.lk/', 'https://www.nationstrust.com/',
    'https://www.lankapay.net/', 'https://www.pabcbank.com/', 'https://www.mbslbank.com/',
    'https://www.ceybank.com/', 'https://www.flashbank.lk/',

    # ── Sri Lankan Government portals (key ministries & departments) ──────────
    'https://www.gov.lk', 'https://www.elections.gov.lk', 'https://www.police.gov.lk',
    'https://www.customs.gov.lk', 'https://www.ceb.lk', 'https://www.sltb.lk',
    'https://dmt.gov.lk', 'https://dmt.gov.lk/index.php?lang=en',
    'https://www.railway.gov.lk', 'https://slpost.gov.lk', 'https://www.slpa.lk/',
    'https://www.army.lk', 'https://www.airforce.lk',
    'https://www.rda.gov.lk', 'https://www.waterboard.lk/', 'https://www.caa.lk',
    'https://rgd.gov.lk/', 'https://www.rgd.gov.lk', 'https://www.drc.gov.lk',
    'https://ciaboc.gov.lk', 'https://www.slbfe.lk/', 'https://labourmin.gov.lk/',
    'https://www.meteo.gov.lk', 'https://www.statistics.gov.lk',
    'https://documents.gov.lk/en/gazette.php', 'https://results.exams.gov.lk',

    # ── Sri Lankan News & Media ───────────────────────────────────────────────
    'https://www.adaderana.lk', 'https://www.adaderana.lk/', 'https://www.lankadeepa.lk',
    'https://www.divaina.lk', 'https://www.mawbima.lk', 'https://www.dailymirror.lk',
    'https://www.sundaytimes.lk', 'https://www.newsfirst.lk', 'https://www.island.lk',
    'https://www.ceylontoday.lk', 'https://www.dailynews.lk', 'https://www.sirasa.lk',
    'https://rupavahini.lk/', 'https://www.gossiplanka.com', 'https://www.lankacnews.com',

    # ── Sri Lankan E-Commerce & Shopping ─────────────────────────────────────
    'https://www.kapruka.com', 'https://www.singer.lk', 'https://www.glomark.lk',
    'https://www.keells.lk', 'https://www.cargillsceylon.com', 'https://www.laugfs.lk',
    'https://www.hitad.lk', 'https://www.riyasewana.com',
    'https://buyabans.com/', 'https://petta.lk/', 'https://www.unitedmotors.lk/',
    'https://www.mybookshop.lk', 'https://www.idealz.lk',

    # ── Sri Lankan Education ──────────────────────────────────────────────────
    'https://www.sliit.lk', 'https://www.nibm.lk', 'https://www.iit.ac.lk',
    'https://www.esoft.lk', 'https://www.slim.lk', 'https://www.nsbm.ac.lk/',
    'https://www.sjp.ac.lk', 'https://www.ugc.ac.lk', 'https://www.kdu.ac.lk',
    'https://www.jfn.ac.lk', 'https://www.sab.ac.lk', 'https://www.wyb.ac.lk',
    'https://www.doenets.lk', 'https://doenets.lk/',

    # ── Sri Lankan Travel & Transport ─────────────────────────────────────────
    'https://www.srilankan.com', 'https://www.airport.lk', 'https://www.pickme.lk',
    'https://www.srilanka.travel', 'https://www.jetwinghotels.com/',
    'https://www.aitkenspenceholidays.com',

    # ── Sri Lankan Health ─────────────────────────────────────────────────────
    'https://www.echannelling.com/', 'https://www.nawaloka.com',
    'https://www.asirihospitals.com', 'https://www.lankahospitals.lk',
    'https://www.durdanshospital.com', 'https://www.1990.lk/',

    # ── Sri Lankan Insurance ──────────────────────────────────────────────────
    'https://www.ceylinco-insurance.com', 'https://www.srilankainsurance.com',
    'https://www.aia.lk', 'https://www.allianz.lk', 'https://unionassurance.com/',

    # ── Sri Lankan Tech & IT ──────────────────────────────────────────────────
    'https://www.wso2.com', 'https://www.virtusa.com/', 'https://www.icta.lk',
    'https://www.hsenid.com', 'https://www.zone24x7.com', 'https://www.mitesp.com/',

    # ── Sri Lankan Jobs & HR ──────────────────────────────────────────────────
    'https://www.topjobs.lk', 'https://www.jobs.lk', 'https://www.lankajobs.com',
    'https://www.xpress.jobs/',

    # ── Sri Lankan Utilities, Payments & Registry ─────────────────────────────
    'https://www.mybill.lk', 'https://www.quickpay.lk',
    'https://www.domains.lk', 'https://www.nic.lk',

    # ── Sri Lankan Entertainment & Culture ───────────────────────────────────
    'https://www.helakuru.lk', 'https://www.helakuru.lk/',
    'https://song.lk/', 'https://www.sinhalalyrics.lk', 'https://www.gossip.lk',

    # ── Sri Lankan Finance & Regulatory ──────────────────────────────────────
    'https://www.cse.lk', 'https://www.sec.gov.lk/', 'https://www.ircsl.gov.lk',

    # ── Sri Lankan Food & Delivery ────────────────────────────────────────────
    'https://www.kfc.lk', 'https://www.pizzahut.lk', 'https://www.dominos.lk',
]

MALICIOUS_URLS = [
    'http://paypal-secure-login.xyz/verify', 'http://amazon-account-update.net/login?id=123',
    'http://evil.xyz/www.paypal.com/account/login', 'https://paypal.com.verify-account.ru',
    'https://amazon-delivery-issue-secure.com/confirm-shipment', 'https://microsoft365-verify-account.net/login-secure',
    'https://appleid-icloud-security-update.com/verify-device', 'https://paypal-account-confirmation-urgent.live/secure-login',
    'https://accounts-google-security-alert.com/reset-password', 'https://irs-gov-tax-refund-claim.com/verify-identity',
    'https://paypa1-secure.com/login', 'https://arnazon-order-confirm.co', 'https://g00gle-accounts.com/verify',
    'https://micr0soft-support.net', 'https://app1e-id.com/icloud', 'https://faceb00k-security-alert.com',
    'https://amaz0n-prime-delivery.net', 'https://secure-login-paypal-verification.com/account',
    'https://amazon-package-delay-claim.com/track', 'https://support-apple.com-verify.com',
    'https://crypto-elon-giveaway.live/claim-reward', 'https://bankofamerica-login-secure.net',
    'https://whatsapp-verification-update.com', 'https://netflix-account-verification.com/renew-subscription',
    'https://free-bitcoin-airdrop-bonus.net/claim-now', 'https://fedex-tracking-update-secure.com/package/confirm',
]


def encode_url(url: str) -> list:
    ids = [max(1, min(99, ord(c) - 31)) for c in url[:SEQ_LEN]]
    ids += [0] * (SEQ_LEN - len(ids))
    return ids


def load_regression_test_set(mean_, scale_):
    """Reconstructs the exact test set from trainer.py to monitor regression drops."""
    if not os.path.exists(DATA_PATH):
        print(f"[WARN] {DATA_PATH} not found. Skipping regression testing.")
        return None, None, None

    print(f"[TEST SET] Reconstructing test split from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df = df[df['label'].isin([0, 2])].copy()

    X_num = df[FEATURE_COLUMNS].values.astype(np.float32)
    X_seq = np.array([encode_url(str(url)) for url in df['url']], dtype=np.int32)
    y = df['label'].values.astype(np.int32)

    def get_host(u):
        try:
            h = urlparse(u if '://' in u else 'http://' + u).netloc.split(':')[0].lower()
            return re.sub(r'^www\.', '', h)
        except Exception:
            return u

    groups = np.array([get_host(str(u)) for u in df['url']])

    # EXACT same split logic as trainer.py
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, tmp_idx = next(gss1.split(X_seq, y, groups))

    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=42)
    val_idx, test_idx = next(gss2.split(X_seq[tmp_idx], y[tmp_idx], groups[tmp_idx]))

    final_test_idx = tmp_idx[test_idx]

    X_num_test = (X_num[final_test_idx] - mean_) / scale_
    return X_seq[final_test_idx], X_num_test, y[final_test_idx]


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

    X_seq_test, X_num_test, y_test = load_regression_test_set(mean_, scale_)

    # -- Build fine-tune dataset ---------------------------------------
    print('\n[DATA] Extracting features for fine-tuning corpus...')
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
    print(f'       {len(y)} finetune samples: {(y==0).sum()} SAFE  {(y==2).sum()} MALICIOUS')

    # -- Load model ----------------------------------------------------
    if not os.path.exists(MODEL_PATH):
        print(f'[ERROR] {MODEL_PATH} not found. Run trainer.py first.')
        sys.exit(1)

    print(f'\n[LOAD] {MODEL_PATH}')
    model = keras.models.load_model(MODEL_PATH)

    # -- Freeze Embedding Layer ----------------------------------------
    # Freezing the embedding layer prevents massive shifts in the latent space 
    # and reduces the risk of catastrophic forgetting across the broader vocabulary.
    for layer in model.layers:
        if isinstance(layer, keras.layers.Embedding):
            layer.trainable = False
            print(f"  [FREEZE] Frozen {layer.name} to prevent catastrophic forgetting")
        else:
            layer.trainable = True

    total_params = model.count_params()
    print(f'[TRAIN] {len(model.layers)} layers ({total_params:,} total params)')

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy'],
    )

    # -- Quick pre-training check --------------------------------------
    if X_seq_test is not None:
        print('\n[BEFORE] Regression check on original test set:')
        loss, acc = model.evaluate({'seq_input': X_seq_test, 'num_input': X_num_test}, y_test, verbose=0)
        print(f"  Test Accuracy: {acc:.4f}  Test Loss: {loss:.4f}")

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
    if X_seq_test is not None:
        print('\n[AFTER] Regression check on original test set:')
        loss_new, acc_new = model.evaluate({'seq_input': X_seq_test, 'num_input': X_num_test}, y_test, verbose=0)
        print(f"  Test Accuracy: {acc_new:.4f} (Change: {acc_new - acc:+.4f})  Test Loss: {loss_new:.4f}")
        if (acc - acc_new) > 0.01:
            print("  [WARN] Severe regression detected! >1% drop in overall accuracy.")

    print('\n[AFTER] Predictions on false-positive URLs:')
    for url in [
        # original corpus
        'https://pixabay.com/', 'https://www.menti.com/', 'https://canva.com/',
        # newly added real-world false positives
        'https://gqmobiles.lk/xiaomi/xiaomi-15-5g',
        'https://www.udemy.com/home/my-courses/learning/',
        'https://www.desmos.com/calculator?form=MG0AV3',
        'https://vercel.com/shuhads-projects-4c112c3a',
        'https://www.gsmarena.com/samsung_galaxy_a05-12583.php',
        'https://codegym.cc/progress',
        'https://chat.deepseek.com/',
        'https://www.combankdigital.com/#/login',
        # Sri Lankan legitimate — new additions
        'https://www.boc.lk', 'https://www.seylan.lk',
        'https://dmt.gov.lk/index.php?lang=en',
        'https://www.echannelling.com/',
        'https://www.ceylinco-insurance.com',
        'https://www.1990.lk/',
        'https://song.lk/',
        # must still catch phishing
        'http://paypal-secure-login.xyz/verify',
        'https://amazon-package-delay-claim.com/track',
        'https://app1e-id.com/icloud',
    ]:
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
