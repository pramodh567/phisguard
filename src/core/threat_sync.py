import os
import sys
import json
import joblib
import shutil
import hashlib
import requests
import csv
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import xgboost as xgb

# Ensure root package imports work seamlessly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.core.feature_extractor import extract_tier1_features

# ----------------- CONFIGURATION & DIRECTORY PATHS ----------------- #
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
TIER1_MODEL_PATH = "models/phishguard_xgb.pkl"
CANDIDATE_MODEL_PATH = "models/phishguard_xgb_candidate.pkl"
META_PATH = "models/features_meta.json"

DATA_DIR = "data"
RAW_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
THREAT_DIR = os.path.join(DATA_DIR, "threat_intel")
ARCHIVE_DIR = os.path.join(THREAT_DIR, "archive")

SEEN_HASHES_FILE = os.path.join(THREAT_DIR, "seen_hashes.json")
MONTHLY_BUFFER_FILE = os.path.join(THREAT_DIR, "monthly_buffer.parquet")
MASTER_TRAIN_FILE = os.path.join(PROCESSED_DIR, "master_train.parquet")
BASELINE_TRAIN_FILE = os.path.join(PROCESSED_DIR, "train.parquet")
BASELINE_TEST_FILE = os.path.join(PROCESSED_DIR, "test.parquet")

# Retraining Threshold
MONTHLY_SAMPLE_TRIGGER = 1000  # Minimum balanced samples required to run full retraining

# Top verified domains for generating realistic, balanced benign URLs
BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "reddit.com", "linkedin.com", "microsoft.com", "apple.com", "github.com",
    "cloudflare.com", "spotify.com", "dropbox.com", "slack.com", "stackoverflow.com",
    "medium.com", "salesforce.com", "zoom.us", "paypal.com", "quora.com",
    "nytimes.com", "bbc.co.uk", "cnn.com", "nih.gov", "harvard.edu",
    "leetcode.com", "takeuforward.org", "mozilla.org", "w3schools.com", "gitlab.com"
]

BENIGN_SUBPATHS = [
    "", "/login", "/home", "/about", "/contact", "/search?q=cybersecurity",
    "/docs/api/v1", "/user/profile", "/checkout/cart", "/help/article/1092",
    "/settings/security", "/explore", "/pricing", "/terms-of-service", "/faq"
]

# Ensure required directory tree exists
os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(THREAT_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)

# ----------------- 1. SHA-256 DEDUPLICATION LAYER ----------------- #
def get_url_hash(url: str) -> str:
    """Computes SHA-256 fingerprint of normalized URL string."""
    return hashlib.sha256(url.strip().lower().encode("utf-8")).hexdigest()

def load_seen_hashes() -> set:
    """Loads all previously seen URL hashes from persistent storage."""
    if os.path.exists(SEEN_HASHES_FILE):
        try:
            with open(SEEN_HASHES_FILE, "r") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_seen_hashes(hashes: set):
    """Saves updated seen hashes registry."""
    with open(SEEN_HASHES_FILE, "w") as f:
        json.dump(list(hashes), f)

# ----------------- 2. INGESTION & DATA BALANCING ----------------- #
def fetch_unique_threat_urls(limit=500) -> list:
    """Downloads URLHaus feed and extracts only brand-new, unique malicious URLs."""
    print("[*] Contacting URLHaus open threat feed...")
    seen_hashes = load_seen_hashes()
    new_urls = []
    
    try:
        response = requests.get(URLHAUS_CSV, timeout=15)
        if response.status_code == 200:
            lines = [l for l in response.text.split('\n') if l and not l.startswith('#')]
            reader = csv.reader(lines)
            for row in reader:
                if len(row) > 2:
                    raw_url = row[2].strip()
                    url_hash = get_url_hash(raw_url)
                    if url_hash not in seen_hashes:
                        new_urls.append(raw_url)
                        seen_hashes.add(url_hash)
                        if len(new_urls) >= limit:
                            break
                            
            save_seen_hashes(seen_hashes)
            print(f"[+] Retrieved {len(new_urls)} UNIQUE zero-day malicious URLs.")
            return new_urls
        else:
            print(f"[-] URLHaus returned HTTP status {response.status_code}.")
    except Exception as e:
        print(f"[-] URLHaus fetch exception: {e}")
    return []

def generate_balanced_benign_urls(count: int) -> list:
    """Generates a structured, balanced set of benign URLs with deduplication."""
    seen_hashes = load_seen_hashes()
    benign_urls = []
    
    for domain in BENIGN_DOMAINS:
        for path in BENIGN_SUBPATHS:
            url = f"https://{domain}{path}"
            url_hash = get_url_hash(url)
            if url_hash not in seen_hashes:
                benign_urls.append(url)
                seen_hashes.add(url_hash)
                if len(benign_urls) >= count:
                    break
        if len(benign_urls) >= count:
            break

    save_seen_hashes(seen_hashes)
    return benign_urls

def ingest_new_threats(feature_cols: list) -> int:
    """Parses incoming threats, pairs them 1:1 with benign samples, and buffers them."""
    malicious = fetch_unique_threat_urls(limit=500)
    if not malicious:
        print("[!] No new unique threat URLs found in this sync pass.")
        return 0

    benign = generate_balanced_benign_urls(len(malicious))
    
    print(f"[*] Extracting mathematical features for {len(malicious) + len(benign)} balanced samples...")
    new_records = []
    for u in malicious:
        try:
            feats = extract_tier1_features(u)
            feats['label'] = 1
            new_records.append(feats)
        except Exception:
            continue
            
    for u in benign:
        try:
            feats = extract_tier1_features(u)
            feats['label'] = 0
            new_records.append(feats)
        except Exception:
            continue

    df_new = pd.DataFrame(new_records).fillna(0)
    for col in feature_cols:
        if col not in df_new.columns:
            df_new[col] = 0

    # Append to staging buffer
    if os.path.exists(MONTHLY_BUFFER_FILE):
        df_existing = pd.read_parquet(MONTHLY_BUFFER_FILE)
        df_total = pd.concat([df_existing, df_new], ignore_index=True)
    else:
        df_total = df_new

    df_total.to_parquet(MONTHLY_BUFFER_FILE)
    print(f"[+] Total balanced samples staged in monthly buffer: {len(df_total)}")
    return len(df_total)

# ----------------- 3. HISTORICAL VAULT INITIALIZATION ----------------- #
def load_or_init_master_vault(feature_cols: list) -> pd.DataFrame:
    """Loads cumulative historical master training data or initializes from baseline files."""
    if os.path.exists(MASTER_TRAIN_FILE):
        df_master = pd.read_parquet(MASTER_TRAIN_FILE)
        print(f"[+] Master Cumulative Vault loaded: {len(df_master)} historical samples.")
        return df_master

    if os.path.exists(BASELINE_TRAIN_FILE):
        df_master = pd.read_parquet(BASELINE_TRAIN_FILE) if BASELINE_TRAIN_FILE.endswith(".parquet") else pd.read_csv(BASELINE_TRAIN_FILE)
        print(f"[+] Initialized Master Vault from baseline train set: {len(df_master)} samples.")
        return df_master

    # Check data/raw/ for raw dataset files
    if os.path.exists(RAW_DIR):
        raw_files = [f for f in os.listdir(RAW_DIR) if f.endswith(('.csv', '.parquet'))]
        if raw_files:
            raw_path = os.path.join(RAW_DIR, raw_files[0])
            print(f"[*] Found raw baseline dataset at '{raw_path}'. Initializing vault...")
            df_raw = pd.read_parquet(raw_path) if raw_path.endswith(".parquet") else pd.read_csv(raw_path)
            
            # If raw file already has extracted features:
            if all(col in df_raw.columns for col in feature_cols[:5]):
                df_master = df_raw
            else:
                # Extract features from raw URL column
                url_col = "url" if "url" in df_raw.columns else df_raw.columns[0]
                label_col = "type" if "type" in df_raw.columns else ("label" if "label" in df_raw.columns else df_raw.columns[1])
                
                print(f"[*] Extracting features from {len(df_raw)} raw Kaggle records (one-time setup)...")
                records = []
                for _, r in df_raw.iterrows():
                    try:
                        f = extract_tier1_features(str(r[url_col]))
                        lbl_val = str(r[label_col]).lower()
                        f['label'] = 0 if lbl_val in ['benign', 'safe', '0'] else 1
                        records.append(f)
                    except Exception:
                        continue
                df_master = pd.DataFrame(records).fillna(0)

            for col in feature_cols:
                if col not in df_master.columns:
                    df_master[col] = 0
            df_master.to_parquet(MASTER_TRAIN_FILE)
            print(f"[+] Master Vault successfully cached at {MASTER_TRAIN_FILE}.")
            return df_master

    print("[!] Notice: No baseline files found in data/raw/ or data/processed/. Master vault starts empty.")
    return pd.DataFrame()

# ----------------- 4. EVALUATION & GUARDRAILS ----------------- #
def evaluate_model(model, X, y) -> dict:
    y_pred = model.predict(X)
    tn, fp, fn, tp = confusion_matrix(y, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "accuracy": accuracy_score(y, y_pred),
        "precision": precision_score(y, y_pred, zero_division=0),
        "recall": recall_score(y, y_pred, zero_division=0),
        "f1": f1_score(y, y_pred, zero_division=0),
        "fpr": fpr
    }

def print_evaluation_comparison(old_m, new_m, title=""):
    print("\n" + "=" * 68)
    print(f"{title:<35} | {'CURRENT PROD':<12} | {'CANDIDATE':<12}")
    print("=" * 68)
    print(f"{'Accuracy':<35} | {old_m['accuracy']*100:>11.2f}% | {new_m['accuracy']*100:>11.2f}%")
    print(f"{'False Positive Rate (FPR)':<35} | {old_m['fpr']*100:>11.2f}% | {new_m['fpr']*100:>11.2f}%")
    print(f"{'Precision (Phishing)':<35} | {old_m['precision']*100:>11.2f}% | {new_m['precision']*100:>11.2f}%")
    print(f"{'Recall (Catch Rate)':<35} | {old_m['recall']*100:>11.2f}% | {new_m['recall']*100:>11.2f}%")
    print("=" * 68)

# ----------------- 5. MONTHLY RETRAINING ENGINE ----------------- #
def run_full_monthly_retraining(feature_cols: list):
    print("\n=======================================================")
    print(f"   PHISHGUARD FULL MODEL RETRAINING ENGINE - {datetime.now().strftime('%Y-%m')}")
    print("=======================================================")

    if not os.path.exists(MONTHLY_BUFFER_FILE):
        print("[-] Abort: No monthly buffer file found to retrain.")
        return

    df_buffer = pd.read_parquet(MONTHLY_BUFFER_FILE)
    print(f"[+] Loaded monthly buffer with {len(df_buffer)} new balanced samples.")

    # 1. Load Master Historical Vault
    df_master = load_or_init_master_vault(feature_cols)

    # 2. Prepare Training and Evaluation Splits
    if not df_master.empty:
        df_full = pd.concat([df_master, df_buffer], ignore_index=True)
    else:
        df_full = df_buffer

    # Load baseline test set or derive stratified holdout
    if os.path.exists(BASELINE_TEST_FILE):
        print(f"[*] Loading baseline test set from {BASELINE_TEST_FILE}...")
        df_test = pd.read_parquet(BASELINE_TEST_FILE) if BASELINE_TEST_FILE.endswith(".parquet") else pd.read_csv(BASELINE_TEST_FILE)
        df_train = df_full
    else:
        print("[*] Creating 80/20 train/validation split for safety evaluation...")
        df_train, df_test = train_test_split(df_full, test_size=0.20, random_state=42, stratify=df_full['label'])

    for col in feature_cols:
        if col not in df_train.columns: df_train[col] = 0
        if col not in df_test.columns: df_test[col] = 0

    X_train, y_train = df_train[feature_cols], df_train['label']
    X_test, y_test = df_test[feature_cols], df_test['label']

    prod_model = joblib.load(TIER1_MODEL_PATH)
    old_metrics = evaluate_model(prod_model, X_test, y_test)

    # 3. Adaptive Hyperparameter Search / Auto-Recovery Loop
    configurations = [
        {"name": "Standard Optimal Retrain", "lr": 0.03, "depth": 6, "lambda": 1.0},
        {"name": "Auto-Recovery 1: High Regularization", "lr": 0.02, "depth": 5, "lambda": 3.0},
        {"name": "Auto-Recovery 2: Conservative Bound", "lr": 0.015, "depth": 5, "lambda": 5.0}
    ]

    candidate_model = None
    passed_guardrails = False

    for cfg in configurations:
        print(f"\n[*] Training full candidate model using [{cfg['name']}] on {len(X_train)} samples...")
        candidate = xgb.XGBClassifier(
            n_estimators=150,
            learning_rate=cfg['lr'],
            max_depth=cfg['depth'],
            reg_lambda=cfg['lambda'],
            subsample=0.85,
            colsample_bytree=0.85,
            random_state=42,
            eval_metric="logloss"
        )
        candidate.fit(X_train, y_train)
        new_metrics = evaluate_model(candidate, X_test, y_test)
        print_evaluation_comparison(old_metrics, new_metrics, title=cfg['name'])

        acc_drop = (old_metrics['accuracy'] - new_metrics['accuracy']) * 100
        fpr_increase = (new_metrics['fpr'] - old_metrics['fpr']) * 100

        # Strict Production Guardrails
        if acc_drop <= 1.5 and fpr_increase <= 1.0:
            print(f"[+] ✅ PASSED all safety criteria on {cfg['name']}.")
            candidate_model = candidate
            passed_guardrails = True
            break
        else:
            print(f"[-] ⚠️ Guardrail violation (Acc Drop: {acc_drop:.2f}%, FPR Rise: {fpr_increase:.2f}%). Attempting next recovery configuration...")

    if not passed_guardrails:
        print("\n[-] Critical: Candidate model failed all auto-recovery attempts.")
        print("[-] Production model retained. Monthly buffer held for review.")
        return

    # 4. Save Backup and Overwrite Production Model
    if os.path.exists(TIER1_MODEL_PATH):
        shutil.copyfile(TIER1_MODEL_PATH, TIER1_MODEL_PATH.replace(".pkl", "_backup.pkl"))
    
    joblib.dump(candidate_model, TIER1_MODEL_PATH) # Directly overwrites active model!
    print(f"\n[+] Candidate model promoted! Production model overwritten at '{TIER1_MODEL_PATH}'.")

    # 5. Compound Master Dataset
    df_full.to_parquet(MASTER_TRAIN_FILE)
    print(f"[+] Master cumulative vault updated: now contains {len(df_full)} total records.")

    # 6. Archive and Reset Monthly Buffer
    archive_path = os.path.join(ARCHIVE_DIR, f"buffer_{datetime.now().strftime('%Y_%m_%d')}.parquet")
    shutil.copyfile(MONTHLY_BUFFER_FILE, archive_path)
    os.remove(MONTHLY_BUFFER_FILE)
    print(f"[+] Monthly buffer archived to '{archive_path}' and reset for next month.")

# ----------------- MAIN DISPATCHER ----------------- #
if __name__ == "__main__":
    with open(META_PATH, "r") as f:
        features = json.load(f)["features"]

    # Step 1: Ingest brand new threats into monthly staging buffer
    buffer_count = ingest_new_threats(features)

    # Step 2: Trigger full retraining once buffer meets target volume
    if buffer_count >= MONTHLY_SAMPLE_TRIGGER:
        run_full_monthly_retraining(features)
    else:
        print(f"[*] Monthly buffer currently has {buffer_count}/{MONTHLY_SAMPLE_TRIGGER} samples. Staging complete.")