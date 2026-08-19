import os
import sys
import json
import joblib
import pickle
import pandas as pd
import numpy as np
import tldextract
from sklearn.metrics import confusion_matrix

sys.path.append(os.path.abspath(".."))
from src.core.build_whitelist import TrancoBloomFilter

def run_cascade_simulation():
    print("Loading models, metadata, and Tranco whitelist...")
    tier1_model = joblib.load("../models/phishguard_xgb.pkl")
    tier2_model = joblib.load("../models/phishguard_tier2_xgb.pkl")
    
    with open("../models/features_meta.json", "r") as f:
        t1_feats = json.load(f)["features"]
    with open("../models/tier2_features_meta.json", "r") as f:
        t2_feats = json.load(f)["features"]
        
    with open("../models/tranco_bloom.pkl", "rb") as f:
        tranco_whitelist = pickle.load(f)
        
    print("Loading test dataset...")
    df = pd.read_csv("../data/raw/kaggle_baseline.csv").fillna(0)
    if 'type' in df.columns:
        df['label'] = df['type'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
    
    # Invert abnormal_url if not already inverted
    if 'abnormal_url' in df.columns:
        df['abnormal_url'] = 1 - df['abnormal_url']

    # Sample 3,000 URLs to test real-world throughput
    df_test = df.sample(n=3000, random_state=42).reset_index(drop=True)
    # Explicitly cast to a standard Python integer list to satisfy Pylance
    y_true = list(df_test['label'].astype(int))
    urls = df_test['url'].values if 'url' in df_test.columns else df_test.iloc[:, 0].values

    whitelisted_count = 0
    tier1_only_count = 0
    tier2_count = 0
    final_preds = []

    print(f"Simulating full 3-Tier Pipeline on {len(df_test)} test URLs...\n")

    for i in range(len(df_test)):
        raw_url = str(urls[i])
        row_df = df_test.iloc[[i]]

        # 1. Tranco Whitelist Check
        ext = tldextract.extract(raw_url)
        root_domain = f"{ext.domain}.{ext.suffix}".lower()
        exact_brand_spoof = row_df['phish_adv_exact_brand_match'].values[0] if 'phish_adv_exact_brand_match' in row_df else 0

        if tranco_whitelist.check(root_domain) and exact_brand_spoof == 0:
            whitelisted_count += 1
            final_preds.append(0)  # Safe
            continue

        # 2. Tier 1 Fast Math
        p1 = tier1_model.predict_proba(row_df[t1_feats])[0][1]

        # 3. Tier 2 Escalation (Ambiguity between 20% and 80%)
        if 0.20 <= p1 <= 0.80:
            tier2_count += 1
            p2 = tier2_model.predict_proba(row_df[t2_feats])[0][1]
            final_preds.append(1 if p2 >= 0.50 else 0)
        else:
            tier1_only_count += 1
            final_preds.append(1 if p1 >= 0.50 else 0)

    # Metrics
    # Ensure both arguments are evaluated as standard lists
    cm = confusion_matrix(y_true, list(final_preds))
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    accuracy = float(np.mean(np.array(final_preds) == y_true))

    print("================ PIPELINE SIMULATION RESULTS ================")
    print(f"Total URLs Scanned:          {len(df_test):,}")
    print(f"  ├─ Whitelist Handled:      {whitelisted_count} ({(whitelisted_count/len(df_test))*100:.1f}%) [Instant <0.1ms]")
    print(f"  ├─ Tier 1 Handled:         {tier1_only_count} ({(tier1_only_count/len(df_test))*100:.1f}%) [Fast <5ms]")
    print(f"  └─ Tier 2 Escalations:     {tier2_count} ({(tier2_count/len(df_test))*100:.1f}%) [Deep Inspection]")
    print("-------------------------------------------------------------")
    print(f"Overall Accuracy:            {accuracy * 100:.2f}%")
    print(f"False Positive Rate (FPR):   {fpr * 100:.2f}%")
    print(f"Confusion Matrix:            [TN: {tn:<4} | FP: {fp:<4}]")
    print(f"                             [FN: {fn:<4} | TP: {tp:<4}]")
    print("=============================================================")

if __name__ == "__main__":
    run_cascade_simulation()