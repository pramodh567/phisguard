import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix

def run_cascade_simulation():
    print("Loading aligned models and metadata...")
    tier1_model = joblib.load("../models/phishguard_xgb.pkl")
    tier2_model = joblib.load("../models/phishguard_tier2_xgb.pkl")
    
    with open("../models/features_meta.json", "r") as f:
        t1_feats = json.load(f)["features"]
    with open("../models/tier2_features_meta.json", "r") as f:
        t2_feats = json.load(f)["features"]
        
    print("Loading test data...")
    df = pd.read_csv("../data/raw/kaggle_baseline.csv").fillna(0)
    if 'type' in df.columns:
        df['label'] = df['type'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
    
    # Sample 2,000 URLs to simulate live traffic
    df_test = df.sample(n=2000, random_state=42).reset_index(drop=True)
    y_true = df_test['label'].values
    
    # Bulk predict for simulation speed
    p1_probs = tier1_model.predict_proba(df_test[t1_feats])[:, 1]
    p2_probs = tier2_model.predict_proba(df_test[t2_feats])[:, 1]
    
    t1_preds, cascade_preds = [], []
    escalated_count = 0
    
    for i in range(len(y_true)):
        p1 = p1_probs[i]
        t1_preds.append(1 if p1 >= 0.5 else 0)
        
        # CASCADE LOGIC: Ambiguous zone between 20% and 80%
        if 0.20 <= p1 <= 0.80:
            escalated_count += 1
            p2 = p2_probs[i]
            cascade_preds.append(1 if p2 >= 0.5 else 0)
        else:
            cascade_preds.append(1 if p1 >= 0.5 else 0)
            
    print(f"\n-> Tier 1 handled securely: {len(y_true) - escalated_count} URLs")
    print(f"-> Escalated to Tier 2 (Deep Inspector): {escalated_count} URLs ({(escalated_count/len(y_true))*100:.1f}%)")
    
    def get_metrics(true_y, pred_y, name):
        cm = confusion_matrix(true_y, pred_y)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        acc = float(np.mean(np.array(pred_y) == np.array(true_y)))
        print(f"\n--- {name} ---")
        print(f"Accuracy: {acc * 100:.2f}% | FPR: {fpr * 100:.2f}%")
        print(f"[TN: {tn:<4} | FP: {fp:<4}]")
        print(f"[FN: {fn:<4} | TP: {tp:<4}]")

    get_metrics(y_true, t1_preds, "Pure Tier 1 (Math Only)")
    get_metrics(y_true, cascade_preds, "Full Cascade Architecture (Model 1 + Model 2)")

if __name__ == "__main__":
    run_cascade_simulation()