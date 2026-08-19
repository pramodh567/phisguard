import os
import json
import joblib
from collections import Counter
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score, precision_recall_fscore_support
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE

os.makedirs("models", exist_ok=True)

# The exact mathematical features from the Kaggle dataset
TIER1_FEATURES = [
    'abnormal_url', 'path_len', 'url_len', 'domain_len', 'url_entropy', 
    'subdomain_count', 'suspicious_extension', 'phish_brand_mentions', 
    'phish_adv_exact_brand_match', 'phish_urgency_words', 'phish_security_words', 
    'phish_adv_number_count', 'phish_adv_hyphen_count', 'path_underscore_count'
]

def load_tier1_data(filepath="data/raw/kaggle_baseline.csv"):
    print(f"Loading Tier 1 (Math) data directly from {filepath}...")
    df = pd.read_csv(filepath)
    
    if 'type' in df.columns:
        df['label'] = df['type'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
    elif 'label' in df.columns:
        df['label'] = df['label'].astype(int)
        
    # Ensure columns exist, fill NaNs with 0 for safety
    available_features = [f for f in TIER1_FEATURES if f in df.columns]
    
    # Sample 80,000 rows for fast training
    df_sampled = df.sample(n=min(80000, len(df)), random_state=42).fillna(0)

    # FIX: Invert the Kaggle abnormal_url column so 1 = Malicious, 0 = Safe
    if 'abnormal_url' in df_sampled.columns:
        df_sampled['abnormal_url'] = 1 - df_sampled['abnormal_url']
    
    X = df_sampled[available_features]
    y = df_sampled['label']
    
    print(f"Dataset shape: {X.shape[0]} samples, {X.shape[1]} features.")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    print("\nApplying SMOTE balancing on training split...")
    smote = SMOTE(random_state=42)
    resampled = smote.fit_resample(X_train, y_train)
    
    return resampled[0], X_test, resampled[1], y_test, available_features

def evaluate_tier1_model(model, X_test, y_test):
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    accuracy = float(np.mean(preds == y_test))
    
    print(f"\n================ Tier 1 (Math) Evaluation ================")
    print(f"Accuracy:  {accuracy * 100:.2f}% | FPR: {fpr * 100:.2f}%")
    print(f"  [TN: {tn:<6} | FP: {fp:<6}]")
    print(f"  [FN: {fn:<6} | TP: {tp:<6}]")
    print("==========================================================\n")

def run_training_pipeline():
    X_train, X_test, y_train, y_test, feature_names = load_tier1_data()
    
    xgb_model = XGBClassifier(
        n_estimators=250, learning_rate=0.07, max_depth=6, 
        subsample=0.85, colsample_bytree=0.85, random_state=42, n_jobs=-1
    )
    xgb_model.fit(X_train, y_train)
    evaluate_tier1_model(xgb_model, X_test, y_test)
    
    joblib.dump(xgb_model, "models/phishguard_xgb.pkl")
    with open("models/features_meta.json", "w") as f:
        json.dump({"features": feature_names}, f, indent=4)
    print("✅ Tier 1 model saved successfully.")

if __name__ == "__main__":
    run_training_pipeline()