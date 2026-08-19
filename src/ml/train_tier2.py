import os
import json
import joblib
from collections import Counter
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE

# Import the exact Math features from train.py so they never get out of sync
from train import TIER1_FEATURES

TIER2_NETWORK_FEATURES = [
    'web_unique_domains', 'web_security_score', 'web_hsts', 
    'web_xframe', 'web_http_status', 'web_is_live'
]

def load_tier2_data(filepath="data/raw/kaggle_baseline.csv"):
    print(f"Loading Tier 2 (Math + Network) data directly from {filepath}...")
    df = pd.read_csv(filepath)
    
    if 'type' in df.columns:
        df['label'] = df['type'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
    elif 'label' in df.columns:
        df['label'] = df['label'].astype(int)
        
    combined_features = TIER1_FEATURES + TIER2_NETWORK_FEATURES
    available_features = [f for f in combined_features if f in df.columns]
    
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

def evaluate_tier2_model(model, X_test, y_test):
    preds = model.predict(X_test)
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    accuracy = float(np.mean(preds == y_test))
    
    print(f"\n================ Tier 2 (Math + Network) Evaluation ================")
    print(f"Accuracy:  {accuracy * 100:.2f}% | FPR: {fpr * 100:.2f}%")
    print(f"  [TN: {tn:<6} | FP: {fp:<6}]")
    print(f"  [FN: {fn:<6} | TP: {tp:<6}]")
    print("====================================================================\n")

def run_tier2_pipeline():
    X_train, X_test, y_train, y_test, feature_names = load_tier2_data()
    
    xgb_model = XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=7, 
        subsample=0.85, colsample_bytree=0.85, random_state=42, n_jobs=-1
    )
    xgb_model.fit(X_train, y_train)
    evaluate_tier2_model(xgb_model, X_test, y_test)
    
    joblib.dump(xgb_model, "models/phishguard_tier2_xgb.pkl")
    with open("models/tier2_features_meta.json", "w") as f:
        json.dump({"features": feature_names}, f, indent=4)
    print("✅ Tier 2 model saved successfully.")

if __name__ == "__main__":
    run_tier2_pipeline()