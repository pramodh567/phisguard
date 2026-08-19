import pandas as pd
import numpy as np
from xgboost import XGBClassifier

def rank_kaggle_features(filepath="../data/raw/kaggle_baseline.csv"):
    print(f"Loading raw dataset from {filepath}...")
    
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print(f"❌ Error: Could not find {filepath}.")
        return

    print(f"Dataset loaded. Found {df.shape[0]} rows and {df.shape[1]} columns.")

    # 1. Define the target 'y'
    if 'type' in df.columns:
        y = df['type'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
    elif 'label' in df.columns:
        y = df['label'].astype(int)
    else:
        print("❌ Error: Target column not found.")
        return

    # 2. DROP THE TARGET COLUMNS FROM X (Fixing Target Leakage)
    cols_to_drop = ['type', 'label', 'url', 'domain', 'id']
    for col in cols_to_drop:
        if col in df.columns:
            df = df.drop(columns=[col])

    # Keep only numeric features for XGBoost
    X = df.select_dtypes(include=[np.number])
    
    print(f"Training XGBoost on {X.shape[1]} numeric features to determine importance...")

    # 3. Train the model
    model = XGBClassifier(
        n_estimators=100, 
        max_depth=6, 
        random_state=42, 
        n_jobs=-1
    )
    model.fit(X, y)

    # 4. Extract and sort feature importances
    importances = model.feature_importances_
    feature_names = X.columns
    
    feat_df = pd.DataFrame({
        'Feature': feature_names, 
        'Importance': importances
    }).sort_values(by='Importance', ascending=False).reset_index(drop=True)

    # 5. Display the Top 25
    print("\n🏆 Top 25 Most Important Features (Determined by AI):")
    print(feat_df.head(25).to_string(index=True))
    
    feat_df.to_csv("master_feature_ranking.csv", index=False)
    print("\n✅ Full ranking saved to 'experiments/master_feature_ranking.csv'")

if __name__ == "__main__":
    rank_kaggle_features()