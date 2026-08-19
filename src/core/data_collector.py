import os
import pandas as pd
import requests

os.makedirs("data/raw", exist_ok=True)

def get_live_trends():
    """Fetches real-time, zero-day malicious URLs from URLhaus."""
    print("1. Fetching LIVE zero-day threats from URLhaus...")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        with open("data/raw/urlhaus.csv", "wb") as f:
            f.write(response.content)
            
        df = pd.read_csv("data/raw/urlhaus.csv", skiprows=8, header=None)
        # The URL is in column index 2
        df = df[[2]].rename(columns={2: 'url'})
        df['label'] = 1
        print(f"   -> Gathered {len(df)} live malicious URLs.")
        return df
    except Exception as e:
        print(f"   -> Warning: Could not fetch live data ({e}). Continuing with baseline.")
        return pd.DataFrame()

def get_local_baseline():
    """Reads the Kaggle dataset located in data/raw/kaggle_baseline.csv."""
    print("2. Reading LOCAL baseline dataset from 'data/raw/kaggle_baseline.csv'...")
    filepath = "data/raw/kaggle_baseline.csv"
    
    if not os.path.exists(filepath):
        print(f"   -> ERROR: File not found at '{filepath}'. Please verify the location.")
        return pd.DataFrame()
        
    try:
        df = pd.read_csv(filepath)
        
        # Determine URL and label column names
        url_col = 'url' if 'url' in df.columns else df.columns[0]
        
        if 'type' in df.columns:
            df['label'] = df['type'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
        elif 'label' in df.columns:
            df['label'] = df['label'].astype(int)
        else:
            print("   -> ERROR: Could not find 'type' or 'label' column in baseline dataset.")
            return pd.DataFrame()
            
        df = df[[url_col, 'label']].rename(columns={url_col: 'url'})
        
        # Sample realistic baseline (50,000 Benign, 25,000 Malicious)
        benign = df[df['label'] == 0]
        malicious = df[df['label'] == 1]
        
        n_benign = min(50000, len(benign))
        n_malicious = min(25000, len(malicious))
        
        sampled_benign = benign.sample(n=n_benign, random_state=42)
        sampled_malicious = malicious.sample(n=n_malicious, random_state=42)
        
        print(f"   -> Sampled {len(sampled_benign)} safe and {len(sampled_malicious)} malicious baseline URLs.")
        return pd.concat([sampled_benign, sampled_malicious])
    except Exception as e:
        print(f"   -> ERROR reading baseline data: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    live_df = get_live_trends()
    base_df = get_local_baseline()
    
    if not base_df.empty:
        print("\n3. Merging datasets into Master Training File...")
        final_df = pd.concat([base_df, live_df], ignore_index=True)
        final_df = final_df.dropna().drop_duplicates(subset=['url']).sample(frac=1, random_state=42).reset_index(drop=True)
        
        output_path = "data/raw/initial_dataset.csv"
        final_df.to_csv(output_path, index=False)
        print(f"✅ Dataset prepared successfully: {len(final_df)} unique records saved to '{output_path}'.")
        print("\nClass breakdown:")
        print(final_df['label'].value_counts())
    else:
        print("\n❌ Pipeline aborted. Please check 'data/raw/kaggle_baseline.csv'.")