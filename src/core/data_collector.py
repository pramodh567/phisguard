import pandas as pd
import requests
import zipfile
import io
import os
import time

# Ensure directories exist
os.makedirs("data/raw", exist_ok=True)

def download_malicious_urls():
    print("Downloading recent malicious URLs from URLhaus (Abuse.ch)...")
    urlhaus_csv_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    
    try:
        response = requests.get(urlhaus_csv_url, timeout=15)
        response.raise_for_status()
        
        # URLHaus CSV has 8 lines of comments at the top starting with #
        with open("data/raw/urlhaus_recent.csv", "wb") as f:
            f.write(response.content)
            
        # Read into Pandas, skipping the comment lines
        df_malicious = pd.read_csv("data/raw/urlhaus_recent.csv", skiprows=8, header=None)
        df_malicious.columns = ['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter']
        
        # Keep only the URL column and label it as 1 (Malicious)
        df_malicious = df_malicious[['url']].copy()
        df_malicious['label'] = 1
        
        print(f"Successfully downloaded {len(df_malicious)} malicious URLs.")
        return df_malicious
        
    except requests.exceptions.RequestException as e:
        print(f"Error downloading URLhaus data: {e}")
        return None

def download_benign_urls():
    print("Downloading Top 1M benign domains from Tranco...")
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    
    try:
        response = requests.get(tranco_url, timeout=30)
        response.raise_for_status()
        
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            # The zip usually contains a single csv file
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                df_benign = pd.read_csv(f, header=None, names=['rank', 'domain'])
                
        # To balance the dataset, we'll take the top 50,000 domains and format them as URLs
        df_benign = df_benign.head(50000).copy()
        # Add https:// to make them look like standard URLs for our feature extractor
        df_benign['url'] = "https://" + df_benign['domain']
        df_benign['label'] = 0
        df_benign = df_benign[['url', 'label']]
        
        print(f"Successfully processed {len(df_benign)} benign URLs.")
        df_benign.to_csv("data/raw/tranco_top_benign.csv", index=False)
        return df_benign
        
    except requests.exceptions.RequestException as e:
        print(f"Error downloading Tranco data: {e}")
        return None

if __name__ == "__main__":
    malicious = download_malicious_urls()
    time.sleep(2) # Respect API limits
    benign = download_benign_urls()
    
    if malicious is not None and benign is not None:
        # Combine them for our initial dataset
        combined_df = pd.concat([malicious, benign], ignore_index=True)
        # Shuffle the dataset
        combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        combined_df.to_csv("data/raw/initial_dataset.csv", index=False)
        print("\nData collection complete. Master file saved to 'data/raw/initial_dataset.csv'.")