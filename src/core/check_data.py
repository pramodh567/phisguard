import pandas as pd
import os

def run_health_check():
    filepath = "data/raw/initial_dataset.csv"
    
    if not os.path.exists(filepath):
        print(f"❌ Error: {filepath} not found. Run data_collector.py first.")
        return
        
    try:
        df = pd.read_csv(filepath)
        print("✅ File loaded successfully.\n")
        print("--- DATASET HEALTH REPORT ---")
        
        # 1. Check Total Rows
        total_rows = len(df)
        print(f"Total Records: {total_rows}")
        
        # 2. Check Class Balance (0 = Benign, 1 = Malicious)
        print("\nClass Distribution:")
        counts = df['label'].value_counts()
        for label, count in counts.items():
            class_name = "Malicious (1)" if label == 1 else "Benign (0)"
            percentage = (count / total_rows) * 100
            print(f"  {class_name}: {count} rows ({percentage:.2f}%)")
            
        # 3. Check for Missing/Null Data
        null_count = df['url'].isnull().sum()
        if null_count > 0:
            print(f"\n⚠️ Warning: Found {null_count} missing URLs.")
        else:
            print("\n✅ No missing URLs detected.")
            
        # 4. Show a sample
        print("\nSample Data (First 3 rows):")
        print(df.head(3))
        
    except Exception as e:
        print(f"❌ Failed to read data: {e}")

if __name__ == "__main__":
    run_health_check()