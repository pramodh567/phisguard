import os
import math
import hashlib
import pickle

os.makedirs("models", exist_ok=True)

class TrancoBloomFilter:
    """A lightweight, zero-dependency Bloom Filter using SHA-256."""
    def __init__(self, expected_items: int, fp_rate: float = 0.001):
        self.size = self._get_size(expected_items, fp_rate)
        self.hash_count = self._get_hash_count(self.size, expected_items)
        self.bit_array = bytearray((self.size + 7) // 8)
        
    def _get_size(self, n: int, p: float) -> int:
        return int(-(n * math.log(p)) / (math.log(2) ** 2))
        
    def _get_hash_count(self, m: int, n: int) -> int:
        return int((m / n) * math.log(2))
        
    def add(self, item: str):
        for i in range(self.hash_count):
            digest = hashlib.sha256(f"{item}{i}".encode('utf8')).hexdigest()
            index = int(digest, 16) % self.size
            self.bit_array[index // 8] |= (1 << (index % 8))
            
    def check(self, item: str) -> bool:
        for i in range(self.hash_count):
            digest = hashlib.sha256(f"{item}{i}".encode('utf8')).hexdigest()
            index = int(digest, 16) % self.size
            if not (self.bit_array[index // 8] & (1 << (index % 8))):
                return False
        return True

def build_bloom_from_local_file(csv_path: str = "data/raw/top-1m.csv", output_path: str = "models/tranco_bloom.pkl"):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Could not find '{csv_path}'. Please place the Tranco CSV in 'data/raw/'.")

    print(f"Reading Tranco list from {csv_path}...")
    
    # 1.2M capacity with 0.1% False Positive Rate
    bloom = TrancoBloomFilter(expected_items=1200000, fp_rate=0.001)
    
    count = 0
    with open(csv_path, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 2:
                domain = parts[1].strip().lower()
                bloom.add(domain)
                count += 1

    with open(output_path, "wb") as f:
        pickle.dump(bloom, f)
        
    print(f"✅ Added {count:,} domains to Bloom Filter.")
    print(f"Filter size: {len(bloom.bit_array) / (1024 * 1024):.2f} MB")
    print(f"Saved artifact to '{output_path}'.")

if __name__ == "__main__":
    build_bloom_from_local_file()