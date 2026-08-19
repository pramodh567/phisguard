import os
import sys
import time
import json
import joblib
import pickle
import tldextract
import pandas as pd
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.core.feature_extractor import extract_tier1_features, extract_tier2_features
from src.core.build_whitelist import TrancoBloomFilter

app = FastAPI(title="PhishGuard Security Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Models & Whitelist
try:
    tier1_model = joblib.load("models/phishguard_xgb.pkl")
    with open("models/features_meta.json", "r") as f:
        tier1_features = json.load(f)["features"]

    tier2_model = joblib.load("models/phishguard_tier2_xgb.pkl")
    with open("models/tier2_features_meta.json", "r") as f:
        tier2_features = json.load(f)["features"]
        
    # --- THE CLEAN FIX FOR PICKLE & PYLANCE ---
    import __main__
    from src.core.build_whitelist import TrancoBloomFilter
    setattr(__main__, "TrancoBloomFilter", TrancoBloomFilter)
    # ------------------------------------------
    
    with open("models/tranco_bloom.pkl", "rb") as f:
        tranco_whitelist = pickle.load(f)
        
    print("✅ Models and Tranco Whitelist successfully loaded.")
except Exception as e:
    print(f"⚠️ Startup Error: {e}")

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    is_phishing: bool
    risk_score: float
    decision: str
    tier_executed: str
    latency_ms: float
    features_breakdown: Dict[str, Any]

@app.post("/api/v1/scan", response_model=URLScanResponse)
def scan_url(request: URLScanRequest):
    start_time = time.time()
    raw_url = request.url.strip()

    # 1. BLOOM FILTER WHITELIST CHECK
    ext = tldextract.extract(raw_url)
    root_domain = f"{ext.domain}.{ext.suffix}".lower()
    
    t1_extracted = extract_tier1_features(raw_url)
    
    # If the domain is in the top 1M globally AND it's not a subdomain brand hijack (e.g., paypal.attacker.com)
    if tranco_whitelist.check(root_domain) and t1_extracted['phish_adv_exact_brand_match'] == 0:
        return URLScanResponse(
            url=raw_url,
            is_phishing=False,
            risk_score=1.0, # 1% baseline risk
            decision="SAFE",
            tier_executed="Tranco Whitelist Pre-Filter",
            latency_ms=round((time.time() - start_time) * 1000, 2),
            features_breakdown=t1_extracted
        )

    # 2. TIER 1 MATH
    t1_df = pd.DataFrame([t1_extracted])[tier1_features]
    t1_prob = float(tier1_model.predict_proba(t1_df)[0][1])
    
    tier_used = "Tier 1 (Instant Math)"
    final_prob = t1_prob
    combined_features = t1_extracted.copy()

    # 3. TIER 2 ESCALATION (Ambiguity 20% to 80%)
    if 0.20 <= t1_prob <= 0.80:
        tier_used = "Tier 2 (Deep Inspector)"
        combined_features.update(extract_tier2_features(raw_url, timeout=2.0))
        t2_df = pd.DataFrame([combined_features])[tier2_features]
        final_prob = float(tier2_model.predict_proba(t2_df)[0][1])

    # 4. FINAL DECISION
    if final_prob < 0.25:
        decision_label = "SAFE"
    elif final_prob < 0.65:
        decision_label = "SUSPICIOUS"
    else:
        decision_label = "MALICIOUS"

    return URLScanResponse(
        url=raw_url,
        is_phishing=final_prob >= 0.50,
        risk_score=round(final_prob * 100, 2),
        decision=decision_label,
        tier_executed=tier_used,
        latency_ms=round((time.time() - start_time) * 1000, 2),
        features_breakdown={
            "abnormal_url": combined_features.get("abnormal_url", 0),
            "exact_brand_spoof": combined_features.get("phish_adv_exact_brand_match", 0),
            "entropy": combined_features.get("url_entropy", 0.0)
        }
    )