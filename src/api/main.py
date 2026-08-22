from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends
import os
import sys
import time
import json
import joblib
from datetime import datetime
import pickle
import tldextract
import pandas as pd
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.core.feature_extractor import extract_tier1_features, extract_tier2_features
from src.core.build_whitelist import TrancoBloomFilter
from src.core.database import SessionLocal, ScanLog, init_db
from src.api.auth import router as auth_router, get_optional_user, get_db
from src.api.dashboard import router as dashboard_router

app = FastAPI(title="PhishGuard Security Engine")
app.include_router(auth_router)
app.include_router(dashboard_router)

@app.get("/login", include_in_schema=False)
def serve_login_page():
    return FileResponse("frontend/login.html")

@app.get("/dashboard", include_in_schema=False)
def serve_dashboard_page():
    return FileResponse("frontend/dashboard.html")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- STARTUP LIFECYCLE ----------------- #
@app.on_event("startup")
def on_startup():
    init_db()
    print("✅ Database tables verified and initialized.")

try:
    tier1_model = joblib.load("models/phishguard_xgb.pkl")
    with open("models/features_meta.json", "r") as f:
        tier1_features = json.load(f)["features"]

    tier2_model = joblib.load("models/phishguard_tier2_xgb.pkl")
    with open("models/tier2_features_meta.json", "r") as f:
        tier2_features = json.load(f)["features"]

    import __main__
    setattr(__main__, "TrancoBloomFilter", TrancoBloomFilter)

    with open("models/tranco_bloom.pkl", "rb") as f:
        tranco_whitelist = pickle.load(f)

    print("✅ Models and Tranco Whitelist successfully loaded.")
except Exception as e:
    print(f"⚠️ Startup Error: {e}")

# ----------------- ASYNC LOGGING TASK ----------------- #
def log_scan_to_database(scan_data: dict, user_id: Optional[int] = None):
    """Executes in background; discards duplicate inserts within 20 seconds."""
    db = SessionLocal()
    try:
        # Backend Deduplication Guard
        if user_id:
            recent_log = db.query(ScanLog).filter(
                ScanLog.user_id == user_id,
                ScanLog.url == scan_data["url"]
            ).order_by(ScanLog.scanned_at.desc()).first()

            if recent_log:
                time_diff = (datetime.utcnow() - recent_log.scanned_at).total_seconds()
                if time_diff < 20:
                    return  # Skip duplicate write to the database

        ext = tldextract.extract(scan_data["url"])
        domain = f"{ext.domain}.{ext.suffix}".lower()
        
        log_entry = ScanLog(
            user_id=user_id,
            url=scan_data["url"],
            domain=domain,
            risk_score=scan_data["risk_score"],
            decision=scan_data["decision"],
            tier_executed=scan_data["tier_executed"],
            latency_ms=scan_data["latency_ms"],
            features_json=json.dumps(scan_data.get("features_breakdown", {}))
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        print(f"Background Logging Error: {e}")
    finally:
        db.close()

# ----------------- SCHEMAS ----------------- #
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

# ----------------- SCAN ENDPOINT ----------------- #
@app.post("/api/v1/scan", response_model=URLScanResponse)
def scan_url(request: URLScanRequest, background_tasks: BackgroundTasks, req: Request, db: Session = Depends(get_db)):
    start_time = time.time()
    raw_url = request.url.strip()

    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Get the user ID if the extension sent a token
    user = get_optional_user(req, db)
    user_id = getattr(user, "id") if user else None

    # 1. Tranco Whitelist Pre-Filter
    ext = tldextract.extract(raw_url)
    root_domain = f"{ext.domain}.{ext.suffix}".lower()
    t1_extracted = extract_tier1_features(raw_url)

    if tranco_whitelist.check(root_domain) and t1_extracted['phish_adv_exact_brand_match'] == 0:
        elapsed = round((time.time() - start_time) * 1000, 2)
        response_payload = {
            "url": raw_url,
            "is_phishing": False,
            "risk_score": 1.0,
            "decision": "SAFE",
            "tier_executed": "Tranco Whitelist Pre-Filter",
            "latency_ms": elapsed,
            "features_breakdown": t1_extracted
        }
        background_tasks.add_task(log_scan_to_database, response_payload, user_id)
        return URLScanResponse(**response_payload)

    # 2. Tier 1 Fast Math Inference
    t1_df = pd.DataFrame([t1_extracted])[tier1_features]
    t1_prob = float(tier1_model.predict_proba(t1_df)[0][1])

    tier_used = "Tier 1 (Instant Math)"
    final_prob = t1_prob
    combined_features = t1_extracted.copy()

    # 3. Tier 2 Escalation (20% to 80% ambiguity)
    if 0.20 <= t1_prob <= 0.80:
        tier_used = "Tier 2 (Deep Inspector)"
        combined_features.update(extract_tier2_features(raw_url, timeout=0.35))
        t2_df = pd.DataFrame([combined_features])[tier2_features]
        final_prob = float(tier2_model.predict_proba(t2_df)[0][1])

    # 4. Final Decision Mapping
    if final_prob < 0.25:
        decision_label = "SAFE"
    elif final_prob < 0.50:
        decision_label = "SUSPICIOUS"
    else:
        decision_label = "MALICIOUS"

    elapsed = round((time.time() - start_time) * 1000, 2)
    response_payload = {
        "url": raw_url,
        "is_phishing": final_prob >= 0.50,
        "risk_score": round(final_prob * 100, 2),
        "decision": decision_label,
        "tier_executed": tier_used,
        "latency_ms": elapsed,
        "features_breakdown": combined_features
    }

    background_tasks.add_task(log_scan_to_database, response_payload, user_id)
    return URLScanResponse(**response_payload)