from fastapi import APIRouter, Depends, Response, Query
from sqlalchemy.orm import Session
import csv
import io
import math
from src.core.database import SessionLocal, ScanLog
from src.api.auth import get_current_user, User

router = APIRouter(prefix="/api/v1/analyst", tags=["Analyst Dashboard"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# In src/api/dashboard.py, update the default from 50 to 15:
@router.get("/history")
def get_scan_history(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(15, ge=1, le=100, description="Items per page"), # Changed default to 15
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(ScanLog).filter(ScanLog.user_id == current_user.id)
    total_items = query.count()
    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 1

    offset = (page - 1) * page_size
    logs = query.order_by(ScanLog.scanned_at.desc()).offset(offset).limit(page_size).all()
    
    # Aggregated stats for the risk chart
    safe_count = db.query(ScanLog).filter(ScanLog.user_id == current_user.id, ScanLog.decision == "SAFE").count()
    suspicious_count = db.query(ScanLog).filter(ScanLog.user_id == current_user.id, ScanLog.decision == "SUSPICIOUS").count()
    malicious_count = db.query(ScanLog).filter(ScanLog.user_id == current_user.id, ScanLog.decision == "MALICIOUS").count()

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "stats": [safe_count, suspicious_count, malicious_count],
        "logs": [{
            "url": l.url,
            "risk_score": l.risk_score,
            "decision": l.decision,
            "tier_executed": l.tier_executed,
            "scanned_at": l.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
        } for l in logs]
    }

@router.get("/export")
def export_ioc_report(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    logs = db.query(ScanLog).filter(ScanLog.user_id == current_user.id, ScanLog.decision == "MALICIOUS").all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "URL", "Domain", "Risk Score", "Decision"])
    for l in logs:
        writer.writerow([l.scanned_at, l.url, l.domain, l.risk_score, l.decision])
    
    response = Response(content=output.getvalue(), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=phishguard_ioc_report.csv"
    return response