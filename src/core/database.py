import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# Environment-aware Database URL
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./phishguard.db" # Default fallback for local testing
)

# Connect configuration based on DB type
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    # PostgreSQL Production Pool Config
    engine = create_engine(
        DATABASE_URL, 
        pool_pre_ping=True, 
        pool_size=10, 
        max_overflow=20
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ----------------- DATABASE MODELS ----------------- #
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanLog", back_populates="user", cascade="all, delete-orphan")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    url = Column(Text, nullable=False)
    verdict = Column(String(20), nullable=False)        # SAFE / SUSPICIOUS / MALICIOUS
    confidence = Column(Float, nullable=False)
    latency_ms = Column(Float, nullable=False)
    scan_type = Column(String(20), default="TIER1")     # TIER1 / TIER2 / WHITELIST
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")

# ----------------- DATABASE HELPERS ----------------- #
def init_db():
    """Creates database tables if they do not exist."""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Database session dependency for FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()