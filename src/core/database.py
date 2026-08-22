import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# By default, uses SQLite locally (phishguard.db in project root).
# To use PostgreSQL, set the DATABASE_URL environment variable:
# DATABASE_URL="postgresql://user:password@localhost:5432/phishguard"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ----------------- DATABASE SCHEMAS ----------------- #

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")  # analyst, admin
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scans = relationship("ScanLog", back_populates="user")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Nullable for anonymous/extension scans
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True)
    risk_score = Column(Float, nullable=False)
    decision = Column(String(50), nullable=False)  # SAFE, SUSPICIOUS, MALICIOUS
    tier_executed = Column(String(100), nullable=False)
    latency_ms = Column(Float, nullable=False)
    features_json = Column(Text, nullable=True)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    user = relationship("User", back_populates="scans")


def init_db():
    """Initializes and verifies all database tables."""
    Base.metadata.create_all(bind=engine)