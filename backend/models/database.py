from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from typing import Generator
import os
from dotenv import load_dotenv

load_dotenv()

# Use persistent storage path for Railway deployments
# Falls back to local path for development
def get_database_path():
    """Get database path, preferring persistent storage if available"""
    persistent_path = "/app/data/appsec.db"

    # Check if running in Railway (persistent volume mounted)
    if os.path.exists("/app/data"):
        return f"sqlite:///{persistent_path}"

    # Local development fallback
    return "sqlite:///./appsec.db"

DATABASE_URL = os.getenv("DATABASE_URL", get_database_path())

# Fix for Fly.io/Heroku postgres:// URLs - SQLAlchemy requires postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

def get_db() -> Generator:
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables"""
    from models.models import (
        User, Project, Scan, Vulnerability, ThreatModel, ChatMessage,
        SystemSettings, ApplicationProfile, SuggestedRule, PromptFeedback,
        ArchitectureVersion, ThreatHistory
    )
    Base.metadata.create_all(bind=engine)
