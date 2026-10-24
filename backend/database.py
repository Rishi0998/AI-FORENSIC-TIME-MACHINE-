"""
Database setup using SQLAlchemy with async SQLite.
Stores parsed log events, analysis results, and attack chains.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

default_db = "sqlite:////tmp/forensics.db" if os.getenv("VERCEL") else "sqlite:///./forensics.db"
DATABASE_URL = os.getenv("DATABASE_URL", default_db)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency that provides a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all database tables."""
    from models.event import Event, AnalysisResult, AttackChain  # noqa: F401
    Base.metadata.create_all(bind=engine)
