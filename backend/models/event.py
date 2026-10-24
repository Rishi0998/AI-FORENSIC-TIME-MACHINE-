"""
SQLAlchemy models for forensic events, analysis results, and attack chains.
"""
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import Base


class Event(Base):
    """A single parsed log event."""
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    source_type = Column(String, nullable=False)  # linux, windows, network
    user = Column(String, nullable=True)
    process = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    action = Column(String, nullable=False)
    raw_log = Column(Text, nullable=False)
    severity = Column(String, default="low")  # low, medium, high, critical
    is_suspicious = Column(Integer, default=0)
    detection_rule = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AttackChain(Base):
    """A reconstructed attack chain linking multiple events."""
    __tablename__ = "attack_chains"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True, nullable=False)
    chain_name = Column(String, nullable=False)
    phase = Column(String, nullable=False)  # recon, initial_access, execution, etc.
    event_ids = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="medium")
    mitre_tactic = Column(String, nullable=True)
    order_index = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class AnalysisResult(Base):
    """AI-generated analysis and explanation for a session."""
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True, nullable=False)
    summary = Column(Text, nullable=False)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="low")
    attack_narrative = Column(Text, nullable=True)
    mitre_mapping = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    graph_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
