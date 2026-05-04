from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class TargetApp(Base):
    __tablename__ = "target_apps"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    endpoint = Column(String)
    system_prompt = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    audits = relationship("AuditRun", back_populates="target")

class AuditRun(Base):
    __tablename__ = "audit_runs"

    id = Column(Integer, primary_key=True, index=True)
    target_app_id = Column(Integer, ForeignKey("target_apps.id"))
    status = Column(String, default="running")
    run_date = Column(DateTime, default=datetime.utcnow)

    target = relationship("TargetApp", back_populates="audits")
    findings = relationship("Finding", back_populates="audit")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    audit_run_id = Column(Integer, ForeignKey("audit_runs.id"))
    module = Column(String) # ex: sensitive_data_leak, prompt_injection
    severity = Column(String) # high, medium, low
    title = Column(String)
    evidence = Column(String)
    framework_mapping = Column(String) # ex: OWASP LLM02, NIST GV-1.1
    recommendation = Column(String)

    audit = relationship("AuditRun", back_populates="findings")