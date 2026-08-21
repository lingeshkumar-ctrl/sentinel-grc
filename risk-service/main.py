from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from typing import List, Optional
import datetime

# Setup Database
SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class RiskModel(Base):
    __tablename__ = "risks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    likelihood = Column(Integer) # 1-5
    impact = Column(Integer) # 1-5
    inherent_score = Column(Integer)
    status = Column(String, default="Raised") # "Raised", "In Progress L2", "Escalated L3", "Escalated Manager"
    creator_username = Column(String)

class ArchivedRiskModel(Base):
    __tablename__ = "archived_risks"
    id = Column(Integer, primary_key=True, index=True)
    original_id = Column(Integer)
    name = Column(String)
    likelihood = Column(Integer)
    impact = Column(Integer)
    creator_username = Column(String)
    resolved_by = Column(String)
    resolution_notes = Column(String)
    resolved_at = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sentinel-GRC Risk Service")

class RiskCreate(BaseModel):
    name: str
    likelihood: int
    impact: int

class Risk(RiskCreate):
    id: int
    inherent_score: int
    status: str
    creator_username: str
    class Config:
        from_attributes = True

class EscalateRequest(BaseModel):
    status: str

class ResolveRequest(BaseModel):
    resolution_notes: str

class ArchivedRisk(BaseModel):
    id: int
    original_id: int
    name: str
    likelihood: int
    impact: int
    creator_username: str
    resolved_by: str
    resolution_notes: str
    resolved_at: datetime.datetime
    class Config:
        from_attributes = True

@app.get("/health")
def health_check():
    return {"status": "Risk Service OK"}

@app.post("/api/risk", response_model=Risk)
def create_risk(risk: RiskCreate, x_user_name: Optional[str] = Header(None)):
    if not (1 <= risk.likelihood <= 5) or not (1 <= risk.impact <= 5):
        raise HTTPException(status_code=400, detail="Likelihood and Impact must be between 1 and 5")
    
    score = risk.likelihood * risk.impact
    creator = x_user_name if x_user_name else "unknown"
    
    db = SessionLocal()
    db_risk = RiskModel(
        name=risk.name, 
        likelihood=risk.likelihood, 
        impact=risk.impact, 
        inherent_score=score,
        status="Raised",
        creator_username=creator
    )
    db.add(db_risk)
    db.commit()
    db.refresh(db_risk)
    db.close()
    
    return db_risk

@app.get("/api/risk", response_model=List[Risk])
def read_risks():
    db = SessionLocal()
    risks = db.query(RiskModel).all()
    db.close()
    return risks

@app.put("/api/risk/{risk_id}/escalate", response_model=Risk)
def escalate_risk(risk_id: int, req: EscalateRequest):
    db = SessionLocal()
    db_risk = db.query(RiskModel).filter(RiskModel.id == risk_id).first()
    if db_risk is None:
        db.close()
        raise HTTPException(status_code=404, detail="Risk not found")
    
    db_risk.status = req.status
    db.commit()
    db.refresh(db_risk)
    db.close()
    return db_risk

@app.post("/api/risk/{risk_id}/resolve")
def resolve_risk(risk_id: int, req: ResolveRequest, x_user_name: Optional[str] = Header(None)):
    db = SessionLocal()
    db_risk = db.query(RiskModel).filter(RiskModel.id == risk_id).first()
    if db_risk is None:
        db.close()
        raise HTTPException(status_code=404, detail="Risk not found")
    
    resolved_by = x_user_name if x_user_name else "unknown"

    # Move to Archive
    archived = ArchivedRiskModel(
        original_id=db_risk.id,
        name=db_risk.name,
        likelihood=db_risk.likelihood,
        impact=db_risk.impact,
        creator_username=db_risk.creator_username,
        resolved_by=resolved_by,
        resolution_notes=req.resolution_notes
    )
    db.add(archived)
    db.delete(db_risk) # Delete from active
    db.commit()
    db.close()
    
    return {"status": "resolved and archived"}

@app.get("/api/archive", response_model=List[ArchivedRisk])
def read_archive():
    db = SessionLocal()
    archives = db.query(ArchivedRiskModel).order_by(ArchivedRiskModel.resolved_at.desc()).all()
    db.close()
    return archives

@app.delete("/api/risk/{risk_id}")
def delete_risk(risk_id: int):
    # Just in case an admin needs to hard delete without resolving
    db = SessionLocal()
    db_risk = db.query(RiskModel).filter(RiskModel.id == risk_id).first()
    if db_risk is None:
        db.close()
        raise HTTPException(status_code=404, detail="Risk not found")
    
    db.delete(db_risk)
    db.commit()
    db.close()
    return {"status": "deleted"}
