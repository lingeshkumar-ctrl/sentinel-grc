from fastapi import FastAPI, HTTPException, Header, Query
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from typing import List, Optional, Dict
import datetime

# Secure SQLite connection
SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ControlModel(Base):
    __tablename__ = "controls"
    id = Column(String, primary_key=True, index=True)
    framework = Column(String, index=True) # ISO 27001, NIST CSF 2.0, SOC 2 Type II
    category = Column(String, index=True)
    title = Column(String)
    description = Column(Text)
    status = Column(String, default="Not Implemented") # Implemented, Partial, Not Implemented
    evidence_notes = Column(Text, default="")
    updated_by = Column(String, default="System")
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sentinel-GRC Compliance & Framework Engine")

class ControlStatusUpdate(BaseModel):
    status: str = Field(pattern="^(Implemented|Partial|Not Implemented)$", description="Must be a valid status")
    evidence_notes: Optional[str] = None

class ControlResponse(BaseModel):
    id: str
    framework: str
    category: str
    title: str
    description: str
    status: str
    evidence_notes: Optional[str]
    updated_by: Optional[str]
    updated_at: Optional[datetime.datetime]
    class Config:
        from_attributes = True

class FrameworkMetric(BaseModel):
    total: int
    implemented: int
    partial: int
    not_implemented: int
    score: int

class MetricsResponse(BaseModel):
    frameworks: Dict[str, FrameworkMetric]
    overall_score: int
    total_controls: int

def init_db():
    db = SessionLocal()
    if db.query(ControlModel).count() == 0:
        seed_controls = [
            # ISO 27001:2022
            ControlModel(
                id="ISO-A.5.15",
                framework="ISO 27001",
                category="Access Control",
                title="Access Control Policy",
                description="Rules to control physical and logical access to information and other associated assets must be established and documented.",
                status="Implemented",
                evidence_notes="Stateless JWT with RBAC Gateway deployed and verified.",
                updated_by="admin"
            ),
            ControlModel(
                id="ISO-A.8.24",
                framework="ISO 27001",
                category="Cryptography",
                title="Use of Cryptography",
                description="Rules for the effective use of cryptography, including cryptographic key management, must be defined and implemented.",
                status="Implemented",
                evidence_notes="Bcrypt password hashing (cost factor 10) + HMAC-SHA256 tokens.",
                updated_by="admin"
            ),
            ControlModel(
                id="ISO-A.5.24",
                framework="ISO 27001",
                category="Incident Management",
                title="Information Security Incident Planning",
                description="The organization must establish processes, roles, and responsibilities for managing information security incidents.",
                status="Implemented",
                evidence_notes="Multi-tier L1-L3 escalation matrix active with resolution audit trail.",
                updated_by="admin"
            ),
            ControlModel(
                id="ISO-A.8.7",
                framework="ISO 27001",
                category="Threat Protection",
                title="Protection Against Malware",
                description="Protection against malware must be implemented and supported by appropriate user awareness.",
                status="Partial",
                evidence_notes="Host-level endpoint detection active; SIEM pipeline integration planned.",
                updated_by="admin"
            ),
            ControlModel(
                id="ISO-A.8.8",
                framework="ISO 27001",
                category="Vulnerability Mgmt",
                title="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities of information systems must be obtained in a timely manner.",
                status="Not Implemented",
                evidence_notes="",
                updated_by="System"
            ),
            ControlModel(
                id="ISO-A.6.6",
                framework="ISO 27001",
                category="Operations",
                title="Remote Working Security",
                description="Security measures must be implemented when personnel are working remotely to protect information.",
                status="Partial",
                evidence_notes="Zero-trust reverse proxy and session rate-limiting in effect.",
                updated_by="admin"
            ),

            # NIST CSF 2.0
            ControlModel(
                id="NIST-GV.OC-01",
                framework="NIST CSF 2.0",
                category="Govern",
                title="Organizational Context",
                description="The organizational mission, objectives, stakeholders, and legal requirements are understood and inform risk decisions.",
                status="Implemented",
                evidence_notes="GRC governance framework established and mapped to operations.",
                updated_by="admin"
            ),
            ControlModel(
                id="NIST-PR.AC-01",
                framework="NIST CSF 2.0",
                category="Protect",
                title="Identity Management & Access Control",
                description="Identities and credentials for authorized individuals, processes, and devices are managed consistently.",
                status="Implemented",
                evidence_notes="Centralized IAM microservice managing lifecycle and real-time revocation.",
                updated_by="admin"
            ),
            ControlModel(
                id="NIST-PR.DS-01",
                framework="NIST CSF 2.0",
                category="Protect",
                title="Data Security Controls",
                description="Confidentiality, integrity, and availability of data-at-rest and data-in-transit are protected.",
                status="Implemented",
                evidence_notes="TLS container bridges and parameterized query persistence.",
                updated_by="admin"
            ),
            ControlModel(
                id="NIST-DE.CM-01",
                framework="NIST CSF 2.0",
                category="Detect",
                title="Continuous Cybersecurity Monitoring",
                description="Networks and computing environments are monitored to detect potential cybersecurity events and anomalies.",
                status="Partial",
                evidence_notes="Rate limiting and live health check monitors configured in Gateway.",
                updated_by="admin"
            ),
            ControlModel(
                id="NIST-RS.RP-01",
                framework="NIST CSF 2.0",
                category="Respond",
                title="Incident Response Plan Execution",
                description="The incident response plan is executed during or after an incident according to defined triage procedures.",
                status="Implemented",
                evidence_notes="Role-gated ticket escalation engine with resolution archiving active.",
                updated_by="admin"
            ),

            # SOC 2 Type II
            ControlModel(
                id="SOC2-CC6.1",
                framework="SOC 2 Type II",
                category="Security",
                title="Logical & Physical Access Controls",
                description="The entity implements logical access security software, infrastructure, and architectures over protected information.",
                status="Implemented",
                evidence_notes="API Gateway per-route RBAC policies for L1, L2, L3, Manager, Admin.",
                updated_by="admin"
            ),
            ControlModel(
                id="SOC2-CC6.3",
                framework="SOC 2 Type II",
                category="Security",
                title="Principle of Least Privilege",
                description="The entity authorizes, modifies, or removes access to data, software, and functions based on role need.",
                status="Implemented",
                evidence_notes="Strict role verification; write actions forbidden for unassigned tiers.",
                updated_by="admin"
            ),
            ControlModel(
                id="SOC2-CC7.2",
                framework="SOC 2 Type II",
                category="Monitoring",
                title="System Anomaly & Vulnerability Monitoring",
                description="The entity monitors system components and control operations for vulnerabilities and anomalous behaviors.",
                status="Partial",
                evidence_notes="Per-IP token-bucket rate limiter defending against brute-force.",
                updated_by="admin"
            ),
            ControlModel(
                id="SOC2-CC8.1",
                framework="SOC 2 Type II",
                category="Change Mgmt",
                title="Authorized Change Management",
                description="The entity authorizes, designs, develops, tests, approves, and implements changes to system infrastructure.",
                status="Not Implemented",
                evidence_notes="",
                updated_by="System"
            )
        ]
        db.add_all(seed_controls)
        db.commit()
    db.close()

init_db()

@app.get("/health")
def health_check():
    return {"status": "Compliance Service OK"}

@app.get("/api/compliance/controls", response_model=List[ControlResponse])
def get_controls(framework: Optional[str] = Query(None), category: Optional[str] = Query(None)):
    db = SessionLocal()
    query = db.query(ControlModel)
    if framework:
        query = query.filter(ControlModel.framework == framework)
    if category:
        query = query.filter(ControlModel.category == category)
    controls = query.order_by(ControlModel.id.asc()).all()
    db.close()
    return controls

@app.put("/api/compliance/controls/{control_id}", response_model=ControlResponse)
def update_control(control_id: str, update: ControlStatusUpdate, x_user_name: Optional[str] = Header(None)):
    db = SessionLocal()
    control = db.query(ControlModel).filter(ControlModel.id == control_id).first()
    if not control:
        db.close()
        raise HTTPException(status_code=404, detail="Control not found")
    
    control.status = update.status
    if update.evidence_notes is not None:
        control.evidence_notes = update.evidence_notes
    
    control.updated_by = x_user_name if x_user_name else "Auditor"
    control.updated_at = datetime.datetime.utcnow()
    
    db.commit()
    db.refresh(control)
    db.close()
    return control

@app.get("/api/compliance/metrics", response_model=MetricsResponse)
def get_metrics():
    db = SessionLocal()
    controls = db.query(ControlModel).all()
    db.close()

    frameworks: Dict[str, Dict[str, int]] = {}
    
    for c in controls:
        if c.framework not in frameworks:
            frameworks[c.framework] = {"total": 0, "implemented": 0, "partial": 0, "not_implemented": 0}
        
        frameworks[c.framework]["total"] += 1
        if c.status == "Implemented":
            frameworks[c.framework]["implemented"] += 1
        elif c.status == "Partial":
            frameworks[c.framework]["partial"] += 1
        else:
            frameworks[c.framework]["not_implemented"] += 1

    metrics: Dict[str, FrameworkMetric] = {}
    total_score_sum = 0
    total_framework_count = 0

    for fw, counts in frameworks.items():
        total = counts["total"]
        if total > 0:
            # Implemented = 100%, Partial = 50%, Not Implemented = 0%
            score = int(((counts["implemented"] * 1.0 + counts["partial"] * 0.5) / total) * 100)
        else:
            score = 0
        
        metrics[fw] = FrameworkMetric(
            total=total,
            implemented=counts["implemented"],
            partial=counts["partial"],
            not_implemented=counts["not_implemented"],
            score=score
        )
        total_score_sum += score
        total_framework_count += 1

    overall = int(total_score_sum / total_framework_count) if total_framework_count > 0 else 0

    return MetricsResponse(
        frameworks=metrics,
        overall_score=overall,
        total_controls=len(controls)
    )
