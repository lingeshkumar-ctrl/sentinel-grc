import asyncio
import json
import random
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Sentinel-GRC Real-Time SIEM & MITRE ATT&CK Engine", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurityEvent(BaseModel):
    id: str
    timestamp: str
    event_type: str  # AUTH_ANOMALY, RATE_LIMIT_EXCEEDED, JIT_ELEVATION, POLICY_VIOLATION, BRUTE_FORCE
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source_ip: str
    actor: str
    mitre_tactic: str  # TA0001, TA0004, TA0006, etc.
    mitre_technique: str
    details: str

# In-memory buffer of recent events
EVENT_LOGS: List[SecurityEvent] = []

MITRE_MATRIX = [
    {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "status": "DEFENDED", "coverage": 95},
            {"id": "T1078", "name": "Valid Accounts (Compromised Creds)", "status": "MONITORED", "coverage": 80},
            {"id": "T1566", "name": "Phishing & Spearphishing", "status": "MONITORED", "coverage": 70}
        ]
    },
    {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "status": "DEFENDED", "coverage": 90},
            {"id": "T1548", "name": "Abuse Elevation Control (JIT Bypass)", "status": "DEFENDED", "coverage": 98},
            {"id": "T1078.004", "name": "Cloud Administrator Impersonation", "status": "DEFENDED", "coverage": 85}
        ]
    },
    {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "techniques": [
            {"id": "T1070", "name": "Indicator Removal (Log Tampering)", "status": "DEFENDED", "coverage": 100},
            {"id": "T1562", "name": "Impair Defenses (WAF Disablement)", "status": "DEFENDED", "coverage": 92}
        ]
    },
    {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "techniques": [
            {"id": "T1110", "name": "Brute Force / Credential Stuffing", "status": "DEFENDED", "coverage": 96},
            {"id": "T1552", "name": "Unsecured Credentials in Code", "status": "DEFENDED", "coverage": 88}
        ]
    },
    {
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "techniques": [
            {"id": "T1048", "name": "Exfiltration Over Asymmetric Web Service", "status": "MONITORED", "coverage": 75},
            {"id": "T1567", "name": "Exfiltration to Cloud Storage (S3)", "status": "DEFENDED", "coverage": 89}
        ]
    }
]

# Seed initial historical events
SEED_IPS = ["198.51.100.45", "203.0.113.19", "192.0.2.88", "185.220.101.5", "10.0.4.12"]
SEED_ACTORS = ["unknown_bot", "l1_analyst", "l2_responder", "contractor_vpn", "system_gateway"]

def generate_random_event() -> SecurityEvent:
    event_templates = [
        {
            "type": "RATE_LIMIT_EXCEEDED",
            "sev": "MEDIUM",
            "mitre_tac": "TA0001: Initial Access",
            "mitre_tech": "T1190 - HTTP Flood on Ingress Gateway",
            "msg": "Token-bucket rate limiter triggered: Client exceeded 10 req/sec threshold on /api/auth/login"
        },
        {
            "type": "BRUTE_FORCE",
            "sev": "HIGH",
            "mitre_tac": "TA0006: Credential Access",
            "mitre_tech": "T1110.001 - Password Guessing Attack",
            "msg": "Multiple failed bcrypt authentications detected across 15 distinct usernames from anomalous ASN"
        },
        {
            "type": "JIT_ELEVATION",
            "sev": "INFO",
            "mitre_tac": "TA0004: Privilege Escalation",
            "mitre_tech": "T1548 - Authorized JIT PAM Activation",
            "msg": "Operator granted 120-minute temporary emergency access to PostgreSQL Production DB"
        },
        {
            "type": "AUTH_ANOMALY",
            "sev": "HIGH",
            "mitre_tac": "TA0001: Initial Access",
            "mitre_tech": "T1078 - Impossible Travel Anomaly",
            "msg": "Session active in Frankfurt 5 minutes after concurrent authentication from San Jose"
        },
        {
            "type": "POLICY_VIOLATION",
            "sev": "CRITICAL",
            "mitre_tac": "TA0005: Defense Evasion",
            "mitre_tech": "T1562 - Unencrypted S3 Bucket Provisioning Attempt",
            "msg": "Policy-as-Code pipeline blocked Terraform commit attempting to create public S3 bucket"
        }
    ]

    t = random.choice(event_templates)
    return SecurityEvent(
        id=f"EVT-{random.randint(100000, 999999)}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=t["type"],
        severity=t["sev"],
        source_ip=random.choice(SEED_IPS),
        actor=random.choice(SEED_ACTORS),
        mitre_tactic=t["mitre_tac"],
        mitre_technique=t["mitre_tech"],
        details=t["msg"]
    )

for _ in range(8):
    EVENT_LOGS.append(generate_random_event())

@app.get("/health")
def health():
    return {"service": "telemetry-service", "status": "operational", "active_events": len(EVENT_LOGS)}

@app.get("/api/siem/events")
def get_recent_events():
    return EVENT_LOGS[-30:]

@app.get("/api/siem/mitre")
def get_mitre_matrix():
    total_techniques = sum(len(t["techniques"]) for t in MITRE_MATRIX)
    defended_techniques = sum(len([x for x in t["techniques"] if x["status"] == "DEFENDED"]) for t in MITRE_MATRIX)
    coverage_pct = round((defended_techniques / total_techniques) * 100, 1)
    
    return {
        "tactics": MITRE_MATRIX,
        "total_techniques": total_techniques,
        "defended_techniques": defended_techniques,
        "coverage_percentage": coverage_pct
    }

@app.post("/api/siem/emit")
def emit_event(event: SecurityEvent):
    EVENT_LOGS.append(event)
    return {"status": "EMITTED", "event_id": event.id}

@app.get("/api/siem/stream")
async def event_stream(request: Request):
    """Server-Sent Events (SSE) live telemetry stream."""
    async def sse_generator():
        while True:
            if await request.is_disconnected():
                break
            
            # Send an event every 3-5 seconds
            evt = generate_random_event()
            EVENT_LOGS.append(evt)
            data = f"data: {json.dumps(evt.dict())}\n\n"
            yield data
            await asyncio.sleep(random.uniform(3.0, 5.0))

    return StreamingResponse(sse_generator(), media_type="text/event-stream")
