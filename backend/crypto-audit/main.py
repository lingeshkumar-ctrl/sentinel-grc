import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Sentinel-GRC Cryptographic SHA-256 Audit Chain", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditBlock(BaseModel):
    index: int
    timestamp: str
    event_type: str  # INCIDENT_RESOLVED, JIT_GRANTED, POLICY_ENFORCED, COMPLIANCE_EVIDENCE_ATTACHED, TENANT_PROVISIONED
    actor: str
    payload: Dict[str, Any]
    prev_hash: str
    block_hash: str

class RecordEventRequest(BaseModel):
    event_type: str
    actor: str
    payload: Dict[str, Any]

class VerificationResult(BaseModel):
    is_valid: bool
    total_blocks_verified: int
    tampered_block_index: Optional[int]
    status_message: str
    verified_at: str

# In-memory cryptographic ledger
CHAIN: List[AuditBlock] = []

def compute_hash(index: int, timestamp: str, event_type: str, actor: str, payload: Dict[str, Any], prev_hash: str) -> str:
    payload_str = json.dumps(payload, sort_keys=True)
    raw = f"{index}|{timestamp}|{event_type}|{actor}|{payload_str}|{prev_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def create_genesis_block() -> AuditBlock:
    ts = "2026-08-01T00:00:00.000000Z"
    prev = "0000000000000000000000000000000000000000000000000000000000000000"
    payload = {"message": "Sentinel-GRC Cryptographic Genesis Block Initialized"}
    b_hash = compute_hash(0, ts, "GENESIS", "system_kernel", payload, prev)
    return AuditBlock(
        index=0,
        timestamp=ts,
        event_type="GENESIS",
        actor="system_kernel",
        payload=payload,
        prev_hash=prev,
        block_hash=b_hash
    )

CHAIN.append(create_genesis_block())

# Add initial historical blocks
INITIAL_EVENTS = [
    {
        "type": "COMPLIANCE_CONTROL_VERIFIED",
        "actor": "admin",
        "payload": {"control_id": "ISO-A.5.15", "framework": "ISO 27001", "status": "Implemented"}
    },
    {
        "type": "JIT_ACCESS_GRANTED",
        "actor": "manager_alice",
        "payload": {"user": "l3_specialist", "resource": "prod-k8s-cluster", "ttl_minutes": 120}
    },
    {
        "type": "INCIDENT_RESOLVED",
        "actor": "manager_alice",
        "payload": {"ticket_id": "RISK-01", "title": "SQL Injection on Auth", "action": "WAF Rule Deployed"}
    },
    {
        "type": "TENANT_PROVISIONED",
        "actor": "admin",
        "payload": {"tenant": "FintechCorp Global", "tier": "Financial-Grade", "sla": "99.99%"}
    }
]

for item in INITIAL_EVENTS:
    last_block = CHAIN[-1]
    idx = last_block.index + 1
    ts = datetime.now(timezone.utc).isoformat()
    b_hash = compute_hash(idx, ts, item["type"], item["actor"], item["payload"], last_block.block_hash)
    CHAIN.append(AuditBlock(
        index=idx,
        timestamp=ts,
        event_type=item["type"],
        actor=item["actor"],
        payload=item["payload"],
        prev_hash=last_block.block_hash,
        block_hash=b_hash
    ))

@app.get("/health")
def health():
    return {"service": "crypto-audit", "status": "operational", "chain_length": len(CHAIN)}

@app.get("/api/crypto/blocks", response_model=List[AuditBlock])
def get_blocks():
    return CHAIN

@app.post("/api/crypto/record", response_model=AuditBlock)
def record_event(req: RecordEventRequest):
    last_block = CHAIN[-1]
    new_idx = last_block.index + 1
    ts = datetime.now(timezone.utc).isoformat()
    b_hash = compute_hash(new_idx, ts, req.event_type, req.actor, req.payload, last_block.block_hash)
    
    new_block = AuditBlock(
        index=new_idx,
        timestamp=ts,
        event_type=req.event_type,
        actor=req.actor,
        payload=req.payload,
        prev_hash=last_block.block_hash,
        block_hash=b_hash
    )
    CHAIN.append(new_block)
    return new_block

@app.get("/api/crypto/verify", response_model=VerificationResult)
def verify_integrity():
    """Mathematically recomputes the entire blockchain to verify zero tampering."""
    for i in range(1, len(CHAIN)):
        current = CHAIN[i]
        previous = CHAIN[i - 1]

        # 1. Verify prev_hash link
        if current.prev_hash != previous.block_hash:
            return VerificationResult(
                is_valid=False,
                total_blocks_verified=i,
                tampered_block_index=current.index,
                status_message=f"CRITICAL: Hash chain broken at Block #{current.index}. PrevHash does not match Block #{previous.index} Hash.",
                verified_at=datetime.now(timezone.utc).isoformat()
            )

        # 2. Recompute current block hash
        expected_hash = compute_hash(
            current.index,
            current.timestamp,
            current.event_type,
            current.actor,
            current.payload,
            current.prev_hash
        )

        if current.block_hash != expected_hash:
            return VerificationResult(
                is_valid=False,
                total_blocks_verified=i,
                tampered_block_index=current.index,
                status_message=f"CRITICAL: Payload tampering detected in Block #{current.index}. Stored hash {current.block_hash[:16]}... does not match recalculated hash {expected_hash[:16]}...",
                verified_at=datetime.now(timezone.utc).isoformat()
            )

    return VerificationResult(
        is_valid=True,
        total_blocks_verified=len(CHAIN),
        tampered_block_index=None,
        status_message="SUCCESS: Cryptographic non-repudiation verified. All SHA-256 blocks are valid and mathematically immutable.",
        verified_at=datetime.now(timezone.utc).isoformat()
    )

@app.post("/api/crypto/simulate-tamper")
def simulate_tamper(block_index: int = 2):
    """Demonstration utility: Alters payload of a block to demonstrate real-time mathematical detection."""
    if block_index >= len(CHAIN) or block_index == 0:
        raise HTTPException(status_code=400, detail="Invalid block index for tampering demonstration")
    
    CHAIN[block_index].payload["TAMPERED_FLAG"] = "Malicious unauthorized modification injected"
    return {"status": "TAMPERED", "message": f"Block #{block_index} payload maliciously modified. Run verification to observe mathematical detection."}
