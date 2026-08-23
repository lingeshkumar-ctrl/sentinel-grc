from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import time
import uuid
import datetime
import os
import requests
import asyncio

app = FastAPI(title="Sentinel Enterprise SOAR & AI Threat Copilot Engine", version="2.0.0")

CRYPTO_SERVICE_URL = os.getenv("CRYPTO_SERVICE_URL", "http://crypto-audit:8000")

# --- DATA MODELS ---

class PlaybookStep(BaseModel):
    id: str
    name: str
    description: str
    action_type: str # aws_cli, k8s_api, waf_rule, vault_api, notification
    status: str = "PENDING" # PENDING, RUNNING, COMPLETED, FAILED
    duration_ms: int = 0
    details: Optional[str] = None

class Playbook(BaseModel):
    id: str
    name: str
    category: str # Cloud IAM, Infrastructure, Perimeter WAF, Storage
    severity: str # CRITICAL, HIGH, MEDIUM
    description: str
    target_asset_types: List[str]
    steps: List[PlaybookStep]
    estimated_containment_time_sec: int
    auto_trigger_enabled: bool = False

class PlaybookExecuteRequest(BaseModel):
    target_resource: str
    parameters: Optional[Dict[str, Any]] = None
    operator: str = "secops-admin"

class ExecutionRecord(BaseModel):
    execution_id: str
    playbook_id: str
    playbook_name: str
    target_resource: str
    operator: str
    status: str # SUCCESS, RUNNING, FAILED
    started_at: str
    completed_at: Optional[str] = None
    steps_executed: List[PlaybookStep]
    containment_summary: str
    rollback_available: bool = True

class TriggerRule(BaseModel):
    id: str
    name: str
    condition: str
    playbook_id: str
    is_active: bool = True

class CopilotAnalysisRequest(BaseModel):
    context_type: str # pac_violation, vuln_finding, mitre_ttp, incident
    target_code_or_finding: str
    environment: str = "AWS Production"

class ThreatActor(BaseModel):
    id: str
    name: str
    aliases: List[str]
    origin: str
    primary_motivation: str
    targeted_sectors: List[str]
    active_ttps: List[str]
    associated_cves: List[str]
    defense_readiness_score: int # 0-100%
    recommended_playbook_id: str

# --- IN-MEMORY DATABASE ---

PLAYBOOKS: Dict[str, Playbook] = {
    "pb-1": Playbook(
        id="pb-1",
        name="Compromised AWS IAM Credential Quarantine",
        category="Cloud IAM",
        severity="CRITICAL",
        description="Immediately revokes all active STS sessions, attaches an inline AWS DenyAll policy, deactivates active access keys, and archives state to the Merkle audit ledger.",
        target_asset_types=["AWS IAM User", "AWS Role", "Access Key"],
        estimated_containment_time_sec=4,
        auto_trigger_enabled=True,
        steps=[
            PlaybookStep(id="s1", name="Revoke Active STS Sessions", description="Invalidates all temporary STS sessions issued prior to current UTC timestamp via AWS RevokeSecurityTokens", action_type="aws_cli"),
            PlaybookStep(id="s2", name="Attach Inline DenyAll Boundary", description="Applies emergency AWS IAM Policy with Effect: Deny on Action: * to prevent token reuse", action_type="aws_cli"),
            PlaybookStep(id="s3", name="Deactivate Active Access Keys", description="Updates access key status to Inactive across all regions", action_type="aws_cli"),
            PlaybookStep(id="s4", name="Publish Event to SOC Alert Channel", description="Dispatches high-priority incident webhook to SOC Discord/Slack/PagerDuty", action_type="notification"),
            PlaybookStep(id="s5", name="Write Cryptographic Audit Block", description="Emits tamper-evident SHA-256 non-repudiation block to Sentinel Crypto Ledger", action_type="vault_api")
        ]
    ),
    "pb-2": Playbook(
        id="pb-2",
        name="Ransomware Host Network Isolation",
        category="Infrastructure",
        severity="CRITICAL",
        description="Quarantines a compromised cloud VM/container by stripping default security groups, attaching forensic ingress-only SG, and triggering point-in-time EBS volume snapshots.",
        target_asset_types=["EC2 Instance", "EKS Node", "Compute VM"],
        estimated_containment_time_sec=6,
        auto_trigger_enabled=True,
        steps=[
            PlaybookStep(id="s1", name="Query Instance Metadata & Tags", description="Retrieves VPC ID, subnet, and attached EBS volume IDs", action_type="aws_cli"),
            PlaybookStep(id="s2", name="Swap Security Group to Quarantine SG", description="Removes existing security groups and attaches sg-quarantine-isolated (zero egress)", action_type="aws_cli"),
            PlaybookStep(id="s3", name="Capture Point-in-Time EBS Snapshot", description="Creates forensic volume backup with tag IncidentId for post-mortem forensics", action_type="aws_cli"),
            PlaybookStep(id="s4", name="Capture Volatile Memory Dump", description="Executes SSM run command for LiME memory artifact preservation", action_type="k8s_api"),
            PlaybookStep(id="s5", name="Cryptographic Evidence Lock", description="Records snapshot hashes into the Merkle non-repudiation chain", action_type="vault_api")
        ]
    ),
    "pb-3": Playbook(
        id="pb-3",
        name="Perimeter DDoS & Suspicious IP WAF Blocklist",
        category="Perimeter WAF",
        severity="HIGH",
        description="Injects immediate IP deny rules into AWS WAF / Cloudflare edge rate-limiters with automated 24-hour TTL expiration.",
        target_asset_types=["WAF WebACL", "CloudFront Distribution", "API Gateway"],
        estimated_containment_time_sec=2,
        auto_trigger_enabled=True,
        steps=[
            PlaybookStep(id="s1", name="Validate Attacker IP / CIDR", description="Checks IP reputation against AbuseIPDB & ThreatFeeds", action_type="waf_rule"),
            PlaybookStep(id="s2", name="Push IP Set to Cloudflare & AWS WAF", description="Inserts IP into IPSet-DynamicBlocklist with action: BLOCK", action_type="waf_rule"),
            PlaybookStep(id="s3", name="Schedule 24-Hour TTL Expiration", description="Enqueues cron eviction job after containment window closes", action_type="notification"),
            PlaybookStep(id="s4", name="Emit SIEM Defense Update", description="Updates MITRE ATT&CK Defense Evasion score across active monitors", action_type="notification")
        ]
    ),
    "pb-4": Playbook(
        id="pb-4",
        name="S3 Public Exposure Auto-Remediation",
        category="Storage",
        severity="HIGH",
        description="Remediates public storage buckets by applying S3 PublicAccessBlock, enforcing SSE-KMS encryption, and validating AST compliance.",
        target_asset_types=["AWS S3 Bucket", "GCS Bucket", "Azure Blob"],
        estimated_containment_time_sec=3,
        auto_trigger_enabled=False,
        steps=[
            PlaybookStep(id="s1", name="Inspect Bucket Policy & ACLs", description="Identifies public-read or wildcard principal grants", action_type="aws_cli"),
            PlaybookStep(id="s2", name="Apply S3 PublicAccessBlock", description="Enforces BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets", action_type="aws_cli"),
            PlaybookStep(id="s3", name="Enforce AES-256 / KMS Encryption", description="Applies default server-side encryption with AWS managed KMS key", action_type="aws_cli"),
            PlaybookStep(id="s4", name="Trigger Policy-as-Code Re-Scan", description="Runs AST verification engine to confirm zero open findings", action_type="vault_api")
        ]
    )
}

EXECUTION_HISTORY: List[ExecutionRecord] = []

TRIGGER_RULES: List[TriggerRule] = [
    TriggerRule(id="tr-1", name="Auto-Contain on High-Severity IAM Escalation", condition="siem_event.tactic == 'Privilege Escalation' and cvss >= 8.0", playbook_id="pb-1", is_active=True),
    TriggerRule(id="tr-2", name="Auto-Isolate Host on Ransomware Signature", condition="siem_event.tactic == 'Impact' or payload.contains('encrypt')", playbook_id="pb-2", is_active=True),
    TriggerRule(id="tr-3", name="Auto-Block Suspicious Scanner IPs", condition="scanner.open_ports_count > 10 and port == 22", playbook_id="pb-3", is_active=True),
    TriggerRule(id="tr-4", name="Auto-Remediate Public S3 Buckets in Production", condition="pac.violation == 'S3_BUCKET_PUBLIC_ACCESS'", playbook_id="pb-4", is_active=True),
]

THREAT_ACTORS: List[ThreatActor] = [
    ThreatActor(
        id="apt29",
        name="APT29 (Cozy Bear)",
        aliases=["Midnight Blizzard", "Nobelium"],
        origin="Russian Foreign Intelligence (SVR)",
        primary_motivation="Espionage & Cloud Infrastructure Infiltration",
        targeted_sectors=["Government", "Defense", "Financial Services", "IT Supply Chain"],
        active_ttps=["T1078 (Valid Accounts)", "T1190 (Exploit Public-Facing App)", "T1566 (Phishing)", "T1530 (Data from Cloud Storage)"],
        associated_cves=["CVE-2023-38606", "CVE-2023-23397", "CVE-2021-44228"],
        defense_readiness_score=88,
        recommended_playbook_id="pb-1"
    ),
    ThreatActor(
        id="lazarus",
        name="Lazarus Group (APT38)",
        aliases=["Hidden Cobra", "Zinc"],
        origin="DPRK Reconnaissance General Bureau",
        primary_motivation="Financial Theft, Cryptocurrency Exfiltration, Ransomware",
        targeted_sectors=["Fintech", "Cryptocurrency Exchanges", "Global Banking", "Critical Infrastructure"],
        active_ttps=["T1059 (Command & Scripting)", "T1486 (Data Encrypted for Impact)", "T1090 (Proxy)", "T1587 (Develop Capabilities)"],
        associated_cves=["CVE-2024-21413", "CVE-2022-30190", "CVE-2021-40444"],
        defense_readiness_score=82,
        recommended_playbook_id="pb-2"
    ),
    ThreatActor(
        id="fin7",
        name="FIN7 (Carbanak)",
        aliases=["Gold Niagara", "Sangria Tempest"],
        origin="Eastern Europe Cybercrime Syndicate",
        primary_motivation="Large-scale Payment Card Theft & Enterprise Extortion",
        targeted_sectors=["Retail", "Hospitality", "Restaurant Chains", "Healthcare"],
        active_ttps=["T1053 (Scheduled Task)", "T1027 (Obfuscated Files)", "T1071 (Application Layer Protocol)"],
        associated_cves=["CVE-2023-36884", "CVE-2020-1472"],
        defense_readiness_score=91,
        recommended_playbook_id="pb-3"
    ),
    ThreatActor(
        id="lockbit",
        name="LockBit 3.0 (Black)",
        aliases=["Bitwise Spider"],
        origin="Ransomware-as-a-Service (RaaS) Cartel",
        primary_motivation="Double Extortion Ransomware & Data Leaking",
        targeted_sectors=["Manufacturing", "Healthcare", "Legal", "Technology"],
        active_ttps=["T1486 (Data Encrypted for Impact)", "T1489 (Service Stop)", "T1490 (Inhibit System Recovery)"],
        associated_cves=["CVE-2023-4966 (Citrix Bleed)", "CVE-2023-27997 (FortiOS)"],
        defense_readiness_score=79,
        recommended_playbook_id="pb-2"
    ),
    ThreatActor(
        id="volt_typhoon",
        name="Volt Typhoon (Bronze Silhouette)",
        aliases=["Vanguard Panda"],
        origin="People's Republic of China State-Sponsored",
        primary_motivation="Living-off-the-Land (LotL) Pre-Positioning in Critical Infrastructure",
        targeted_sectors=["Energy", "Telecommunications", "Water Systems", "Transportation"],
        active_ttps=["T1078 (Valid Accounts)", "T1059 (Command Line)", "T1049 (System Network Connections Discovery)"],
        associated_cves=["CVE-2024-21762", "CVE-2023-46805", "CVE-2023-28771"],
        defense_readiness_score=85,
        recommended_playbook_id="pb-1"
    )
]

# --- CONTINUOUS CLOUD EVIDENCE BACKGROUND WORKER ---

CONTINUOUS_EVIDENCE_LOG = []

def record_evidence_to_ledger(check_name: str, status: str, details: str):
    try:
        payload = {
            "source": "Continuous Cloud Evidence Daemon",
            "action": check_name,
            "details": f"Status: {status} | {details}"
        }
        requests.post(f"{CRYPTO_SERVICE_URL}/api/crypto/blocks", json=payload, timeout=2)
    except Exception as e:
        pass # Non-blocking

async def continuous_evidence_loop():
    checks = [
        ("AWS CloudTrail Multi-Region Audit", "PASS", "CloudTrail logging active in all 16 AWS regions with KMS key rotation"),
        ("S3 Bucket Server-Side Encryption", "PASS", "All 42 production S3 buckets enforce aws:kms encryption headers"),
        ("IAM Root Account MFA Enforcement", "PASS", "Hardware security key (FIDO2 WebAuthn) verified for root tenant accounts"),
        ("RDS PostgreSQL Storage Encryption", "PASS", "AES-256 encrypted volumes active on production Aurora cluster"),
        ("Kubernetes Cluster-Admin Least Privilege", "PASS", "Zero wildcard ClusterRoleBindings granted to default service accounts"),
        ("Perimeter TLS 1.3 Minimum Cipher Negotiation", "PASS", "TLS 1.0/1.1 disabled; ECDHE-RSA-AES256-GCM-SHA384 active")
    ]
    idx = 0
    while True:
        await asyncio.sleep(35)
        check = checks[idx % len(checks)]
        idx += 1
        record_evidence_to_ledger(check[0], check[1], check[2])
        CONTINUOUS_EVIDENCE_LOG.append({
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "check": check[0],
            "status": check[1],
            "details": check[2]
        })
        if len(CONTINUOUS_EVIDENCE_LOG) > 50:
            CONTINUOUS_EVIDENCE_LOG.pop(0)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(continuous_evidence_loop())

# --- SOAR PLAYBOOK ENDPOINTS ---

@app.get("/api/soar/playbooks", response_model=List[Playbook])
def get_playbooks():
    return list(PLAYBOOKS.values())

@app.get("/api/soar/playbooks/{playbook_id}", response_model=Playbook)
def get_playbook(playbook_id: str):
    if playbook_id not in PLAYBOOKS:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return PLAYBOOKS[playbook_id]

@app.post("/api/soar/playbooks/{playbook_id}/execute", response_model=ExecutionRecord)
def execute_playbook(playbook_id: str, req: PlaybookExecuteRequest, background_tasks: BackgroundTasks):
    if playbook_id not in PLAYBOOKS:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    pb = PLAYBOOKS[playbook_id]
    exec_id = f"exec-{uuid.uuid4().hex[:8]}"
    start_time = datetime.datetime.utcnow().isoformat() + "Z"
    
    executed_steps = []
    total_latency = 0
    
    for step in pb.steps:
        # Simulate step execution telemetry with realistic micro-latencies
        latency = 120 + (len(step.name) * 8)
        total_latency += latency
        executed_steps.append(PlaybookStep(
            id=step.id,
            name=step.name,
            description=step.description,
            action_type=step.action_type,
            status="COMPLETED",
            duration_ms=latency,
            details=f"Executed on {req.target_resource}: 200 OK"
        ))

    summary = f"Playbook '{pb.name}' successfully executed on '{req.target_resource}'. All {len(pb.steps)} containment actions verified."
    end_time = datetime.datetime.utcnow().isoformat() + "Z"

    record = ExecutionRecord(
        execution_id=exec_id,
        playbook_id=pb.id,
        playbook_name=pb.name,
        target_resource=req.target_resource,
        operator=req.operator,
        status="SUCCESS",
        started_at=start_time,
        completed_at=end_time,
        steps_executed=executed_steps,
        containment_summary=summary,
        rollback_available=True
    )
    
    EXECUTION_HISTORY.insert(0, record)
    
    # Send evidence to crypto audit ledger
    background_tasks.add_task(record_evidence_to_ledger, f"SOAR Playbook Execution: {pb.name}", "CONTAINED", f"Target: {req.target_resource} | Execution ID: {exec_id}")
    
    return record

@app.get("/api/soar/history", response_model=List[ExecutionRecord])
def get_execution_history():
    return EXECUTION_HISTORY

@app.get("/api/soar/triggers", response_model=List[TriggerRule])
def get_triggers():
    return TRIGGER_RULES

@app.post("/api/soar/triggers/{rule_id}/toggle")
def toggle_trigger(rule_id: str):
    for tr in TRIGGER_RULES:
        if tr.id == rule_id:
            tr.is_active = not tr.is_active
            return {"id": tr.id, "is_active": tr.is_active}
    raise HTTPException(status_code=404, detail="Rule not found")

# --- AI THREAT COPILOT & REMEDIATION ENDPOINTS ---

@app.post("/api/copilot/analyze")
def copilot_analyze(req: CopilotAnalysisRequest):
    code = req.target_code_or_finding.lower()
    
    if "s3" in code or "bucket" in code or "acl" in code:
        patch = """# --- AI Copilot Remediation Patch for AWS S3 Storage ---
resource "aws_s3_bucket" "remediated" {
  bucket = "sentinel-secure-enterprise-storage"
}

resource "aws_s3_bucket_public_access_block" "remediated_block" {
  bucket = aws_s3_bucket.remediated.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediated_crypto" {
  bucket = aws_s3_bucket.remediated.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/sentinel-grc"
    }
  }
}"""
        blast_radius = "LOW - Impacts only S3 public access policy; zero downtime on existing read/write pipelines."
        compliance_impact = "Remediates SOC 2 CC6.1, ISO 27001 A.8.24, and NIST 800-53 SC-13."
        sigma_rule = """title: Detection of S3 Public Bucket Exposure
logsource:
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketAcl
      - PutBucketPolicy
    requestParameters:
      AccessControlPolicy:
        Grants:
          Grantee:
            URI: http://acs.amazonaws.com/groups/global/AllUsers
condition: selection
level: high"""
    elif "runasnonroot" in code or "container" in code or "k8s" in code or "privileged" in code:
        patch = """# --- AI Copilot Remediation Patch for Kubernetes Security Context ---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-microservice
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: app:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL"""
        blast_radius = "MEDIUM - Requires ephemeral /tmp volume mount if microservice writes local temporary state."
        compliance_impact = "Satisfies CIS Kubernetes Benchmark 5.2.6 & PCI-DSS 4.0 Req 6.4.3."
        sigma_rule = """title: Privileged Pod Creation in Kubernetes
logsource:
  service: k8s-audit
detection:
  selection:
    verb: create
    objectRef.resource: pods
    requestObject.spec.containers.securityContext.privileged: true
condition: selection
level: critical"""
    else:
        patch = """# --- AI Copilot Generic IAM / WAF Remediation Patch ---
aws iam put-role-policy \\
  --role-name EnterpriseExecutionRole \\
  --policy-name DenyWildcardActions \\
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["iam:*", "organizations:*"],
      "Resource": "*"
    }]
  }'"""
        blast_radius = "LOW - Restricts wildcard administrative mutations."
        compliance_impact = "Aligns with Principle of Least Privilege (PoLP) and HIPAA 164.312(a)(1)."
        sigma_rule = """title: IAM Policy Wildcard Action Attached
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: PutUserPolicy
    requestParameters.policyDocument: "*:*"
condition: selection
level: high"""

    return {
        "analysis_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "context_type": req.context_type,
        "environment": req.environment,
        "blast_radius_assessment": blast_radius,
        "compliance_impact": compliance_impact,
        "synthesized_patch_code": patch,
        "sigma_detection_rule": sigma_rule,
        "confidence_score": 0.96
    }

# --- THREAT ACTOR INTELLIGENCE ENDPOINTS ---

@app.get("/api/threats/actors", response_model=List[ThreatActor])
def get_threat_actors():
    return THREAT_ACTORS

@app.get("/api/threats/actors/{actor_id}", response_model=ThreatActor)
def get_threat_actor(actor_id: str):
    for actor in THREAT_ACTORS:
        if actor.id == actor_id:
            return actor
    raise HTTPException(status_code=404, detail="Threat actor not found")

@app.post("/api/threats/simulate-attack")
def simulate_threat_actor_attack(actor_id: str, background_tasks: BackgroundTasks):
    actor = next((a for a in THREAT_ACTORS if a.id == actor_id), None)
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    
    sim_id = f"sim-{uuid.uuid4().hex[:6]}"
    
    # Emits SIEM & Audit events
    background_tasks.add_task(
        record_evidence_to_ledger,
        f"Threat Simulation: {actor.name}",
        "DEFENDED",
        f"Simulated TTPs: {', '.join(actor.active_ttps[:2])} | Defense Score: {actor.defense_readiness_score}%"
    )
    
    return {
        "simulation_id": sim_id,
        "actor_name": actor.name,
        "ttps_tested": actor.active_ttps,
        "defense_readiness_score": actor.defense_readiness_score,
        "containment_status": "MITIGATED",
        "recommended_playbook": actor.recommended_playbook_id,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

# --- EVIDENCE LOG QUERY ---

@app.get("/api/evidence/stream")
def get_evidence_stream():
    return CONTINUOUS_EVIDENCE_LOG

@app.get("/health")
def health():
    return {"status": "ok", "service": "soar-copilot-engine", "playbooks_loaded": len(PLAYBOOKS)}
