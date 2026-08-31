import json
import re
import yaml
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Sentinel-GRC Policy-as-Code (PaC) Engine", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EvaluateRequest(BaseModel):
    manifest_type: str  # terraform, kubernetes, aws_iam
    code: str

class PolicyViolation(BaseModel):
    rule_id: str
    title: str
    severity: str  # Critical, High, Medium, Low
    line_number: Optional[int]
    matched_snippet: str
    explanation: str
    remediation_snippet: str

class EvaluationResponse(BaseModel):
    manifest_type: str
    total_rules_evaluated: int
    violations_count: int
    compliance_score: float
    status: str  # PASSED, FAILED, WARNING
    violations: List[PolicyViolation]
    evaluated_at: str

RULES_CATALOG = [
    {
        "id": "PAC-IAM-01",
        "type": "aws_iam",
        "title": "Disallow Wildcard Action in IAM Policy ('*')",
        "severity": "Critical",
        "pattern": r'"Action"\s*:\s*("\*"|\[\s*"\*"\s*\])',
        "explanation": "Granting 'Action: *' provides unrestricted root-level access across all cloud APIs, violating the Principle of Least Privilege.",
        "remediation": '"Action": ["s3:GetObject", "s3:PutObject"]'
    },
    {
        "id": "PAC-IAM-02",
        "type": "aws_iam",
        "title": "Disallow Wildcard Resource in Allow Effect ('*')",
        "severity": "High",
        "pattern": r'"Resource"\s*:\s*"\*"',
        "explanation": "Applying allow actions to 'Resource: *' exposes all tenant data buckets and instances to lateral movement.",
        "remediation": '"Resource": "arn:aws:s3:::company-isolated-vault/*"'
    },
    {
        "id": "PAC-TF-01",
        "type": "terraform",
        "title": "Require S3 Bucket Server-Side Encryption (SSE-KMS)",
        "severity": "Critical",
        "pattern": r'resource\s+"aws_s3_bucket"',
        "negative_pattern": r'server_side_encryption_configuration|sse_algorithm',
        "explanation": "S3 bucket definition does not specify server-side encryption at rest, violating SOC 2 CC6.1 and ISO 27001 A.8.24.",
        "remediation": '''  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }'''
    },
    {
        "id": "PAC-TF-02",
        "type": "terraform",
        "title": "Restrict Open Ingress from 0.0.0.0/0 on Sensitive Ports",
        "severity": "Critical",
        "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "explanation": "Security Group allows unrestricted global ingress from 0.0.0.0/0, exposing internal microservices to automated port scanning.",
        "remediation": 'cidr_blocks = ["10.0.0.0/16"] # Restrict to internal VPC CIDR'
    },
    {
        "id": "PAC-K8S-01",
        "type": "kubernetes",
        "title": "Disallow Privileged Container Execution (privileged: true)",
        "severity": "Critical",
        "pattern": r'privileged:\s*true',
        "explanation": "Running containers in privileged mode disables host kernel isolation, allowing container escape attacks.",
        "remediation": '''securityContext:
  privileged: false
  allowPrivilegeEscalation: false'''
    },
    {
        "id": "PAC-K8S-02",
        "type": "kubernetes",
        "title": "Enforce Read-Only Root Filesystem (readOnlyRootFilesystem)",
        "severity": "Medium",
        "negative_pattern": r'readOnlyRootFilesystem:\s*true',
        "pattern": r'containers:',
        "explanation": "Containers should run with an immutable read-only root filesystem to prevent malware dropped in /tmp from persisting.",
        "remediation": '''securityContext:
  readOnlyRootFilesystem: true'''
    },
    {
        "id": "PAC-K8S-03",
        "type": "kubernetes",
        "title": "Require CPU and Memory Resource Limits",
        "severity": "Medium",
        "negative_pattern": r'resources:\s*limits:',
        "pattern": r'containers:',
        "explanation": "Pods without explicit CPU/Memory limits are vulnerable to noisy-neighbor resource exhaustion and Denial of Service (DoS).",
        "remediation": '''resources:
  limits:
    memory: "512Mi"
    cpu: "500m"'''
    }
]

@app.get("/health")
def health():
    return {"service": "policy-engine", "status": "operational"}

@app.get("/api/pac/rules")
def get_rules():
    return RULES_CATALOG

@app.post("/api/pac/evaluate", response_model=EvaluationResponse)
def evaluate_manifest(req: EvaluateRequest):
    lines = req.code.split("\n")
    violations = []
    applicable_rules = [r for r in RULES_CATALOG if r["type"] == req.manifest_type or req.manifest_type == "all"]

    for rule in applicable_rules:
        # Check standard positive regex matching
        if "negative_pattern" not in rule:
            for idx, line in enumerate(lines):
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    violations.append(PolicyViolation(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        line_number=idx + 1,
                        matched_snippet=line.strip(),
                        explanation=rule["explanation"],
                        remediation_snippet=rule["remediation"]
                    ))
        else:
            # Negative pattern: violation occurs if 'pattern' is present but 'negative_pattern' is absent
            has_trigger = re.search(rule["pattern"], req.code, re.IGNORECASE)
            has_required = re.search(rule["negative_pattern"], req.code, re.IGNORECASE)
            if has_trigger and not has_required:
                # Find line of trigger
                trigger_line = 1
                for idx, line in enumerate(lines):
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        trigger_line = idx + 1
                        break
                violations.append(PolicyViolation(
                    rule_id=rule["id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    line_number=trigger_line,
                    matched_snippet=lines[trigger_line - 1].strip() if trigger_line <= len(lines) else "Manifest Block",
                    explanation=rule["explanation"],
                    remediation_snippet=rule["remediation"]
                ))

    # Calculate compliance score
    crit_count = len([v for v in violations if v.severity == "Critical"])
    high_count = len([v for v in violations if v.severity == "High"])
    med_count = len([v for v in violations if v.severity == "Medium"])

    penalty = (crit_count * 30) + (high_count * 15) + (med_count * 5)
    score = max(0.0, min(100.0, round(100.0 - penalty, 1)))

    status = "PASSED"
    if score < 70:
        status = "FAILED"
    elif score < 90:
        status = "WARNING"

    return EvaluationResponse(
        manifest_type=req.manifest_type,
        total_rules_evaluated=len(applicable_rules),
        violations_count=len(violations),
        compliance_score=score,
        status=status,
        violations=violations,
        evaluated_at=datetime.now(timezone.utc).isoformat()
    )
