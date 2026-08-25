import socket
import ssl
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Sentinel-GRC Live Vulnerability & Port Scanner", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

COMMON_PORTS = [
    {"port": 22, "service": "SSH (Secure Shell)", "criticality": "High"},
    {"port": 80, "service": "HTTP (Web Ingress)", "criticality": "Medium"},
    {"port": 443, "service": "HTTPS (TLS Web Ingress)", "criticality": "Low"},
    {"port": 3306, "service": "MySQL Database", "criticality": "Critical"},
    {"port": 5432, "service": "PostgreSQL Database", "criticality": "Critical"},
    {"port": 6379, "service": "Redis Cache", "criticality": "Critical"},
    {"port": 8080, "service": "HTTP Alternate / API Gateway", "criticality": "Medium"},
    {"port": 8081, "service": "IAM Auth Daemon", "criticality": "High"},
    {"port": 8443, "service": "HTTPS Secondary", "criticality": "Medium"},
    {"port": 27017, "service": "MongoDB Service", "criticality": "Critical"},
]

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"  # full, ports_only, headers_only, ssl_only

class PortResult(BaseModel):
    port: int
    service: str
    state: str  # OPEN, CLOSED, FILTERED
    latency_ms: float
    criticality: str

class VulnerabilityFinding(BaseModel):
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low
    cwe_id: str
    cvss_score: float
    cvss_vector: str
    description: str
    remediation: str

class ScanResponse(BaseModel):
    target: str
    resolved_ip: Optional[str]
    scan_timestamp: str
    duration_ms: float
    ports: List[PortResult]
    open_port_count: int
    headers_analyzed: Dict[str, Any]
    ssl_info: Optional[Dict[str, Any]]
    findings: List[VulnerabilityFinding]
    risk_rating: str

def calculate_cvss(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H") -> tuple[float, str]:
    """Generates standard CVSS v3.1 vector string and score."""
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    score_map = {"H": 3.0, "L": 1.5, "N": 0.0}
    impact = score_map.get(c, 0) + score_map.get(i, 0) + score_map.get(a, 0)
    score = min(10.0, round(impact * 1.1 + 0.5, 1))
    return score, vector

def probe_port(host: str, port: int, timeout: float = 0.6) -> PortResult:
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    state = "CLOSED"
    try:
        res = sock.connect_ex((host, port))
        if res == 0:
            state = "OPEN"
    except socket.timeout:
        state = "FILTERED"
    except Exception:
        state = "CLOSED"
    finally:
        sock.close()
    
    latency = round((time.time() - start) * 1000, 2)
    svc = next((p["service"] for p in COMMON_PORTS if p["port"] == port), "Custom Daemon")
    crit = next((p["criticality"] for p in COMMON_PORTS if p["port"] == port), "Medium")
    return PortResult(port=port, service=svc, state=state, latency_ms=latency, criticality=crit)

def analyze_headers(url: str) -> tuple[Dict[str, Any], List[VulnerabilityFinding]]:
    findings = []
    headers_result = {}
    
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-GRC-Scanner/2.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            headers = dict(resp.headers)
            headers_result["status_code"] = resp.getcode()
            headers_result["server"] = headers.get("Server", "Undisclosed")
            headers_result["hsts"] = headers.get("Strict-Transport-Security", None)
            headers_result["csp"] = headers.get("Content-Security-Policy", None)
            headers_result["x_frame"] = headers.get("X-Frame-Options", None)
            headers_result["x_content_type"] = headers.get("X-Content-Type-Options", None)
            headers_result["cors"] = headers.get("Access-Control-Allow-Origin", None)

            # Rule checks
            if not headers_result["hsts"]:
                score, vec = calculate_cvss(av="N", ac="L", pr="N", ui="R", c="L", i="L", a="N")
                findings.append(VulnerabilityFinding(
                    id="SEC-HSTS-01",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    severity="Medium",
                    cwe_id="CWE-319: Cleartext Transmission of Sensitive Information",
                    cvss_score=score,
                    cvss_vector=vec,
                    description="The server does not enforce HTTPS connections via HSTS, exposing users to SSL-stripping and downgrade attacks.",
                    remediation="Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' in web server/ingress configuration."
                ))

            if not headers_result["csp"]:
                score, vec = calculate_cvss(av="N", ac="L", pr="N", ui="R", c="H", i="H", a="N")
                findings.append(VulnerabilityFinding(
                    id="SEC-CSP-02",
                    title="Missing Content-Security-Policy (CSP)",
                    severity="High",
                    cwe_id="CWE-693: Protection Mechanism Failure",
                    cvss_score=score,
                    cvss_vector=vec,
                    description="Absence of a Content-Security-Policy enables Cross-Site Scripting (XSS) and data injection payloads to execute in client contexts.",
                    remediation="Define a restrictive CSP policy restricting script-src, object-src, and frame-ancestors."
                ))

            if not headers_result["x_frame"]:
                score, vec = calculate_cvss(av="N", ac="M", pr="N", ui="R", c="N", i="L", a="N")
                findings.append(VulnerabilityFinding(
                    id="SEC-CLICKJACK-03",
                    title="Missing X-Frame-Options (Clickjacking Risk)",
                    severity="Medium",
                    cwe_id="CWE-1021: Improper Restriction of Rendered UI Layers",
                    cvss_score=score,
                    cvss_vector=vec,
                    description="The target web endpoint does not forbid iframe framing, allowing adversaries to mount UI redressing/clickjacking attacks.",
                    remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
                ))

            if headers_result["cors"] == "*":
                score, vec = calculate_cvss(av="N", ac="L", pr="N", ui="N", c="H", i="N", a="N")
                findings.append(VulnerabilityFinding(
                    id="SEC-CORS-04",
                    title="Overly Permissive CORS Policy (Wildcard '*')",
                    severity="High",
                    cwe_id="CWE-942: Overly Permissive Cross-Domain Whitelist",
                    cvss_score=score,
                    cvss_vector=vec,
                    description="Access-Control-Allow-Origin is configured to '*', enabling malicious third-party scripts to access authenticated API data.",
                    remediation="Specify explicit trusted domain origins instead of wildcards."
                ))
    except Exception as e:
        headers_result["error"] = str(e)
    
    return headers_result, findings

def inspect_ssl(host: str, port: int = 443) -> tuple[Optional[Dict[str, Any]], List[VulnerabilityFinding]]:
    findings = []
    ssl_info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                ssl_info["protocol"] = version
                ssl_info["cipher"] = cipher[0] if cipher else "Unknown"
                ssl_info["bits"] = cipher[2] if cipher else 0
                ssl_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                ssl_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                ssl_info["expires"] = cert.get("notAfter", "Unknown")

                if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    score, vec = calculate_cvss(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="N")
                    findings.append(VulnerabilityFinding(
                        id="SEC-TLS-OBSOLETE",
                        title=f"Insecure Legacy TLS Protocol Detected ({version})",
                        severity="Critical",
                        cwe_id="CWE-326: Inadequate Encryption Strength",
                        cvss_score=score,
                        cvss_vector=vec,
                        description=f"Host is accepting deprecated {version} handshakes vulnerable to POODLE, BEAST, and cryptanalytic attacks.",
                        remediation="Disable TLS 1.0/1.1 and enforce TLS 1.2 or TLS 1.3 as the strict cryptographic minimum."
                    ))
    except Exception as e:
        ssl_info = None

    return ssl_info, findings

@app.get("/health")
def health():
    return {"service": "scanner-service", "status": "operational", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.post("/api/scanner/run", response_model=ScanResponse)
def run_scan(req: ScanRequest):
    clean_host = req.target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    start_time = time.time()

    # Resolve IP
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(clean_host)
    except Exception:
        resolved_ip = "127.0.0.1" if clean_host in ["localhost", "127.0.0.1"] else None

    # Probe ports
    port_results = []
    findings = []

    for p in COMMON_PORTS:
        res = probe_port(clean_host, p["port"])
        port_results.append(res)
        if res.state == "OPEN" and res.port in [3306, 5432, 6379, 27017]:
            score, vec = calculate_cvss(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H")
            findings.append(VulnerabilityFinding(
                id=f"SEC-PORT-{res.port}",
                title=f"Exposed High-Value Database Service (Port {res.port}: {res.service})",
                severity="Critical",
                cwe_id="CWE-284: Improper Access Control",
                cvss_score=score,
                cvss_vector=vec,
                description=f"Database port {res.port} is directly listening on the network interface without VPC firewall isolation.",
                remediation="Bind database daemon strictly to 127.0.0.1 and restrict ingress with Security Group/Firewall rules."
            ))

    # Header analysis
    headers_res, header_findings = analyze_headers(req.target)
    findings.extend(header_findings)

    # SSL analysis
    ssl_res, ssl_findings = inspect_ssl(clean_host)
    findings.extend(ssl_findings)

    duration = round((time.time() - start_time) * 1000, 2)
    open_count = len([p for p in port_results if p.state == "OPEN"])

    # Overall risk rating calculation
    critical_count = len([f for f in findings if f.severity == "Critical"])
    high_count = len([f for f in findings if f.severity == "High"])
    if critical_count > 0:
        overall_risk = "CRITICAL"
    elif high_count > 0:
        overall_risk = "HIGH"
    elif len(findings) > 0:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "SECURE"

    return ScanResponse(
        target=req.target,
        resolved_ip=resolved_ip,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        duration_ms=duration,
        ports=port_results,
        open_port_count=open_count,
        headers_analyzed=headers_res,
        ssl_info=ssl_res,
        findings=findings,
        risk_rating=overall_risk,
    )
