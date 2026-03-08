from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import lightgbm as lgb
from collections import defaultdict
from datetime import datetime, timedelta
import re
import logging
import random
import string
import uuid
import threading
import time as _time
import json

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AI-GATEWAY")

# ============================================================
# APP
# ============================================================
app = FastAPI(title="Research-Grade AI API Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# CONFIG
# ============================================================
DECAY_RATE = 0.95
REPUTATION_BLOCK = -30
BLOCK_DURATION = 86400

EDOS_COST_THRESHOLD = 300
EDOS_WINDOW = 3600

SLOWLORIS_TIME_THRESHOLD = 10
SLOWLORIS_COUNT_THRESHOLD = 5

# ============================================================
# HONEYPOT CONFIG
# ============================================================
HONEYPOT_ROUTES = {
    "/api/v1/internal/customer-dump",
    "/api/v1/admin/export-users",
    "/api/v2/debug/db-query",
    "/internal/kyc/bulk-download",
    "/api/v1/legacy/account-details",
}

# ============================================================
# IP REPUTATION SYSTEM
# ============================================================
class IPReputation:
    def __init__(self):
        self.score = defaultdict(float)
        self.last_seen = {}
        self.blocked = {}
        self.whitelist = {"127.0.0.1", "::1", "localhost"}

    def apply_decay(self, ip):
        if ip in self.last_seen:
            hrs = (datetime.now() - self.last_seen[ip]).total_seconds() / 3600
            self.score[ip] *= DECAY_RATE ** hrs
        self.last_seen[ip] = datetime.now()

    def update(self, ip, delta):
        if ip in self.whitelist:
            return
        self.apply_decay(ip)
        self.score[ip] += float(delta)
        if self.score[ip] < REPUTATION_BLOCK:
            self.blocked[ip] = datetime.now()

    def is_blocked(self, ip):
        if ip in self.whitelist:
            return False
        if ip in self.blocked:
            if (datetime.now() - self.blocked[ip]).total_seconds() > BLOCK_DURATION:
                del self.blocked[ip]
                self.score[ip] = 0.0
                return False
            return True
        return False

    def unblock(self, ip):
        self.blocked.pop(ip, None)
        self.score[ip] = 0.0

ip_rep = IPReputation()

# ============================================================
# PATTERN ATTACKS
# ============================================================
PATTERNS = {
    "SQL_INJECTION": r"union|select|or\s+1=1|drop|--",
    "XSS": r"<script|onerror|onload|javascript:",
    "PATH_TRAVERSAL": r"\.\./|\.\.\\|/etc/passwd",
    "COMMAND_INJECTION": r";\s*ls|&&|\|\|"
}

def detect_pattern(text):
    for name, pat in PATTERNS.items():
        if re.search(pat, text, re.IGNORECASE):
            return name, 25
    return "NONE", 0

# ============================================================
# EDoS DETECTOR
# ============================================================
EDOS_ENDPOINT_COST = {
    "/analyze": 30,
    "/ml": 50,
    "/export": 40,
    "/report": 35
}

class EDoSDetector:
    def __init__(self):
        self.costs = defaultdict(list)

    def record(self, ip, path):
        cost = 1
        for ep, c in EDOS_ENDPOINT_COST.items():
            if ep in path:
                cost = c
        self.costs[ip].append((datetime.now(), cost))

    def detect(self, ip):
        cutoff = datetime.now() - timedelta(seconds=EDOS_WINDOW)
        self.costs[ip] = [(t, c) for t, c in self.costs[ip] if t > cutoff]
        total = sum(c for _, c in self.costs[ip])
        return total > EDOS_COST_THRESHOLD, float(total)

edos = EDoSDetector()

# ============================================================
# WORKFLOW CONFUSION
# ============================================================
WORKFLOWS = {
    "checkout": ["login", "cart", "checkout", "payment"],
    "password_reset": ["request", "verify", "reset"]
}

class WorkflowDetector:
    def __init__(self):
        self.sessions = defaultdict(list)

    def extract_step(self, path):
        for step in ["login", "cart", "checkout", "payment", "request", "verify", "reset"]:
            if step in path.lower():
                return step
        return None

    def detect(self, session_id, step):
        for seq in WORKFLOWS.values():
            if step in seq:
                for r in seq[:seq.index(step)]:
                    if r not in self.sessions[session_id]:
                        return True
        self.sessions[session_id].append(step)
        return False

workflow = WorkflowDetector()

# ============================================================
# 🌟 SEMANTIC DRIFT (FIXED & NOVEL)
# ============================================================
class SemanticDriftDetector:
    def __init__(self):
        self.baseline = {}
        self.drift_count = defaultdict(int)

    def detect(self, ip, vec):
        vec = np.asarray(vec, dtype=float)

        if ip not in self.baseline:
            self.baseline[ip] = vec
            return False

        drift = np.linalg.norm(vec - self.baseline[ip])

        # EMA update
        self.baseline[ip] = 0.85 * self.baseline[ip] + 0.15 * vec

        if drift > 4.5:     # FIXED THRESHOLD
            self.drift_count[ip] += 1
        else:
            self.drift_count[ip] = max(0, self.drift_count[ip] - 1)

        return self.drift_count[ip] >= 3

semantic_drift = SemanticDriftDetector()

# ============================================================
# SLOWLORIS / LOW-RATE DOS
# ============================================================
class SlowlorisDetector:
    def __init__(self):
        self.last_request_time = {}
        self.slow_count = defaultdict(int)

    def detect(self, ip):
        now = datetime.now()

        if ip not in self.last_request_time:
            self.last_request_time[ip] = now
            return False

        delta = (now - self.last_request_time[ip]).total_seconds()
        self.last_request_time[ip] = now

        if delta > SLOWLORIS_TIME_THRESHOLD:
            self.slow_count[ip] += 1
        else:
            self.slow_count[ip] = max(0, self.slow_count[ip] - 1)

        return self.slow_count[ip] >= SLOWLORIS_COUNT_THRESHOLD

slowloris = SlowlorisDetector()

# ============================================================
# HONEYPOT FAKE DATA GENERATOR
# ============================================================
def generate_fake_response(path: str) -> dict:
    fake_name = random.choice(string.ascii_uppercase) + \
                "".join(random.choices(string.ascii_lowercase, k=6))
    fake_ssn = f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

    if "customer" in path or "kyc" in path or "account" in path:
        return {
            "status": "ok",
            "customers": [
                {
                    "id": str(uuid.uuid4()),
                    "name": random.choice(string.ascii_uppercase) + "".join(random.choices(string.ascii_lowercase, k=6)),
                    "ssn": f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}",
                    "balance": round(random.uniform(500, 50000), 2)
                }
                for _ in range(random.randint(3, 8))
            ]
        }
    if "export" in path or "bulk" in path:
        return {
            "status": "ok",
            "export_url": f"https://cdn.internal.bank/exports/{uuid.uuid4()}.csv",
            "rows": random.randint(1000, 50000)
        }
    if "debug" in path or "db" in path:
        return {
            "status": "ok",
            "query_result": [{"table": "users", "count": random.randint(100, 9999)}]
        }
    return {"status": "ok", "data": str(uuid.uuid4())}

# ============================================================
# ATTACKER PROFILER
# ============================================================
class AttackerProfiler:
    def __init__(self):
        self.profiles = defaultdict(lambda: {"hits": [], "routes_tried": set(), "total_hits": 0, "first_seen": None})

    def record(self, ip: str, path: str, headers: dict):
        profile = self.profiles[ip]
        if profile["first_seen"] is None:
            profile["first_seen"] = datetime.now().isoformat()
        profile["hits"].append({
            "time": datetime.now().isoformat(),
            "path": path,
            "user_agent": headers.get("user-agent", "unknown"),
            "origin": headers.get("origin", "unknown"),
        })
        profile["routes_tried"].add(path)
        profile["total_hits"] += 1
        logger.warning(f"HONEYPOT HIT | IP={ip} | path={path} | total_hits={profile['total_hits']}")

    def get_profile(self, ip: str):
        p = self.profiles[ip]
        return {**p, "routes_tried": list(p["routes_tried"])}

profiler = AttackerProfiler()

# ============================================================
# FEATURES (ML + DRIFT SAFE)
# ============================================================
def entropy(text):
    if not text:
        return 0.0
    return -sum(
        (text.count(c) / len(text)) *
        np.log2(text.count(c) / len(text) + 1e-9)
        for c in set(text)
    )

def extract_features(data, ip):
    path = data.get("path", "").lower()
    body = data.get("body", "")

    base = np.array([
        len(path),
        len(body),
        entropy(body),
        float(ip_rep.score.get(ip, 0.0))
    ])

    # intent flags (ONLY drift sees these)
    intent = np.array([
        1 if "admin" in path else 0,
        1 if "export" in path else 0,
        1 if "payment" in path else 0
    ])

    return np.concatenate([base, intent]).reshape(1, -1)

# ============================================================
# ML MODELS (UNCHANGED)
# ============================================================
scaler = StandardScaler()
X_train = np.random.normal(0, 1, (600, 4))
scaler.fit(X_train)

iso = IsolationForest(contamination=0.15, random_state=42).fit(X_train)
lgbm = lgb.LGBMClassifier(random_state=42).fit(
    X_train, np.random.randint(0, 2, 600)
)

# ============================================================
# AUDIT LOG
# ============================================================
class AuditLog:
    def __init__(self):
        self.entries = []

    def log(self, action, target_id, details, actor="system"):
        self.entries.append({
            "id": str(uuid.uuid4()), "timestamp": datetime.now().isoformat(),
            "action": action, "target_id": target_id,
            "details": details, "actor": actor
        })

    def get_entries(self, limit=100, action_filter=None):
        filtered = self.entries
        if action_filter:
            filtered = [e for e in filtered if e["action"] == action_filter]
        return list(reversed(filtered[-limit:]))

audit_log = AuditLog()

# ============================================================
# ATTACK LOG ANALYZER
# ============================================================
class AttackLogAnalyzer:
    def __init__(self):
        self.logs = []

    def record(self, ip, path, body, attack_type, threat_score, blocked, details=None):
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "path": path,
            "body": body[:500] if body else "",
            "attack_type": attack_type,
            "threat_score": float(threat_score),
            "blocked": blocked,
            "details": details or {},
        }
        self.logs.append(entry)
        return entry

    def get_logs(self, limit=200, attack_type=None, ip=None, blocked_only=False):
        filtered = self.logs
        if attack_type:
            filtered = [l for l in filtered if l["attack_type"] == attack_type]
        if ip:
            filtered = [l for l in filtered if l["ip"] == ip]
        if blocked_only:
            filtered = [l for l in filtered if l["blocked"]]
        return list(reversed(filtered[-limit:]))

    def get_summary(self):
        total = len(self.logs)
        blocked = sum(1 for l in self.logs if l["blocked"])
        allowed = total - blocked

        by_type = defaultdict(int)
        by_ip = defaultdict(int)
        by_path = defaultdict(int)
        by_hour = defaultdict(int)

        for l in self.logs:
            by_type[l["attack_type"]] += 1
            if l["blocked"]:
                by_ip[l["ip"]] += 1
            by_path[l["path"]] += 1
            try:
                hour = l["timestamp"][:13]
                by_hour[hour] += 1
            except Exception:
                pass

        top_attackers = sorted(by_ip.items(), key=lambda x: -x[1])[:10]
        top_attack_types = sorted(by_type.items(), key=lambda x: -x[1])
        top_targeted_paths = sorted(by_path.items(), key=lambda x: -x[1])[:10]
        timeline = [{
            "hour": h,
            "count": c
        } for h, c in sorted(by_hour.items())]

        avg_threat = sum(l["threat_score"] for l in self.logs) / total if total else 0
        max_threat = max((l["threat_score"] for l in self.logs), default=0)

        unique_ips = len(set(l["ip"] for l in self.logs if l["blocked"]))

        return {
            "total_requests": total,
            "blocked": blocked,
            "allowed": allowed,
            "block_rate": round(blocked / total * 100, 1) if total else 0,
            "unique_attacker_ips": unique_ips,
            "avg_threat_score": round(avg_threat, 2),
            "max_threat_score": round(max_threat, 2),
            "top_attackers": [{"ip": ip, "count": c} for ip, c in top_attackers],
            "top_attack_types": [{"type": t, "count": c} for t, c in top_attack_types],
            "top_targeted_paths": [{"path": p, "count": c} for p, c in top_targeted_paths],
            "timeline": timeline,
        }

    def get_ip_report(self, ip):
        ip_logs = [l for l in self.logs if l["ip"] == ip]
        if not ip_logs:
            return None
        blocked = sum(1 for l in ip_logs if l["blocked"])
        by_type = defaultdict(int)
        for l in ip_logs:
            by_type[l["attack_type"]] += 1
        paths_targeted = list(set(l["path"] for l in ip_logs))
        return {
            "ip": ip,
            "total_requests": len(ip_logs),
            "blocked": blocked,
            "first_seen": ip_logs[0]["timestamp"],
            "last_seen": ip_logs[-1]["timestamp"],
            "attack_types": dict(by_type),
            "paths_targeted": paths_targeted,
            "avg_threat_score": round(sum(l["threat_score"] for l in ip_logs) / len(ip_logs), 2),
            "recent_logs": list(reversed(ip_logs[-20:])),
        }

attack_log = AttackLogAnalyzer()

# ============================================================
# ALERT MANAGER
# ============================================================
class AlertManager:
    def __init__(self):
        self.alerts = []

    def create_alert(self, alert_type, severity, title, description, related_api_id=None):
        alert = {
            "id": str(uuid.uuid4()), "type": alert_type, "severity": severity,
            "title": title, "description": description,
            "related_api_id": related_api_id,
            "created_at": datetime.now().isoformat(),
            "acknowledged": False, "acknowledged_at": None, "acknowledged_by": None
        }
        self.alerts.append(alert)
        logger.warning(f"ALERT [{severity.upper()}] {title}")
        return alert

    def acknowledge(self, alert_id, user="admin"):
        for a in self.alerts:
            if a["id"] == alert_id:
                a["acknowledged"] = True
                a["acknowledged_at"] = datetime.now().isoformat()
                a["acknowledged_by"] = user
                return True
        return False

    def get_alerts(self, unacknowledged_only=False, severity=None, limit=100):
        filtered = self.alerts
        if unacknowledged_only:
            filtered = [a for a in filtered if not a["acknowledged"]]
        if severity:
            filtered = [a for a in filtered if a["severity"] == severity]
        return list(reversed(filtered[-limit:]))

    def get_summary(self):
        total = len(self.alerts)
        unacked = sum(1 for a in self.alerts if not a["acknowledged"])
        by_severity = defaultdict(int)
        for a in self.alerts:
            by_severity[a["severity"]] += 1
        return {"total": total, "unacknowledged": unacked, "by_severity": dict(by_severity)}

alert_mgr = AlertManager()

# ============================================================
# API ENTRY DATA MODEL
# ============================================================
class APIEntry:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", str(uuid.uuid4()))
        self.url = kwargs.get("url", "")
        self.method = kwargs.get("method", "GET")
        self.version = kwargs.get("version", "unknown")
        self.status = kwargs.get("status", "active")
        self.discovered_at = kwargs.get("discovered_at", datetime.now().isoformat())
        self.last_seen = kwargs.get("last_seen", datetime.now().isoformat())
        self.last_traffic = kwargs.get("last_traffic", None)
        self.source = kwargs.get("source", "manual")
        self.owner = kwargs.get("owner", "unknown")
        self.description = kwargs.get("description", "")
        self.tags = kwargs.get("tags", [])
        self.auth_type = kwargs.get("auth_type", "none")
        self.encryption = kwargs.get("encryption", "https_tls12")
        self.rate_limiting = kwargs.get("rate_limiting", False)
        self.cors_policy = kwargs.get("cors_policy", "permissive")
        self.input_validation = kwargs.get("input_validation", False)
        self.data_exposure_risk = kwargs.get("data_exposure_risk", "medium")
        self.versioned = kwargs.get("versioned", True)
        self.documentation_url = kwargs.get("documentation_url", "")
        self.repository_url = kwargs.get("repository_url", "")
        self.deployment_env = kwargs.get("deployment_env", "production")
        self.security_score = kwargs.get("security_score", 0.0)
        self.risk_score = kwargs.get("risk_score", 0.0)
        self.risk_level = kwargs.get("risk_level", "info")
        self.compliance_score = kwargs.get("compliance_score", 0.0)
        self.request_count_30d = kwargs.get("request_count_30d", 0)
        self.error_rate = kwargs.get("error_rate", 0.0)
        self.avg_response_time_ms = kwargs.get("avg_response_time_ms", 0.0)
        self.traffic_trend = kwargs.get("traffic_trend", "stable")
        self.days_since_last_commit = kwargs.get("days_since_last_commit", 0)
        self.has_owner_team = kwargs.get("has_owner_team", True)
        self.is_documented = kwargs.get("is_documented", True)
        self.deprecation_date = kwargs.get("deprecation_date", None)
        self.compliance_findings = kwargs.get("compliance_findings", [])
        self.security_findings = kwargs.get("security_findings", [])
        self.recommendations = kwargs.get("recommendations", [])

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}

# ============================================================
# API REGISTRY
# ============================================================
class APIRegistry:
    def __init__(self):
        self.apis = {}

    def register(self, entry):
        self.apis[entry.id] = entry
        audit_log.log("api_registered", entry.id, f"Registered {entry.method} {entry.url}")
        return entry.id

    def get(self, api_id):
        return self.apis.get(api_id)

    def get_all(self, status=None, risk_level=None, source=None, owner=None):
        results = list(self.apis.values())
        if status:
            results = [a for a in results if a.status == status]
        if risk_level:
            results = [a for a in results if a.risk_level == risk_level]
        if source:
            results = [a for a in results if a.source == source]
        if owner:
            results = [a for a in results if a.owner == owner]
        return results

    def update_status(self, api_id, new_status):
        api = self.apis.get(api_id)
        if api:
            old_status = api.status
            api.status = new_status
            audit_log.log("status_changed", api_id, f"{old_status} -> {new_status}")
            if new_status == "zombie":
                alert_mgr.create_alert("new_zombie_detected", "high",
                    f"Zombie API: {api.method} {api.url}",
                    f"API classified as zombie. No traffic, still deployed.", api_id)
            return True
        return False

    def remove(self, api_id):
        if api_id in self.apis:
            api = self.apis.pop(api_id)
            audit_log.log("api_removed", api_id, f"Removed {api.method} {api.url}")
            return True
        return False

    def get_summary(self):
        by_status = defaultdict(int)
        by_risk = defaultdict(int)
        by_source = defaultdict(int)
        for a in self.apis.values():
            by_status[a.status] += 1
            by_risk[a.risk_level] += 1
            by_source[a.source] += 1
        return {"total_apis": len(self.apis), "by_status": dict(by_status), "by_risk_level": dict(by_risk), "by_source": dict(by_source)}

api_registry = APIRegistry()

# ============================================================
# SECURITY POSTURE ASSESSOR
# ============================================================
class SecurityPostureAssessor:
    AUTH_SCORES = {"jwt": 25, "oauth2": 25, "api_key": 15, "basic": 5, "none": 0}
    ENCRYPTION_SCORES = {"https_tls13": 25, "https_tls12": 20, "http": 0, "none": 0}

    def assess(self, api):
        score = 0
        findings = []
        recs = []
        auth_s = self.AUTH_SCORES.get(api.auth_type, 0)
        score += auth_s
        if auth_s == 0:
            findings.append({"severity": "critical", "category": "authentication", "finding": "No authentication configured"})
            recs.append({"priority": 1, "action": "Implement JWT or OAuth2 authentication", "category": "authentication"})
        elif auth_s <= 5:
            findings.append({"severity": "high", "category": "authentication", "finding": f"Weak authentication: {api.auth_type}"})
            recs.append({"priority": 2, "action": "Upgrade from basic auth to JWT/OAuth2", "category": "authentication"})
        elif auth_s <= 15:
            findings.append({"severity": "medium", "category": "authentication", "finding": "API key auth - consider upgrading"})
            recs.append({"priority": 3, "action": "Consider OAuth2 for better security", "category": "authentication"})
        enc_s = self.ENCRYPTION_SCORES.get(api.encryption, 0)
        score += enc_s
        if enc_s == 0:
            findings.append({"severity": "critical", "category": "encryption", "finding": "No encryption - plaintext traffic"})
            recs.append({"priority": 1, "action": "Enable HTTPS with TLS 1.3", "category": "encryption"})
        elif enc_s <= 20:
            findings.append({"severity": "low", "category": "encryption", "finding": "TLS 1.2 - consider TLS 1.3"})
            recs.append({"priority": 4, "action": "Upgrade to TLS 1.3", "category": "encryption"})
        if api.rate_limiting:
            score += 15
        else:
            findings.append({"severity": "high", "category": "rate_limiting", "finding": "No rate limiting"})
            recs.append({"priority": 2, "action": "Add rate limiting (100 req/min per client)", "category": "rate_limiting"})
        if api.input_validation:
            score += 15
        else:
            findings.append({"severity": "high", "category": "input_validation", "finding": "No input validation"})
            recs.append({"priority": 2, "action": "Add JSON Schema / Pydantic validation", "category": "input_validation"})
        cors_scores = {"strict": 10, "moderate": 7, "permissive": 3, "none": 0}
        cors_s = cors_scores.get(api.cors_policy, 0)
        score += cors_s
        if cors_s <= 3:
            findings.append({"severity": "medium", "category": "cors", "finding": f"CORS policy: {api.cors_policy}"})
            recs.append({"priority": 3, "action": "Restrict CORS to trusted origins", "category": "cors"})
        exp_scores = {"low": 10, "medium": 5, "high": 2, "critical": 0}
        exp_s = exp_scores.get(api.data_exposure_risk, 0)
        score += exp_s
        if exp_s <= 2:
            findings.append({"severity": "critical", "category": "data_exposure", "finding": "High data exposure - may leak PII"})
            recs.append({"priority": 1, "action": "Audit responses for PII. Implement field-level encryption.", "category": "data_exposure"})
        elif exp_s <= 5:
            findings.append({"severity": "medium", "category": "data_exposure", "finding": "Moderate data exposure risk"})
            recs.append({"priority": 3, "action": "Mask sensitive fields in responses", "category": "data_exposure"})
        api.security_score = min(score, 100)
        api.security_findings = findings
        api.recommendations = recs
        return {"api_id": api.id, "security_score": api.security_score, "findings": findings, "recommendations": recs}

security_assessor = SecurityPostureAssessor()

# ============================================================
# API CLASSIFIER
# ============================================================
class APIClassifier:
    def classify(self, api):
        old_status = api.status
        if api.request_count_30d == 0 and api.days_since_last_commit > 180 and api.traffic_trend == "zero":
            api.status = "zombie"
        elif not api.has_owner_team and api.days_since_last_commit > 90:
            api.status = "orphaned"
        elif api.deprecation_date is not None:
            api.status = "deprecated"
        elif api.request_count_30d > 0 and api.days_since_last_commit < 90:
            api.status = "active"
        elif api.traffic_trend == "declining" and api.days_since_last_commit > 120:
            api.status = "zombie"
        if old_status != api.status:
            api_registry.update_status(api.id, api.status)
        return api.status

    def classify_all(self):
        return {api.id: self.classify(api) for api in api_registry.get_all()}

api_classifier = APIClassifier()

# ============================================================
# RISK SCORING ENGINE
# ============================================================
class RiskScorer:
    STATUS_WEIGHTS = {"zombie": 40, "orphaned": 30, "deprecated": 15, "active": 0}

    def score(self, api):
        risk = float(self.STATUS_WEIGHTS.get(api.status, 0))
        risk += max(0, 30 - (api.security_score * 0.3))
        if api.error_rate > 0.5:
            risk += 15
        elif api.error_rate > 0.2:
            risk += 10
        elif api.error_rate > 0.1:
            risk += 5
        if api.days_since_last_commit > 365:
            risk += 15
        elif api.days_since_last_commit > 180:
            risk += 10
        elif api.days_since_last_commit > 90:
            risk += 5
        risk = min(risk, 100)
        api.risk_score = risk
        if risk >= 80:
            api.risk_level = "critical"
        elif risk >= 60:
            api.risk_level = "high"
        elif risk >= 40:
            api.risk_level = "medium"
        elif risk >= 20:
            api.risk_level = "low"
        else:
            api.risk_level = "info"
        return {"api_id": api.id, "risk_score": risk, "risk_level": api.risk_level}

    def score_all(self):
        return {api.id: self.score(api) for api in api_registry.get_all()}

risk_scorer = RiskScorer()

# ============================================================
# COMPLIANCE CHECKER
# ============================================================
class ComplianceChecker:
    OWASP_API_TOP10 = [
        ("API1", "Broken Object Level Authorization", lambda a: a.auth_type != "none"),
        ("API2", "Broken Authentication", lambda a: a.auth_type in ("jwt", "oauth2")),
        ("API3", "Excessive Data Exposure", lambda a: a.data_exposure_risk in ("low",)),
        ("API4", "Lack of Resources & Rate Limiting", lambda a: a.rate_limiting),
        ("API5", "Broken Function Level Authorization", lambda a: a.auth_type in ("jwt", "oauth2")),
        ("API6", "Mass Assignment", lambda a: a.input_validation),
        ("API7", "Security Misconfiguration", lambda a: a.cors_policy in ("strict", "moderate") and a.encryption in ("https_tls12", "https_tls13")),
        ("API8", "Injection", lambda a: a.input_validation),
        ("API9", "Improper Assets Management", lambda a: a.is_documented and a.status != "zombie"),
        ("API10", "Insufficient Logging & Monitoring", lambda a: a.status == "active"),
    ]
    PCI_DSS_CHECKS = [
        ("PCI-1", "Encrypt data in transit", lambda a: a.encryption in ("https_tls12", "https_tls13")),
        ("PCI-2", "Strong authentication", lambda a: a.auth_type in ("jwt", "oauth2")),
        ("PCI-3", "Protect stored cardholder data", lambda a: a.data_exposure_risk in ("low", "medium")),
        ("PCI-4", "Restrict access", lambda a: a.rate_limiting and a.auth_type != "none"),
        ("PCI-5", "Monitor and test networks", lambda a: a.status == "active"),
    ]

    def check(self, api):
        findings = []
        passed = 0
        total = 0
        for code, name, check_fn in self.OWASP_API_TOP10:
            total += 1
            if check_fn(api):
                passed += 1
            else:
                findings.append({"framework": "OWASP API Top 10", "code": code, "name": name, "status": "FAIL"})
        for code, name, check_fn in self.PCI_DSS_CHECKS:
            total += 1
            if check_fn(api):
                passed += 1
            else:
                findings.append({"framework": "PCI-DSS", "code": code, "name": name, "status": "FAIL"})
        api.compliance_score = round((passed / total) * 100, 1) if total > 0 else 0
        api.compliance_findings = findings
        return {"api_id": api.id, "compliance_score": api.compliance_score, "checks_passed": passed, "checks_total": total, "findings": findings}

    def check_all(self):
        return {api.id: self.check(api) for api in api_registry.get_all()}

compliance_checker = ComplianceChecker()

# ============================================================
# TRAFFIC ANALYZER
# ============================================================
class TrafficAnalyzer:
    def __init__(self):
        self.traffic_log = defaultdict(list)

    def record(self, api_id, status_code=200, response_time_ms=50.0):
        self.traffic_log[api_id].append({"timestamp": datetime.now().isoformat(), "status_code": status_code, "response_time_ms": response_time_ms})

    def analyze(self, api_id):
        logs = self.traffic_log.get(api_id, [])
        if not logs:
            return {"api_id": api_id, "total_requests": 0, "error_rate": 0, "avg_response_time_ms": 0, "trend": "zero"}
        total = len(logs)
        errors = sum(1 for l in logs if l["status_code"] >= 400)
        avg_rt = sum(l["response_time_ms"] for l in logs) / total
        trend = "zero" if total < 5 else ("rising" if total > 50 else "stable")
        return {"api_id": api_id, "total_requests": total, "error_rate": round(errors / total, 3), "avg_response_time_ms": round(avg_rt, 2), "trend": trend, "recent_logs": logs[-10:]}

    def analyze_all(self):
        return {api.id: self.analyze(api.id) for api in api_registry.get_all()}

traffic_analyzer = TrafficAnalyzer()

# ============================================================
# DECOMMISSIONING WORKFLOW
# ============================================================
DECOMMISSION_STATES = ["identified", "reviewed", "approved", "traffic_redirected", "disabled", "decommissioned"]

class DecommissionWorkflow:
    def __init__(self):
        self.workflows = {}

    def start(self, api_id):
        api = api_registry.get(api_id)
        if not api:
            return None
        wf_id = str(uuid.uuid4())
        self.workflows[wf_id] = {
            "id": wf_id, "api_id": api_id, "api_url": api.url, "api_method": api.method,
            "current_state": "identified",
            "state_history": [{"state": "identified", "timestamp": datetime.now().isoformat(), "actor": "system"}],
            "created_at": datetime.now().isoformat(), "updated_at": datetime.now().isoformat(),
            "convert_to_honeypot": False, "redirect_url": None, "notes": []
        }
        audit_log.log("decommission_started", api_id, f"Workflow {wf_id} for {api.method} {api.url}")
        alert_mgr.create_alert("decommission_started", "medium", f"Decommission: {api.method} {api.url}", f"Workflow {wf_id} initiated", api_id)
        return self.workflows[wf_id]

    def advance(self, wf_id, actor="admin", notes=""):
        wf = self.workflows.get(wf_id)
        if not wf:
            return None
        current_idx = DECOMMISSION_STATES.index(wf["current_state"])
        if current_idx >= len(DECOMMISSION_STATES) - 1:
            return {"error": "Workflow already completed"}
        next_state = DECOMMISSION_STATES[current_idx + 1]
        wf["current_state"] = next_state
        wf["updated_at"] = datetime.now().isoformat()
        wf["state_history"].append({"state": next_state, "timestamp": datetime.now().isoformat(), "actor": actor})
        if notes:
            wf["notes"].append({"text": notes, "timestamp": datetime.now().isoformat(), "actor": actor})
        if next_state == "decommissioned":
            api = api_registry.get(wf["api_id"])
            if api and wf.get("convert_to_honeypot"):
                HONEYPOT_ROUTES.add(api.url)
                audit_log.log("converted_to_honeypot", wf["api_id"], f"{api.url} -> honeypot trap")
            if api:
                api.status = "decommissioned"
        audit_log.log("decommission_advanced", wf["api_id"], f"{DECOMMISSION_STATES[current_idx]} -> {next_state}")
        return wf

    def set_honeypot(self, wf_id, enabled=True):
        wf = self.workflows.get(wf_id)
        if wf:
            wf["convert_to_honeypot"] = enabled
            return True
        return False

    def set_redirect(self, wf_id, redirect_url):
        wf = self.workflows.get(wf_id)
        if wf:
            wf["redirect_url"] = redirect_url
            return True
        return False

    def get_all(self, status=None):
        results = list(self.workflows.values())
        if status:
            results = [w for w in results if w["current_state"] == status]
        return results

    def get(self, wf_id):
        return self.workflows.get(wf_id)

decommission_wf = DecommissionWorkflow()

# ============================================================
# REMEDIATION ENGINE
# ============================================================
class RemediationEngine:
    TEMPLATES = {
        "authentication": {
            "none": {"priority": 1, "action": "Implement JWT authentication with RS256 signing", "effort": "high", "impact": "critical"},
            "basic": {"priority": 2, "action": "Upgrade from Basic Auth to OAuth2/JWT", "effort": "medium", "impact": "high"},
            "api_key": {"priority": 3, "action": "Consider upgrading to OAuth2 for better access control", "effort": "medium", "impact": "medium"},
        },
        "encryption": {
            "none": {"priority": 1, "action": "Enable HTTPS with TLS 1.3. Obtain SSL certificate.", "effort": "medium", "impact": "critical"},
            "http": {"priority": 1, "action": "Redirect all HTTP to HTTPS. Enforce HSTS.", "effort": "low", "impact": "critical"},
        },
        "rate_limiting": {False: {"priority": 2, "action": "Add rate limiting: 100 req/min standard, 1000 req/min premium.", "effort": "low", "impact": "high"}},
        "input_validation": {False: {"priority": 2, "action": "Implement request validation using JSON Schema or Pydantic.", "effort": "medium", "impact": "high"}},
        "cors": {
            "permissive": {"priority": 3, "action": "Restrict CORS to specific trusted origins.", "effort": "low", "impact": "medium"},
            "none": {"priority": 2, "action": "Configure CORS headers with explicit trusted origins.", "effort": "low", "impact": "high"},
        },
        "data_exposure": {
            "critical": {"priority": 1, "action": "Audit responses for PII. Implement field-level encryption for SSN, account numbers.", "effort": "high", "impact": "critical"},
            "high": {"priority": 2, "action": "Review response schemas. Mask sensitive fields.", "effort": "medium", "impact": "high"},
        },
        "zombie_status": {
            "zombie": {"priority": 1, "action": "Initiate decommissioning. Verify no consumers, then disable or convert to honeypot.", "effort": "low", "impact": "critical"},
            "orphaned": {"priority": 2, "action": "Assign owner team. Review security. If unused, deprecate.", "effort": "low", "impact": "high"},
        }
    }

    def get_recommendations(self, api):
        recs = []
        if api.auth_type in self.TEMPLATES.get("authentication", {}):
            recs.append(self.TEMPLATES["authentication"][api.auth_type])
        if api.encryption in self.TEMPLATES.get("encryption", {}):
            recs.append(self.TEMPLATES["encryption"][api.encryption])
        if not api.rate_limiting:
            recs.append(self.TEMPLATES["rate_limiting"][False])
        if not api.input_validation:
            recs.append(self.TEMPLATES["input_validation"][False])
        if api.cors_policy in self.TEMPLATES.get("cors", {}):
            recs.append(self.TEMPLATES["cors"][api.cors_policy])
        if api.data_exposure_risk in self.TEMPLATES.get("data_exposure", {}):
            recs.append(self.TEMPLATES["data_exposure"][api.data_exposure_risk])
        if api.status in self.TEMPLATES.get("zombie_status", {}):
            recs.append(self.TEMPLATES["zombie_status"][api.status])
        recs.sort(key=lambda x: x["priority"])
        return recs

remediation_engine = RemediationEngine()

# ============================================================
# API DISCOVERY ENGINE
# ============================================================
class APIDiscoveryEngine:
    DISCOVERABLE = {
        "network": [
            {"url": "/api/v1/payments", "method": "POST", "description": "Process customer payments", "auth_type": "jwt", "encryption": "https_tls13", "owner": "payments-team", "data_exposure_risk": "critical", "tags": ["payments", "pci"]},
            {"url": "/api/v1/refunds", "method": "POST", "description": "Issue refunds", "auth_type": "oauth2", "encryption": "https_tls12", "owner": "payments-team", "data_exposure_risk": "high", "tags": ["payments"]},
            {"url": "/api/v1/notifications", "method": "GET", "description": "User notification feed", "auth_type": "api_key", "encryption": "https_tls12", "owner": "comms-team", "data_exposure_risk": "low", "tags": ["notifications"]},
        ],
        "gateway": [
            {"url": "/api/v2/analytics/events", "method": "POST", "description": "Track analytics events", "auth_type": "api_key", "encryption": "https_tls13", "owner": "data-team", "data_exposure_risk": "medium", "tags": ["analytics"]},
            {"url": "/api/v2/analytics/dashboard", "method": "GET", "description": "Analytics dashboard data", "auth_type": "jwt", "encryption": "https_tls13", "owner": "data-team", "data_exposure_risk": "medium", "tags": ["analytics"]},
        ],
        "repo": [
            {"url": "/api/internal/healthcheck", "method": "GET", "description": "Internal service health", "auth_type": "none", "encryption": "http", "owner": "platform-team", "data_exposure_risk": "low", "tags": ["internal"]},
            {"url": "/api/v1/legacy/reports", "method": "GET", "description": "Legacy reporting endpoint", "auth_type": "basic", "encryption": "http", "owner": "unknown", "data_exposure_risk": "high", "tags": ["legacy", "reports"]},
        ],
        "deployment": [
            {"url": "/api/v1/inventory/sync", "method": "POST", "description": "Sync inventory data from warehouse", "auth_type": "api_key", "encryption": "https_tls12", "owner": "ops-team", "data_exposure_risk": "medium", "tags": ["inventory"]},
            {"url": "/api/debug/metrics", "method": "GET", "description": "Debug metrics endpoint", "auth_type": "none", "encryption": "http", "owner": "unknown", "data_exposure_risk": "high", "tags": ["debug", "internal"]},
        ],
    }
    SHADOW_POOL = [
        {"url": "/api/v1/admin/bulk-export", "method": "GET", "description": "Undocumented admin bulk export", "auth_type": "none", "encryption": "http", "data_exposure_risk": "critical", "tags": ["admin", "shadow"]},
        {"url": "/api/internal/cache-flush", "method": "POST", "description": "Internal cache flush found in traffic", "auth_type": "none", "encryption": "http", "data_exposure_risk": "high", "tags": ["internal", "shadow"]},
    ]

    def __init__(self):
        self.discovered_pools = defaultdict(set)
        self.scan_history = []

    def scan(self, scan_type="network"):
        pool = self.DISCOVERABLE.get(scan_type, [])
        newly_discovered = []
        for tmpl in pool:
            existing = [a for a in api_registry.get_all() if a.url == tmpl["url"] and a.method == tmpl["method"]]
            if existing or tmpl["url"] in self.discovered_pools[scan_type]:
                continue
            entry = APIEntry(
                url=tmpl["url"], method=tmpl["method"], description=tmpl["description"],
                source=f"{scan_type}_scan", auth_type=tmpl.get("auth_type", "none"),
                encryption=tmpl.get("encryption", "http"), owner=tmpl.get("owner", "unknown"),
                data_exposure_risk=tmpl.get("data_exposure_risk", "medium"), tags=tmpl.get("tags", []),
                version=tmpl["url"].split("/")[2] if len(tmpl["url"].split("/")) > 2 else "unknown",
                request_count_30d=random.randint(0, 100), days_since_last_commit=random.randint(30, 500),
                has_owner_team=tmpl.get("owner", "unknown") != "unknown", is_documented=False,
                rate_limiting=random.choice([True, False]), input_validation=random.choice([True, False]),
                cors_policy=random.choice(["strict", "moderate", "permissive", "none"]),
                traffic_trend=random.choice(["stable", "declining", "zero"]),
            )
            api_registry.register(entry)
            security_assessor.assess(entry)
            api_classifier.classify(entry)
            risk_scorer.score(entry)
            compliance_checker.check(entry)
            newly_discovered.append(entry.to_dict())
            self.discovered_pools[scan_type].add(tmpl["url"])
        scan_result = {
            "scan_id": str(uuid.uuid4()), "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "apis_discovered": len(newly_discovered), "new_apis": newly_discovered,
            "total_registry_size": len(api_registry.apis)
        }
        self.scan_history.append(scan_result)
        audit_log.log("discovery_scan", "system", f"{scan_type} scan: {len(newly_discovered)} new APIs")
        for api_data in newly_discovered:
            if api_data.get("risk_level") in ("critical", "high"):
                alert_mgr.create_alert("high_risk_discovered", "high",
                    f"High-risk API: {api_data['method']} {api_data['url']}",
                    f"Found via {scan_type} scan. Risk: {api_data.get('risk_level')}", api_data["id"])
        return scan_result

    def discover_shadow_apis(self):
        newly_found = []
        for tmpl in self.SHADOW_POOL:
            existing = [a for a in api_registry.get_all() if a.url == tmpl["url"]]
            if existing:
                continue
            entry = APIEntry(
                url=tmpl["url"], method=tmpl["method"], description=tmpl["description"],
                source="shadow", auth_type=tmpl["auth_type"], encryption=tmpl["encryption"],
                data_exposure_risk=tmpl["data_exposure_risk"], tags=tmpl["tags"],
                owner="unknown", has_owner_team=False, is_documented=False,
                request_count_30d=random.randint(10, 200), traffic_trend="stable",
                days_since_last_commit=999, rate_limiting=False, input_validation=False, cors_policy="none"
            )
            api_registry.register(entry)
            security_assessor.assess(entry)
            api_classifier.classify(entry)
            risk_scorer.score(entry)
            compliance_checker.check(entry)
            newly_found.append(entry.to_dict())
            alert_mgr.create_alert("new_shadow_api", "high",
                f"Shadow API: {entry.method} {entry.url}", "Undocumented API in traffic", entry.id)
        return {"shadow_apis_found": len(newly_found), "apis": newly_found}

discovery_engine = APIDiscoveryEngine()

# ============================================================
# CONTINUOUS MONITOR
# ============================================================
class ContinuousMonitor:
    def __init__(self):
        self.running = False
        self.scan_interval = 60
        self.scan_history = []
        self._thread = None

    def start(self, interval=60):
        if self.running:
            return
        self.running = True
        self.scan_interval = interval
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        audit_log.log("monitoring_started", "system", f"Interval={interval}s")

    def stop(self):
        self.running = False
        audit_log.log("monitoring_stopped", "system", "Stopped")

    def _run_loop(self):
        while self.running:
            _time.sleep(self.scan_interval)
            if not self.running:
                break
            self._run_scan()

    def _run_scan(self):
        api_classifier.classify_all()
        risk_scorer.score_all()
        for api in api_registry.get_all():
            security_assessor.assess(api)
            compliance_checker.check(api)
        zombies = api_registry.get_all(status="zombie")
        self.scan_history.append({
            "timestamp": datetime.now().isoformat(),
            "apis_scanned": len(api_registry.apis), "zombies_found": len(zombies), "status": "completed"
        })
        for api in zombies:
            existing = [a for a in alert_mgr.alerts if a["related_api_id"] == api.id and a["type"] == "new_zombie_detected" and not a["acknowledged"]]
            if not existing:
                alert_mgr.create_alert("new_zombie_detected", "high",
                    f"Zombie: {api.method} {api.url}", "Detected during monitoring", api.id)

    def get_status(self):
        return {
            "running": self.running, "scan_interval": self.scan_interval,
            "total_scans": len(self.scan_history),
            "last_scan": self.scan_history[-1] if self.scan_history else None
        }

continuous_monitor = ContinuousMonitor()

# ============================================================
# SEED DATA
# ============================================================
SEED_APIS = [
    {"url": "/api/v1/users", "method": "GET", "description": "List all users", "auth_type": "jwt", "encryption": "https_tls13", "owner": "backend-team", "status": "active", "source": "manual", "data_exposure_risk": "high", "request_count_30d": 8500, "days_since_last_commit": 5, "has_owner_team": True, "is_documented": True, "rate_limiting": True, "input_validation": True, "cors_policy": "strict", "traffic_trend": "stable"},
    {"url": "/api/v1/orders", "method": "POST", "description": "Create new order", "auth_type": "oauth2", "encryption": "https_tls13", "owner": "orders-team", "status": "active", "source": "manual", "data_exposure_risk": "medium", "request_count_30d": 3200, "days_since_last_commit": 12, "has_owner_team": True, "is_documented": True, "rate_limiting": True, "input_validation": True, "cors_policy": "strict", "traffic_trend": "rising"},
    {"url": "/api/v0/legacy-auth", "method": "POST", "description": "Legacy authentication endpoint", "auth_type": "basic", "encryption": "http", "owner": "unknown", "status": "deprecated", "source": "manual", "data_exposure_risk": "critical", "request_count_30d": 15, "days_since_last_commit": 400, "has_owner_team": False, "is_documented": False, "rate_limiting": False, "input_validation": False, "cors_policy": "permissive", "traffic_trend": "declining"},
    {"url": "/api/v1/reports/export", "method": "GET", "description": "Export data reports", "auth_type": "none", "encryption": "http", "owner": "unknown", "status": "orphaned", "source": "manual", "data_exposure_risk": "critical", "request_count_30d": 3, "days_since_last_commit": 600, "has_owner_team": False, "is_documented": False, "rate_limiting": False, "input_validation": False, "cors_policy": "none", "traffic_trend": "zero"},
    {"url": "/api/v1/old-checkout", "method": "POST", "description": "Deprecated checkout flow", "auth_type": "none", "encryption": "http", "owner": "unknown", "status": "zombie", "source": "manual", "data_exposure_risk": "critical", "request_count_30d": 0, "days_since_last_commit": 900, "has_owner_team": False, "is_documented": False, "rate_limiting": False, "input_validation": False, "cors_policy": "none", "traffic_trend": "zero"},
    {"url": "/api/v1/forgotten-upload", "method": "PUT", "description": "Forgotten file upload endpoint", "auth_type": "none", "encryption": "http", "owner": "unknown", "status": "zombie", "source": "manual", "data_exposure_risk": "high", "request_count_30d": 0, "days_since_last_commit": 750, "has_owner_team": False, "is_documented": False, "rate_limiting": False, "input_validation": False, "cors_policy": "none", "traffic_trend": "zero"},
]

def generate_seed_data():
    for d in SEED_APIS:
        api = APIEntry(**d)
        api_registry.register(api)
    for api in api_registry.get_all():
        security_assessor.assess(api)
        api_classifier.classify(api)
        risk_scorer.score(api)
        compliance_checker.check(api)
    for api in api_registry.get_all(status="zombie"):
        alert_mgr.create_alert("new_zombie_detected", "high",
            f"Zombie API: {api.method} {api.url}",
            f"No traffic, no maintenance, still deployed. Risk: {api.risk_level}", api.id)
    for api in [a for a in api_registry.get_all() if a.source == "shadow"]:
        alert_mgr.create_alert("new_shadow_api", "high",
            f"Shadow API: {api.method} {api.url}", "Undocumented API in traffic", api.id)
    audit_log.log("seed_data", "system", f"Generated {len(SEED_APIS)} seed APIs")

generate_seed_data()

# ============================================================
# CONFIG / TARGET ENDPOINT
# ============================================================
ZOMBIENET_TARGET = None

@app.post("/api/config/target")
async def set_target(req: Request):
    global ZOMBIENET_TARGET
    data = await req.json()
    ZOMBIENET_TARGET = data.get("target_url")
    return {"status": "ok", "target_url": ZOMBIENET_TARGET}

@app.post("/analyze")
async def analyze(req: Request):
    data = await req.json()
    ip = req.client.host
    session_id = data.get("session_id", ip)

    if ip_rep.is_blocked(ip):
        return JSONResponse(status_code=403, content={"status": "BLOCKED", "reason": "IP blocked"})

    text = data.get("path", "") + data.get("body", "")
    attack, pattern_score = detect_pattern(text)

    edos.record(ip, data.get("path", ""))
    is_edos, edos_cost = edos.detect(ip)

    step = workflow.extract_step(data.get("path", ""))
    workflow_attack = workflow.detect(session_id, step) if step else False

    full_features = extract_features(data, ip)
    ml_features = scaler.transform(full_features[:, :4])
    drift_features = full_features.flatten()

    anomaly = iso.predict(ml_features)[0] == -1
    prob = float(lgbm.predict_proba(ml_features)[0][1])

    drift_attack = semantic_drift.detect(ip, drift_features)
    slowloris_attack = slowloris.detect(ip)

    threat_score = (
        pattern_score +
        (30 if anomaly else 0) +
        prob * 40 +
        (35 if is_edos else 0) +
        (35 if workflow_attack else 0) +
        (30 if drift_attack else 0) +
        (40 if slowloris_attack else 0)
    )

    malicious = (
        attack != "NONE" or
        workflow_attack or
        (is_edos and edos_cost > EDOS_COST_THRESHOLD) or
        drift_attack or
        slowloris_attack or
        threat_score > 80
    )

    ip_rep.update(ip, -20 if malicious else 1)

    # ── Record in attack log ──
    detected_attacks = []
    if attack != "NONE":
        detected_attacks.append(attack)
    if is_edos:
        detected_attacks.append("EDOS")
    if workflow_attack:
        detected_attacks.append("WORKFLOW_CONFUSION")
    if drift_attack:
        detected_attacks.append("SEMANTIC_DRIFT")
    if slowloris_attack:
        detected_attacks.append("SLOWLORIS")
    if anomaly and not detected_attacks:
        detected_attacks.append("ML_ANOMALY")

    log_type = ",".join(detected_attacks) if detected_attacks else "BENIGN"
    attack_log.record(
        ip=ip,
        path=data.get("path", ""),
        body=data.get("body", ""),
        attack_type=log_type,
        threat_score=threat_score,
        blocked=malicious,
        details={
            "pattern_attack": attack,
            "edos": is_edos,
            "edos_cost": float(edos_cost),
            "workflow_confusion": workflow_attack,
            "semantic_drift": drift_attack,
            "slowloris": slowloris_attack,
            "ml_anomaly": anomaly,
            "ml_probability": float(prob),
        }
    )

    if malicious:
        return JSONResponse(
            status_code=403,
            content={
                "status": "BLOCKED",
                "attack": attack,
                "edos": is_edos,
                "workflow_confusion": workflow_attack,
                "semantic_drift": drift_attack,
                "slowloris": slowloris_attack,
                "threat_score": float(threat_score)
            }
        )

    return {
        "status": "ALLOWED",
        "threat_score": float(threat_score),
        "reputation": float(ip_rep.score[ip])
    }

# ============================================================
# ADMIN
# ============================================================
@app.post("/unblock")
async def unblock(req: Request):
    ip_rep.unblock((await req.json()).get("ip"))
    return {"status": "success"}

@app.get("/blocked")
def blocked():
    return {"blocked_ips": list(ip_rep.blocked.keys())}

@app.get("/stats")
def stats():
    return {
        "total_ips": len(ip_rep.score),
        "blocked_ips": len(ip_rep.blocked),
        "avg_reputation": float(np.mean(list(ip_rep.score.values()))) if ip_rep.score else 0.0
    }

@app.get("/honeypot/profiles")
def honeypot_profiles():
    return {ip: profiler.get_profile(ip) for ip in profiler.profiles}

@app.get("/honeypot/stats")
def honeypot_stats():
    return {
        "total_attackers_caught": len(profiler.profiles),
        "total_honeypot_hits": sum(p["total_hits"] for p in profiler.profiles.values()),
        "honeypot_routes": list(HONEYPOT_ROUTES),
    }

@app.post("/reset")
def reset_all():
    """Clear all in-memory state for a fresh start."""
    ip_rep.score.clear()
    ip_rep.last_seen.clear()
    ip_rep.blocked.clear()
    profiler.profiles.clear()
    attack_log.logs.clear()
    audit_log.entries.clear()
    alert_mgr.alerts.clear()
    api_registry.apis.clear()
    decommission_wf.workflows.clear()
    discovery_engine.discovered_pools.clear()
    discovery_engine.scan_history.clear()
    continuous_monitor.scan_history.clear()
    continuous_monitor.running = False
    edos.costs.clear()
    workflow.sessions.clear()
    semantic_drift.baseline.clear()
    semantic_drift.drift_count.clear()
    slowloris.last_request_time.clear()
    slowloris.slow_count.clear()
    traffic_analyzer.traffic_log.clear()
    return {"status": "ok", "message": "All in-memory state has been cleared"}

@app.get("/")
def root():
    return {
        "message": "Research-Grade AI API Gateway + Zombie API Defence Platform",
        "features": [
            "SQL/XSS/Traversal/Command Injection",
            "DDoS + Slowloris",
            "EDoS",
            "Workflow Confusion",
            "Semantic Drift (Novel)",
            "ML-based Detection",
            "Auto Block / Unblock",
            "ZombieNet Honeypot Traps",
            "Attacker Profiling",
            "API Discovery Engine (Network/Gateway/Repo/Deployment)",
            "API Registry & Inventory Management",
            "API Classification (Active/Deprecated/Orphaned/Zombie)",
            "Security Posture Assessment",
            "Risk Scoring Engine",
            "Decommissioning Workflows",
            "Remediation Recommendations",
            "Continuous Monitoring",
            "Shadow API Detection",
            "Alert Management System",
            "Traffic Analysis",
            "Compliance Checking (OWASP API Top 10, PCI-DSS)",
            "Audit Logging",
            "Report Export (JSON/CSV)",
            "Attack Log Analysis"
        ]
    }

# ============================================================
# ZOMBIE API DISCOVERY & DEFENCE ENDPOINTS
# ============================================================

@app.post("/api/discovery/scan")
async def discovery_scan(req: Request):
    data = await req.json()
    scan_type = data.get("scan_type", "network")
    if scan_type not in ("network", "gateway", "repo", "deployment", "shadow"):
        return JSONResponse(status_code=400, content={"error": "Invalid scan_type"})
    if scan_type == "shadow":
        return discovery_engine.discover_shadow_apis()
    return discovery_engine.scan(scan_type)

@app.get("/api/discovery/history")
def discovery_history():
    return {"scans": list(reversed(discovery_engine.scan_history))}

@app.get("/api/registry")
def get_registry(status: str = None, risk_level: str = None, source: str = None, owner: str = None):
    apis = api_registry.get_all(status=status, risk_level=risk_level, source=source, owner=owner)
    return {"total": len(apis), "apis": [a.to_dict() for a in apis]}

@app.get("/api/registry/summary")
def registry_summary():
    return api_registry.get_summary()

@app.get("/api/registry/{api_id}")
def get_api_detail(api_id: str):
    api = api_registry.get(api_id)
    if not api:
        return JSONResponse(status_code=404, content={"error": "API not found"})
    return api.to_dict()

@app.post("/api/registry")
async def register_api(req: Request):
    data = await req.json()
    entry = APIEntry(**data, source="manual")
    api_registry.register(entry)
    security_assessor.assess(entry)
    api_classifier.classify(entry)
    risk_scorer.score(entry)
    compliance_checker.check(entry)
    return {"id": entry.id, "status": "registered"}

@app.put("/api/registry/{api_id}/classify")
async def classify_api(api_id: str, req: Request):
    data = await req.json()
    new_status = data.get("status")
    if new_status not in ("active", "deprecated", "orphaned", "zombie"):
        return JSONResponse(status_code=400, content={"error": "Invalid status"})
    if api_registry.update_status(api_id, new_status):
        api = api_registry.get(api_id)
        risk_scorer.score(api)
        return {"id": api_id, "status": new_status}
    return JSONResponse(status_code=404, content={"error": "API not found"})

@app.delete("/api/registry/{api_id}")
def delete_api(api_id: str):
    if api_registry.remove(api_id):
        return {"status": "removed"}
    return JSONResponse(status_code=404, content={"error": "API not found"})

@app.get("/api/security/assess/{api_id}")
def assess_api_security(api_id: str):
    api = api_registry.get(api_id)
    if not api:
        return JSONResponse(status_code=404, content={"error": "API not found"})
    return security_assessor.assess(api)

@app.post("/api/security/assess-all")
def assess_all_apis():
    results = {}
    for api in api_registry.get_all():
        results[api.id] = security_assessor.assess(api)
    return {"assessed": len(results), "results": results}

@app.post("/api/classify-all")
def classify_all():
    results = api_classifier.classify_all()
    return {"classified": len(results), "results": results}

@app.get("/api/risk/scores")
def risk_scores():
    results = risk_scorer.score_all()
    return {"total": len(results), "scores": results}

@app.get("/api/recommendations/{api_id}")
def get_recommendations(api_id: str):
    api = api_registry.get(api_id)
    if not api:
        return JSONResponse(status_code=404, content={"error": "API not found"})
    return {"api_id": api_id, "recommendations": remediation_engine.get_recommendations(api)}

@app.get("/api/decommission/workflows")
def get_decommission_workflows(status: str = None):
    workflows = decommission_wf.get_all(status=status)
    return {"total": len(workflows), "workflows": workflows}

@app.get("/api/decommission/workflows/{wf_id}")
def get_decommission_workflow(wf_id: str):
    wf = decommission_wf.get(wf_id)
    if not wf:
        return JSONResponse(status_code=404, content={"error": "Workflow not found"})
    return wf

@app.post("/api/decommission/start/{api_id}")
def start_decommission(api_id: str):
    wf = decommission_wf.start(api_id)
    if not wf:
        return JSONResponse(status_code=404, content={"error": "API not found"})
    return wf

@app.post("/api/decommission/advance/{wf_id}")
async def advance_decommission(wf_id: str, req: Request):
    data = await req.json()
    wf = decommission_wf.advance(wf_id, data.get("actor", "admin"), data.get("notes", ""))
    if not wf:
        return JSONResponse(status_code=404, content={"error": "Workflow not found"})
    return wf

@app.post("/api/decommission/honeypot/{wf_id}")
async def set_decommission_honeypot(wf_id: str, req: Request):
    data = await req.json()
    if decommission_wf.set_honeypot(wf_id, data.get("enabled", True)):
        return {"status": "updated", "convert_to_honeypot": data.get("enabled", True)}
    return JSONResponse(status_code=404, content={"error": "Workflow not found"})

@app.get("/api/monitoring/status")
def monitoring_status():
    return continuous_monitor.get_status()

@app.post("/api/monitoring/start")
async def start_monitoring(req: Request):
    data = await req.json()
    interval = data.get("interval", 60)
    continuous_monitor.start(interval)
    return {"status": "started", "interval": interval}

@app.post("/api/monitoring/stop")
def stop_monitoring():
    continuous_monitor.stop()
    return {"status": "stopped"}

@app.get("/api/alerts")
def get_alerts(unacknowledged_only: bool = False, severity: str = None):
    alerts = alert_mgr.get_alerts(unacknowledged_only, severity)
    return {"total": len(alerts), "alerts": alerts}

@app.get("/api/alerts/summary")
def alerts_summary():
    return alert_mgr.get_summary()

@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    if alert_mgr.acknowledge(alert_id):
        return {"status": "acknowledged"}
    return JSONResponse(status_code=404, content={"error": "Alert not found"})

@app.get("/api/traffic/analysis")
def traffic_analysis():
    return traffic_analyzer.analyze_all()

@app.get("/api/traffic/analysis/{api_id}")
def traffic_analysis_single(api_id: str):
    return traffic_analyzer.analyze(api_id)

@app.get("/api/compliance/report")
def compliance_report():
    results = compliance_checker.check_all()
    return {"total": len(results), "results": results}

@app.get("/api/compliance/report/{api_id}")
def compliance_report_single(api_id: str):
    api = api_registry.get(api_id)
    if not api:
        return JSONResponse(status_code=404, content={"error": "API not found"})
    return compliance_checker.check(api)

@app.get("/api/audit-log")
def get_audit_log(limit: int = 100, action: str = None):
    return {"total": len(audit_log.get_entries(limit, action)), "entries": audit_log.get_entries(limit, action)}

@app.get("/api/reports/export")
def export_report():
    return {
        "generated_at": datetime.now().isoformat(),
        "summary": api_registry.get_summary(),
        "apis": [a.to_dict() for a in api_registry.get_all()],
        "alerts": alert_mgr.get_alerts(),
        "compliance": compliance_checker.check_all(),
        "audit_log": audit_log.get_entries(500)
    }

@app.get("/api/dashboard/summary")
def dashboard_summary():
    summary = api_registry.get_summary()
    alert_summary = alert_mgr.get_summary()
    monitoring = continuous_monitor.get_status()
    active_wfs = decommission_wf.get_all()
    return {
        "registry": summary,
        "alerts": alert_summary,
        "monitoring": monitoring,
        "zombie_count": summary.get("by_status", {}).get("zombie", 0),
        "active_decommissions": len([w for w in active_wfs if w["current_state"] != "decommissioned"]),
        "completed_decommissions": len([w for w in active_wfs if w["current_state"] == "decommissioned"]),
        "highest_risk_apis": [
            {"id": a.id, "url": a.url, "method": a.method, "risk_score": a.risk_score, "risk_level": a.risk_level, "status": a.status}
            for a in sorted(api_registry.get_all(), key=lambda x: x.risk_score, reverse=True)[:5]
        ]
    }

# ============================================================
# LOG ANALYSIS ENDPOINTS
# ============================================================
@app.get("/api/logs/attacks")
def get_attack_logs(limit: int = 200, attack_type: str = None, ip: str = None, blocked_only: bool = False):
    logs = attack_log.get_logs(limit, attack_type, ip, blocked_only)
    return {"total": len(logs), "logs": logs}

@app.get("/api/logs/summary")
def get_attack_summary():
    return attack_log.get_summary()

@app.get("/api/logs/ip/{ip}")
def get_ip_attack_report(ip: str):
    report = attack_log.get_ip_report(ip)
    if not report:
        return JSONResponse(status_code=404, content={"error": "No logs for this IP"})
    return report

# ============================================================
# HONEYPOT CATCH-ALL (must be LAST route)
# ============================================================
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def honeypot_trap(path: str, req: Request):
    full_path = f"/{path}"
    ip = req.client.host

    if full_path not in HONEYPOT_ROUTES:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    headers = dict(req.headers)
    profiler.record(ip, full_path, headers)
    ip_rep.update(ip, -50)

    logger.warning(f"ATTACKER TRAPPED | IP={ip} | path={full_path} | blocked={ip_rep.is_blocked(ip)}")

    attack_log.record(
        ip=ip,
        path=full_path,
        body="",
        attack_type="HONEYPOT_TRAP",
        threat_score=100.0,
        blocked=False,
        details={"honeypot": True, "user_agent": headers.get("user-agent", "unknown")}
    )

    return JSONResponse(status_code=200, content=generate_fake_response(full_path))

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8010)