"""
Minifra Hub Server
FastAPI application — serves the REST API consumed by Minifra Secure Console.
Run:  python main.py  (or the compiled minifra-hub.exe)
"""
import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure src/ is on the path when running from dist/
sys.path.insert(0, os.path.dirname(__file__))
import db
import models
from collector import HubCollector

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("minifra-hub")

# ── Config loading ─────────────────────────────────────────────────────────────
def _load_config() -> dict:
    cfg_path = os.environ.get(
        "MFS_CONFIG",
        os.path.join(os.path.dirname(__file__), "..", "..", "config", "hub-config.json"),
    )
    if os.path.exists(cfg_path):
        with open(cfg_path) as f:
            return json.load(f)
    logger.warning("Config not found at %s — using defaults", cfg_path)
    return {"auth_token": "changeme", "port": 8080, "endpoints": [], "collect_interval_s": 30}


CONFIG = _load_config()
AUTH_TOKEN: str = CONFIG.get("auth_token", "changeme")
HUB_VERSION = "2.4.1"
START_TIME = time.time()

# ── Collector ─────────────────────────────────────────────────────────────────
collector: Optional[HubCollector] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global collector
    db.init_db()
    collector = HubCollector(CONFIG)
    collector.start()
    logger.info("Minifra Hub %s started on port %d", HUB_VERSION, CONFIG.get("port", 8080))
    yield
    if collector:
        collector.stop()
    logger.info("Hub shutting down")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="Minifra Hub API", version=HUB_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth middleware ────────────────────────────────────────────────────────────
async def verify_token(request: Request):
    token = request.headers.get("X-Auth-Token", "")
    if AUTH_TOKEN and token != AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid auth token",
        )


# ── /api/v1/status ─────────────────────────────────────────────────────────────
@app.get("/api/v1/status", response_model=models.HubStatus, dependencies=[Depends(verify_token)])
def get_status():
    agents = db.get_agents()
    alerts = db.get_alerts(limit=500)
    open_alerts = [a for a in alerts if a["status"] == "open"]
    vault_gb = db.get_vault_size_gb()

    healthy = sum(1 for a in agents if a["status"] == "healthy")
    alert_c = sum(1 for a in agents if a["status"] == "alert")
    offline_c = sum(1 for a in agents if a["status"] == "offline")
    high_alerts = sum(1 for a in open_alerts if a["severity"] == "HIGH")

    if high_alerts >= 3 or any(a["status"] == "alert" for a in agents):
        threat = "ELEVATED"
    elif high_alerts >= 1:
        threat = "GUARDED"
    else:
        threat = "LOW"

    last_evt = max((a["timestamp"] for a in alerts), default=datetime.utcnow().isoformat())

    return models.HubStatus(
        version=HUB_VERSION,
        uptime_s=int(time.time() - START_TIME),
        connected_agents=len(agents),
        agents_healthy=healthy,
        agents_alert=alert_c,
        agents_offline=offline_c,
        alerts_open=len(open_alerts),
        alerts_high=high_alerts,
        vault_used_gb=vault_gb,
        threat_level=threat,
        last_event_ts=last_evt,
    )


# ── /api/v1/agents ─────────────────────────────────────────────────────────────
@app.get("/api/v1/agents", response_model=List[models.Agent], dependencies=[Depends(verify_token)])
def get_agents():
    rows = db.get_agents()
    result = []
    for r in rows:
        logs = json.loads(r.get("logs") or "[]")
        result.append(models.Agent(
            id=r["id"],
            hostname=r["hostname"],
            user=r.get("user_name") or "",
            os=r.get("os") or "Windows",
            ip=r.get("ip") or "",
            lastHeartbeat=r.get("last_heartbeat") or datetime.utcnow().isoformat(),
            licenseStatus=r.get("license_status") or "active",
            licenseExpiry=r.get("license_expiry") or "2027-12-31",
            alertCount=r.get("alert_count") or 0,
            status=r.get("status") or "healthy",
            logs=logs,
        ))
    return result


# ── /api/v1/alerts ─────────────────────────────────────────────────────────────
@app.get("/api/v1/alerts", response_model=List[models.HubAlert], dependencies=[Depends(verify_token)])
def get_alerts():
    rows = db.get_alerts(limit=100)
    return [
        models.HubAlert(
            id=r["id"],
            timestamp=r["timestamp"],
            severity=r["severity"],
            type=r["type"],
            source=r["source"],
            sourceType=r.get("source_type") or "endpoint",
            description=r["description"],
            status=r["status"],
            assignee=r.get("assignee"),
        )
        for r in rows
    ]


@app.put("/api/v1/alerts/{alert_id}", dependencies=[Depends(verify_token)])
async def update_alert(alert_id: str, request: Request):
    body = await request.json()
    db.update_alert_status(alert_id, body.get("status", "open"), body.get("assignee"))
    return {"ok": True}


# ── /api/v1/vault ──────────────────────────────────────────────────────────────
@app.get("/api/v1/vault", response_model=List[models.VaultEntry], dependencies=[Depends(verify_token)])
def get_vault():
    rows = db.get_vault_entries(limit=50)
    return [
        models.VaultEntry(
            id=r["id"],
            agentId=r["agent_id"],
            hostname=r["hostname"],
            timestamp=r["timestamp"],
            duration=r.get("duration") or "00:05:00",
            sizeBytes=r.get("size_bytes") or 0,
            hash=r.get("hash") or "",
            status=r.get("status") or "sealed",
        )
        for r in rows
    ]


# ── /api/v1/proxy/traffic ──────────────────────────────────────────────────────
@app.get("/api/v1/proxy/traffic", response_model=List[models.TrafficEntry], dependencies=[Depends(verify_token)])
def get_traffic(limit: int = 50):
    rows = db.get_traffic(limit=limit)
    return [
        models.TrafficEntry(
            id=r["id"],
            timestamp=r["timestamp"],
            endpoint=r["endpoint"],
            user=r.get("user_name") or "system",
            method=r.get("method") or "GET",
            domain=r["domain"],
            path=r.get("path") or "/",
            category=r.get("category") or "UNCATEGORIZED",
            status=r.get("status") or "ALLOWED",
            sizeKb=r.get("size_kb") or 0,
            ssl=bool(r.get("ssl")),
            reason=r.get("reason"),
        )
        for r in rows
    ]


# ── /api/v1/proxy/dlp ─────────────────────────────────────────────────────────
@app.get("/api/v1/proxy/dlp", response_model=List[models.DlpAlert], dependencies=[Depends(verify_token)])
def get_dlp(limit: int = 20):
    rows = db.get_dlp(limit=limit)
    return [
        models.DlpAlert(
            id=r["id"],
            timestamp=r["timestamp"],
            endpoint=r["endpoint"],
            user=r.get("user_name") or "system",
            type=r.get("type") or "USB",
            destination=r.get("destination") or "",
            sizeKb=r.get("size_kb") or 0,
            status=r.get("status") or "FLAGGED",
            detail=r.get("detail") or "",
        )
        for r in rows
    ]


# ── /api/v1/user-risk ─────────────────────────────────────────────────────────
@app.get("/api/v1/user-risk", response_model=List[models.UserRiskScore], dependencies=[Depends(verify_token)])
def get_user_risk():
    rows = db.get_user_risk()
    result = []
    for r in rows:
        linked = json.loads(r.get("linked_incidents") or "[]")
        recent_events_raw = json.loads(r.get("recent_events") or "[]")
        recent_events = [models.HubEvent(**e) for e in recent_events_raw]
        result.append(models.UserRiskScore(
            id=r["id"],
            username=r["username"],
            displayName=r.get("display_name") or r["username"],
            department=r.get("department") or "IT",
            role=r.get("role") or "User",
            score=r.get("score") or 0,
            level=r.get("level") or "NORMAL",
            trend=r.get("trend") or "STABLE",
            trendDelta=r.get("trend_delta") or 0,
            lastActive=r.get("last_active") or datetime.utcnow().isoformat(),
            alertCount=r.get("alert_count") or 0,
            keywordCount=r.get("keyword_count") or 0,
            bulkCount=r.get("bulk_count") or 0,
            afterHoursCount=r.get("after_hours_count") or 0,
            blockedCount=r.get("blocked_count") or 0,
            linkedIncidents=linked,
            vaultRecordings=r.get("vault_recordings") or 0,
            recommendation=r.get("recommendation") or "No action required.",
            recommendationLevel=r.get("recommendation_level") or "CLEAR",
            recentEvents=recent_events,
        ))
    return result


# ── /api/v1/config ─────────────────────────────────────────────────────────────
@app.get("/api/v1/config", dependencies=[Depends(verify_token)])
def get_config():
    stored = db.get_config("full_config")
    if stored:
        return JSONResponse(content=json.loads(stored))
    return JSONResponse(content={})


@app.put("/api/v1/config", dependencies=[Depends(verify_token)])
async def put_config(request: Request):
    body = await request.json()
    db.set_config("full_config", json.dumps(body))
    return {"ok": True}


# ── Agent push report (from minifra-agent.exe) ────────────────────────────────
@app.post("/api/v1/agent/report", dependencies=[Depends(verify_token)])
async def agent_report(request: Request):
    """Receive push reports from installed agents (richer data than WinRM)."""
    body = await request.json()
    agent_id = body.get("agentId", f"agent-{str(uuid.uuid4())[:8]}")

    db.upsert_agent({
        "id": agent_id,
        "hostname": body.get("hostname", "unknown"),
        "user_name": body.get("user", ""),
        "os": body.get("os", "Windows"),
        "ip": body.get("ip", ""),
        "last_heartbeat": datetime.utcnow().isoformat(),
        "license_status": "active",
        "license_expiry": "2027-12-31",
        "alert_count": len(body.get("alerts", [])),
        "status": "healthy" if not body.get("alerts") else "alert",
        "logs": json.dumps(body.get("logs", [])[-10:]),
    })

    for alert in body.get("alerts", []):
        alert.setdefault("id", f"agt-{str(uuid.uuid4())[:12]}")
        alert.setdefault("status", "open")
        alert.setdefault("assignee", None)
        alert.setdefault("source_type", "endpoint")
        db.insert_alert(alert)

    for event in body.get("traffic", []):
        event.setdefault("id", f"trx-{str(uuid.uuid4())[:12]}")
        db.insert_traffic(event)

    for dlp in body.get("dlp", []):
        dlp.setdefault("id", f"dlp-{str(uuid.uuid4())[:12]}")
        db.insert_dlp(dlp)

    return {"ok": True, "agentId": agent_id}


# ── Health check (no auth) ─────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": HUB_VERSION, "uptime_s": int(time.time() - START_TIME)}


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(CONFIG.get("port", 8080))
    host = CONFIG.get("host", "0.0.0.0")

    cert_file = os.path.join(os.path.dirname(__file__), "..", "..", "certs", "cert.pem")
    key_file  = os.path.join(os.path.dirname(__file__), "..", "..", "certs", "key.pem")
    use_https = os.path.exists(cert_file) and os.path.exists(key_file)

    ssl_kwargs = {}
    if use_https:
        ssl_kwargs = {"ssl_certfile": cert_file, "ssl_keyfile": key_file}
        logger.info("TLS enabled — running HTTPS")
    else:
        logger.info("No certs found — running HTTP (run generate-cert.bat for HTTPS)")

    logger.info("Hub API: %s://%s:%d", "https" if use_https else "http", host, port)
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        log_level="info",
        access_log=True,
        **ssl_kwargs,
    )
