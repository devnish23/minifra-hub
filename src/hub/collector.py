"""
WinRM-based agentless data collector.
Polls each endpoint every collect_interval_s seconds via PowerShell remoting.
"""
import json
import logging
import hashlib
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False

import db

logger = logging.getLogger(__name__)

# Domain → category mapping (extend as needed)
DOMAIN_CATEGORIES = {
    "facebook.com": "SOCIAL_MEDIA", "instagram.com": "SOCIAL_MEDIA",
    "twitter.com": "SOCIAL_MEDIA",  "x.com": "SOCIAL_MEDIA",
    "linkedin.com": "SOCIAL_MEDIA", "tiktok.com": "SOCIAL_MEDIA",
    "youtube.com": "STREAMING",     "netflix.com": "STREAMING",
    "spotify.com": "STREAMING",     "twitch.tv": "STREAMING",
    "google.com": "SEARCH",         "bing.com": "SEARCH",
    "duckduckgo.com": "SEARCH",
    "gmail.com": "EMAIL",           "outlook.com": "EMAIL",
    "office365.com": "EMAIL",
    "onedrive.com": "CLOUD_STORAGE","dropbox.com": "CLOUD_STORAGE",
    "wetransfer.com": "CLOUD_STORAGE",
    "coinbase.com": "CRYPTO",       "binance.com": "CRYPTO",
    "thepiratebay.org": "TORRENTS", "torrentz2.eu": "TORRENTS",
    "bet365.com": "GAMBLING",       "williamhill.com": "GAMBLING",
    "microsoft.com": "PRODUCTIVITY","github.com": "PRODUCTIVITY",
    "bloomberg.com": "FINANCE",     "reuters.com": "FINANCE",
}

BLOCKED_DOMAINS = {"thepiratebay.org", "torrentz2.eu", "wetransfer.com", "pastebin.com"}
WARN_DOMAINS = {"coinbase.com", "binance.com", "bet365.com", "onedrive.com", "dropbox.com"}

SECURITY_EVENT_IDS = {
    4625: ("FAILED LOGON", "HIGH"),
    4648: ("EXPLICIT CREDENTIAL LOGON", "MED"),
    4688: ("PROCESS CREATION", "LOW"),
    4698: ("SCHEDULED TASK CREATED", "HIGH"),
    4740: ("ACCOUNT LOCKED OUT", "HIGH"),
    4771: ("KERBEROS PRE-AUTH FAILED", "HIGH"),
    4756: ("MEMBER ADDED TO SECURITY GROUP", "MED"),
}

PS_SYSINFO = r"""
$os  = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs  = Get-WmiObject Win32_ComputerSystem  -ErrorAction SilentlyContinue
$net = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and
                      $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
[PSCustomObject]@{
    hostname = $env:COMPUTERNAME
    os       = if ($os) { $os.Caption } else { 'Windows' }
    user     = if ($cs) { $cs.UserName } else { '' }
    ip       = if ($net) { $net.IPAddress } else { '' }
} | ConvertTo-Json -Compress
"""

PS_PROCESSES = r"""
Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.CPU -gt 0 } |
  Select-Object Name, Id,
    @{N='CPU';E={[math]::Round([double]$_.CPU,1)}},
    @{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,1)}} |
  Sort-Object CPU -Descending | Select-Object -First 25 |
  ConvertTo-Json -Compress
"""

PS_SECURITY_EVENTS = r"""
try {
  $evts = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625,4648,4688,4698,4740,4771,4756
    StartTime=(Get-Date).AddHours(-24)
  } -MaxEvents 100 -ErrorAction Stop
  $evts | Select-Object `
    @{N='time';E={$_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')}},
    @{N='id';E={$_.Id}},
    @{N='user';E={
      if ($_.Properties.Count -gt 5) { $_.Properties[5].Value }
      elseif ($_.Properties.Count -gt 1) { $_.Properties[1].Value }
      else { 'SYSTEM' }
    }},
    @{N='msg';E={$_.Message.Substring(0,[Math]::Min(300,$_.Message.Length))}} |
  ConvertTo-Json -Compress
} catch { '[]' }
"""

PS_NETWORK = r"""
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Where-Object {
    $_.RemoteAddress -notmatch '^(127\.|0\.|::1)' -and
    $_.RemotePort -ne 0
  } |
  ForEach-Object {
    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
    [PSCustomObject]@{
      local  = "$($_.LocalAddress):$($_.LocalPort)"
      remote = "$($_.RemoteAddress):$($_.RemotePort)"
      proc   = if ($proc) { $proc } else { 'unknown' }
      pid_   = $_.OwningProcess
    }
  } | Select-Object -First 30 | ConvertTo-Json -Compress
"""

PS_USB = r"""
$usb = Get-WmiObject Win32_LogicalDisk -ErrorAction SilentlyContinue |
       Where-Object { $_.DriveType -eq 2 }
if ($usb) {
  $usb | Select-Object DeviceID, VolumeName,
    @{N='SizeGB';E={if($_.Size){[math]::Round($_.Size/1GB,2)}else{0}}} |
  ConvertTo-Json -Compress
} else { '[]' }
"""

PS_USERS = r"""
try {
  $sessions = query user 2>$null
  if ($sessions) {
    $sessions | Select-Object -Skip 1 | ForEach-Object {
      ($_ -split '\s+' | Where-Object { $_ -ne '' }) | Select-Object -First 1
    } | Where-Object { $_ } | ConvertTo-Json -Compress
  } else { '[]' }
} catch { '[]' }
"""


def _run_ps(session, script: str, timeout: int = 10) -> Optional[str]:
    """Execute a PowerShell script via WinRM; return stdout or None."""
    try:
        result = session.run_ps(script)
        if result.status_code == 0:
            return result.std_out.decode("utf-8", errors="replace").strip()
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        logger.debug("PS non-zero exit %d: %s", result.status_code, stderr[:200])
        return None
    except Exception as exc:
        logger.error("WinRM run_ps error: %s", exc)
        return None


def _parse_json(raw: Optional[str], default=None):
    if not raw:
        return default
    try:
        data = json.loads(raw)
        # PowerShell returns a single object (not list) when there is 1 result
        if isinstance(data, dict) and default == []:
            return [data]
        return data
    except json.JSONDecodeError:
        return default


def _categorise_domain(domain: str) -> tuple[str, str]:
    """Return (category, status) for a remote domain/IP."""
    for suffix, cat in DOMAIN_CATEGORIES.items():
        if domain.endswith(suffix):
            if domain in BLOCKED_DOMAINS or any(domain.endswith(b) for b in BLOCKED_DOMAINS):
                return cat, "BLOCKED"
            if domain in WARN_DOMAINS or any(domain.endswith(w) for w in WARN_DOMAINS):
                return cat, "WARNED"
            return cat, "ALLOWED"
    return "UNCATEGORIZED", "ALLOWED"


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _score_risk(alert_c: int, bulk_c: int, after_c: int, blocked_c: int) -> tuple[int, str]:
    score = min(100, alert_c * 15 + bulk_c * 10 + after_c * 3 + blocked_c * 2)
    if score >= 75:
        return score, "CRITICAL"
    if score >= 55:
        return score, "HIGH"
    if score >= 35:
        return score, "ELEVATED"
    return score, "NORMAL"


def _recommendation(level: str) -> tuple[str, str]:
    return {
        "CRITICAL": ("Immediate investigation required — escalate to security team.", "URGENT"),
        "HIGH":     ("Schedule security review interview with user.",                 "REVIEW"),
        "ELEVATED": ("Increase monitoring frequency for this user.",                 "MONITOR"),
        "NORMAL":   ("No action required.",                                          "CLEAR"),
    }[level]


class EndpointCollector:
    def __init__(self, endpoint_cfg: Dict[str, Any]):
        self.cfg = endpoint_cfg
        self.ip: str = endpoint_cfg["ip"]
        self.hostname: str = endpoint_cfg.get("hostname", self.ip)
        self.username: str = endpoint_cfg["username"]
        self.password: str = endpoint_cfg["password"]
        self.transport: str = endpoint_cfg.get("transport", "ntlm")
        self.agent_id: str = f"agent-{self.ip.replace('.', '-')}"

    def _make_session(self):
        if not WINRM_AVAILABLE:
            raise RuntimeError("pywinrm not installed")
        return winrm.Session(
            target=self.ip,
            auth=(self.username, self.password),
            transport=self.transport,
            server_cert_validation="ignore",
            read_timeout_sec=15,
            operation_timeout_sec=12,
        )

    def collect(self):
        logger.info("Collecting from %s (%s)", self.hostname, self.ip)
        try:
            session = self._make_session()
            self._collect_agent(session)
            self._collect_alerts(session)
            self._collect_traffic(session)
            self._collect_usb(session)
            self._compute_user_risk()
        except Exception as exc:
            logger.error("Collection failed for %s: %s", self.ip, exc)
            self._mark_offline()

    def _collect_agent(self, session):
        raw = _run_ps(session, PS_SYSINFO)
        info = _parse_json(raw, {})
        hostname = info.get("hostname") or self.hostname
        procs_raw = _run_ps(session, PS_PROCESSES)
        procs = _parse_json(procs_raw, []) or []
        logs = [f"{datetime.utcnow().strftime('%H:%M:%S')} Heartbeat OK — {len(procs)} processes"]

        # Check for monitored process names (alert-worthy)
        watched = {"whatsapp", "telegram", "anydesk", "teamviewer", "tor", "wireshark"}
        for p in procs:
            name = str(p.get("Name", "")).lower()
            if any(w in name for w in watched):
                logs.append(f"[ALERT] Monitored process: {p.get('Name')}")

        with db.get_conn() as conn:
            existing = conn.execute(
                "SELECT status FROM agents WHERE id=?", (self.agent_id,)
            ).fetchone()

        prev_alerts = db.get_alerts(limit=200)
        my_alerts = [a for a in prev_alerts if a["source"] == hostname]
        alert_count = sum(1 for a in my_alerts if a["status"] == "open")
        status = "healthy" if alert_count == 0 else "alert"

        db.upsert_agent({
            "id": self.agent_id,
            "hostname": hostname,
            "user_name": info.get("user", ""),
            "os": info.get("os", "Windows"),
            "ip": info.get("ip") or self.ip,
            "last_heartbeat": datetime.utcnow().isoformat(),
            "license_status": "active",
            "license_expiry": "2027-12-31",
            "alert_count": alert_count,
            "status": status,
            "logs": json.dumps(logs[-10:]),
        })

    def _collect_alerts(self, session):
        raw = _run_ps(session, PS_SECURITY_EVENTS)
        events = _parse_json(raw, []) or []
        for evt in events:
            eid = int(evt.get("id", 0))
            if eid not in SECURITY_EVENT_IDS:
                continue
            etype, sev = SECURITY_EVENT_IDS[eid]
            ts = evt.get("time", datetime.utcnow().isoformat())
            msg = evt.get("msg", "")
            user = str(evt.get("user", "SYSTEM") or "SYSTEM").strip()
            alert_id = hashlib.md5(f"{self.ip}{eid}{ts}".encode()).hexdigest()[:16]
            db.insert_alert({
                "id": f"evt-{alert_id}",
                "timestamp": ts,
                "severity": sev,
                "type": etype,
                "source": self.hostname,
                "source_type": "endpoint",
                "description": f"{etype} — user: {user or 'SYSTEM'} on {self.hostname}",
                "status": "open",
                "assignee": None,
            })

    def _collect_traffic(self, session):
        raw = _run_ps(session, PS_NETWORK)
        conns = _parse_json(raw, []) or []
        for conn_entry in conns:
            remote = conn_entry.get("remote", "")
            parts = remote.rsplit(":", 1)
            remote_ip = parts[0] if parts else remote
            remote_port = int(parts[1]) if len(parts) > 1 else 443

            domain = _reverse_dns(remote_ip)
            # Strip to root domain for categorisation
            domain_parts = domain.replace("https://", "").replace("http://", "").split("/")[0].split(".")
            root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain

            category, status = _categorise_domain(root_domain)
            ssl_conn = remote_port in (443, 8443)
            method = "CONNECT" if ssl_conn else "GET"
            tid = hashlib.md5(f"{self.ip}{remote}{datetime.utcnow().strftime('%Y%m%d%H%M')}".encode()).hexdigest()[:16]

            db.insert_traffic({
                "id": f"trx-{tid}",
                "timestamp": datetime.utcnow().isoformat(),
                "endpoint": self.hostname,
                "user_name": conn_entry.get("proc", "system"),
                "method": method,
                "domain": root_domain,
                "path": "/",
                "category": category,
                "status": status,
                "size_kb": round(remote_port / 100, 1),
                "ssl": 1 if ssl_conn else 0,
                "reason": "Policy block" if status == "BLOCKED" else None,
            })

            if status == "BLOCKED":
                bid = hashlib.md5(f"block-{self.ip}{root_domain}{datetime.utcnow().strftime('%Y%m%d%H')}".encode()).hexdigest()[:16]
                db.insert_dlp({
                    "id": f"dlp-{bid}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "endpoint": self.hostname,
                    "user_name": conn_entry.get("proc", "system"),
                    "type": "UPLOAD",
                    "destination": root_domain,
                    "size_kb": 0,
                    "status": "BLOCKED",
                    "detail": f"Connection to blocked domain {root_domain} intercepted.",
                })

    def _collect_usb(self, session):
        raw = _run_ps(session, PS_USB)
        drives = _parse_json(raw, []) or []
        for drive in drives:
            vol = drive.get("VolumeName") or drive.get("DeviceID", "?")
            size_gb = float(drive.get("SizeGB", 0))
            uid_str = f"usb-{self.ip}{drive.get('DeviceID','')}{datetime.utcnow().strftime('%Y%m%d')}"
            did = hashlib.md5(uid_str.encode()).hexdigest()[:16]
            db.insert_dlp({
                "id": f"dlp-{did}",
                "timestamp": datetime.utcnow().isoformat(),
                "endpoint": self.hostname,
                "user_name": "endpoint-user",
                "type": "USB",
                "destination": f"USB Drive ({vol})",
                "size_kb": size_gb * 1024 * 1024,
                "status": "FLAGGED",
                "detail": f"Removable drive {vol} connected on {self.hostname} ({size_gb:.1f} GB).",
            })

    def _compute_user_risk(self):
        prev_scores = db.get_previous_scores()
        alerts = db.get_alerts(limit=500)
        my_alerts = [a for a in alerts if a["source"] == self.hostname]
        now = datetime.utcnow()
        cutoff = (now - timedelta(hours=24)).isoformat()

        agents = db.get_agents()
        agent = next((a for a in agents if a["id"] == self.agent_id), None)
        if not agent:
            return

        username = (agent.get("user_name") or "").split("\\")[-1] or self.hostname.lower()
        display_name = username.replace(".", " ").replace("_", " ").title()
        uid = f"usr-{self.agent_id}"

        recent = [a for a in my_alerts if a["timestamp"] >= cutoff]
        alert_count = len(recent)
        blocked_count = sum(1 for a in my_alerts if a["severity"] == "HIGH")
        after_hours_count = sum(
            1 for a in recent
            if a["timestamp"][11:13] not in [str(h).zfill(2) for h in range(8, 18)]
        )

        score, level = _score_risk(alert_count, 0, after_hours_count, blocked_count)
        rec, rec_level = _recommendation(level)

        prev = prev_scores.get(username, score)
        delta = score - prev
        trend = "UP" if delta > 5 else "DOWN" if delta < -5 else "STABLE"

        linked = [a["id"] for a in my_alerts[:5] if a["status"] == "open"]
        recent_events = [
            {
                "date": a["timestamp"],
                "type": a["type"],
                "detail": a["description"],
                "severity": a["severity"],
            }
            for a in my_alerts[:8]
        ]

        db.upsert_user_risk({
            "id": uid,
            "username": username,
            "display_name": display_name,
            "department": "Endpoint",
            "role": "Monitored User",
            "score": score,
            "level": level,
            "trend": trend,
            "trend_delta": abs(delta),
            "last_active": now.isoformat(),
            "alert_count": alert_count,
            "keyword_count": 0,
            "bulk_count": 0,
            "after_hours_count": after_hours_count,
            "blocked_count": blocked_count,
            "linked_incidents": json.dumps(linked),
            "vault_recordings": len(db.get_vault_entries(10)),
            "recommendation": rec,
            "recommendation_level": rec_level,
            "recent_events": json.dumps(recent_events),
        })

    def _mark_offline(self):
        db.upsert_agent({
            "id": self.agent_id,
            "hostname": self.hostname,
            "user_name": "",
            "os": "Windows",
            "ip": self.ip,
            "last_heartbeat": datetime.utcnow().isoformat(),
            "license_status": "active",
            "license_expiry": "2027-12-31",
            "alert_count": 0,
            "status": "offline",
            "logs": json.dumps(["[WARN] Endpoint unreachable via WinRM"]),
        })


class HubCollector:
    """Background scheduler that runs EndpointCollectors on a timer."""

    def __init__(self, config: Dict[str, Any]):
        self.endpoints: List[EndpointCollector] = [
            EndpointCollector(ep) for ep in config.get("endpoints", [])
        ]
        self.interval: int = config.get("collect_interval_s", 30)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.start_time = time.time()

    def start(self):
        if not self.endpoints:
            logger.warning("No endpoints configured — collector idle.")
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="hub-collector")
        self._thread.start()
        logger.info("Collector started — %d endpoints, interval %ds", len(self.endpoints), self.interval)

    def stop(self):
        self._stop.set()

    def _run(self):
        # Initial collection immediately
        self._collect_all()
        while not self._stop.wait(self.interval):
            self._collect_all()

    def _collect_all(self):
        threads = [
            threading.Thread(target=ep.collect, daemon=True, name=f"collect-{ep.ip}")
            for ep in self.endpoints
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)
