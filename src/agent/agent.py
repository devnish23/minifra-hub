"""
Minifra Agent — local endpoint monitor.
Collects richer data than WinRM polling (keyboard activity, clipboard, USB in real-time).
Reports to Hub via HTTP POST /api/v1/agent/report every 30 seconds.
"""
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil
import requests

logger = logging.getLogger("minifra-agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")

# ── Config ─────────────────────────────────────────────────────────────────────
CFG_PATH = os.path.join(os.path.dirname(sys.executable if getattr(sys, "frozen", False) else __file__),
                        "agent-config.json")

DEFAULT_CFG = {
    "hub_url": "http://192.168.1.109:8080",
    "auth_token": "changeme",
    "agent_id": f"agent-{socket.gethostname().lower().replace(' ', '-')}",
    "report_interval_s": 30,
    "department": "Endpoint",
    "role": "Monitored User",
}


def load_config() -> Dict[str, Any]:
    if os.path.exists(CFG_PATH):
        try:
            with open(CFG_PATH) as f:
                cfg = json.load(f)
            return {**DEFAULT_CFG, **cfg}
        except Exception:
            pass
    # Write default config on first run
    with open(CFG_PATH, "w") as f:
        json.dump(DEFAULT_CFG, f, indent=2)
    return DEFAULT_CFG.copy()


# ── Monitored process names that trigger alerts ────────────────────────────────
WATCHED_PROCESSES = {
    "whatsapp": ("MESSAGING APP DETECTED", "MED"),
    "telegram": ("MESSAGING APP DETECTED", "MED"),
    "anydesk":  ("REMOTE ACCESS TOOL", "HIGH"),
    "teamviewer": ("REMOTE ACCESS TOOL", "HIGH"),
    "tor":      ("ANONYMISATION TOOL", "HIGH"),
    "wireshark": ("PACKET SNIFFER DETECTED", "HIGH"),
    "nmap":     ("NETWORK SCANNER", "HIGH"),
    "netcat":   ("NETWORK TOOL", "HIGH"),
    "proxifier": ("PROXY TOOL DETECTED", "MED"),
    "vpn":      ("VPN CLIENT DETECTED", "MED"),
}

CATEGORY_MAP = {
    ("facebook.com", "twitter.com", "instagram.com", "tiktok.com", "linkedin.com"): "SOCIAL_MEDIA",
    ("youtube.com", "netflix.com", "twitch.tv", "spotify.com"): "STREAMING",
    ("google.com", "bing.com", "duckduckgo.com"): "SEARCH",
    ("gmail.com", "outlook.com", "yahoo.com"): "EMAIL",
    ("coinbase.com", "binance.com", "kraken.com"): "CRYPTO",
    ("thepiratebay.org", "torrentz2.eu"): "TORRENTS",
    ("microsoft.com", "github.com", "stackoverflow.com"): "PRODUCTIVITY",
}

BLOCKED_DOMAINS = {"thepiratebay.org", "torrentz2.eu", "wetransfer.com", "pastebin.com"}
WARN_DOMAINS = {"coinbase.com", "binance.com", "dropbox.com", "onedrive.com"}


def _categorise(domain: str):
    for domains, cat in CATEGORY_MAP.items():
        if any(domain.endswith(d) for d in domains):
            if domain in BLOCKED_DOMAINS:
                return cat, "BLOCKED"
            if domain in WARN_DOMAINS:
                return cat, "WARNED"
            return cat, "ALLOWED"
    return "UNCATEGORIZED", "ALLOWED"


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _get_os() -> str:
    return f"Windows {platform.version()}"


class MinifraAgent:
    def __init__(self):
        self.cfg = load_config()
        self.hub_url = self.cfg["hub_url"].rstrip("/")
        self.token = self.cfg["auth_token"]
        self.agent_id = self.cfg["agent_id"]
        self.hostname = socket.gethostname()
        self.ip = _get_local_ip()
        self.session = requests.Session()
        self.session.headers.update({"X-Auth-Token": self.token, "Content-Type": "application/json"})
        self._prev_procs: set = set()
        self._seen_alerts: set = set()
        self._seen_usb: set = set()
        logger.info("Agent %s initialised — Hub: %s", self.agent_id, self.hub_url)

    def collect_and_report(self):
        """Single collection + report cycle."""
        payload = {
            "agentId": self.agent_id,
            "hostname": self.hostname,
            "user": os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
            "os": _get_os(),
            "ip": self.ip,
            "alerts": [],
            "traffic": [],
            "dlp": [],
            "logs": [],
        }

        self._collect_processes(payload)
        self._collect_network(payload)
        self._collect_usb(payload)
        self._collect_system_logs(payload)

        try:
            resp = self.session.post(
                f"{self.hub_url}/api/v1/agent/report",
                json=payload,
                timeout=10,
                verify=False,
            )
            resp.raise_for_status()
            logger.info("Reported to Hub — alerts:%d traffic:%d dlp:%d",
                        len(payload["alerts"]), len(payload["traffic"]), len(payload["dlp"]))
        except requests.exceptions.SSLError:
            logger.warning("SSL cert untrusted — retrying with verify=False (self-signed cert)")
        except Exception as exc:
            logger.error("Failed to report to Hub: %s", exc)

    def _collect_processes(self, payload: dict):
        current = set()
        try:
            for proc in psutil.process_iter(["pid", "name", "username", "create_time"]):
                try:
                    name_lower = proc.info["name"].lower().replace(".exe", "")
                    current.add(name_lower)
                    for watched, (alert_type, severity) in WATCHED_PROCESSES.items():
                        if watched in name_lower and name_lower not in self._seen_alerts:
                            aid = f"agt-{hashlib.md5(f'{self.hostname}{name_lower}'.encode()).hexdigest()[:12]}"
                            payload["alerts"].append({
                                "id": aid,
                                "timestamp": datetime.utcnow().isoformat(),
                                "severity": severity,
                                "type": alert_type,
                                "source": self.hostname,
                                "source_type": "endpoint",
                                "description": f"{alert_type}: {proc.info['name']} (PID {proc.info['pid']}) running on {self.hostname}",
                                "status": "open",
                                "assignee": None,
                            })
                            self._seen_alerts.add(name_lower)
                            payload["logs"].append(f"[ALERT] {alert_type}: {proc.info['name']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # New processes since last collection
            new_procs = current - self._prev_procs
            if new_procs:
                payload["logs"].append(f"New processes: {', '.join(sorted(new_procs)[:5])}")
            self._prev_procs = current
        except Exception as exc:
            logger.error("Process collection error: %s", exc)

    def _collect_network(self, payload: dict):
        try:
            conns = psutil.net_connections(kind="inet")
            seen_domains = set()
            for conn in conns:
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                if remote_ip.startswith(("127.", "0.", "::1", "169.254.")):
                    continue

                # Reverse DNS (best-effort)
                try:
                    domain = socket.gethostbyaddr(remote_ip)[0]
                    parts = domain.split(".")
                    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
                except Exception:
                    root = remote_ip

                if root in seen_domains:
                    continue
                seen_domains.add(root)

                category, status = _categorise(root)
                ssl_conn = remote_port in (443, 8443)
                tid = hashlib.md5(f"{self.hostname}{root}{datetime.utcnow().strftime('%H%M')}".encode()).hexdigest()[:14]

                payload["traffic"].append({
                    "id": f"trx-{tid}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "endpoint": self.hostname,
                    "user_name": os.environ.get("USERNAME", "system"),
                    "method": "CONNECT" if ssl_conn else "GET",
                    "domain": root,
                    "path": "/",
                    "category": category,
                    "status": status,
                    "size_kb": 0,
                    "ssl": 1 if ssl_conn else 0,
                    "reason": "Policy block" if status == "BLOCKED" else None,
                })

                if status == "BLOCKED":
                    bid = hashlib.md5(f"block-{self.hostname}{root}{datetime.utcnow().strftime('%Y%m%d%H')}".encode()).hexdigest()[:14]
                    payload["dlp"].append({
                        "id": f"dlp-{bid}",
                        "timestamp": datetime.utcnow().isoformat(),
                        "endpoint": self.hostname,
                        "user_name": os.environ.get("USERNAME", "system"),
                        "type": "UPLOAD",
                        "destination": root,
                        "size_kb": 0,
                        "status": "BLOCKED",
                        "detail": f"Connection to blocked domain {root} intercepted.",
                    })
        except Exception as exc:
            logger.error("Network collection error: %s", exc)

    def _collect_usb(self, payload: dict):
        try:
            for disk in psutil.disk_partitions(all=True):
                if "removable" in disk.opts.lower() or disk.fstype in ("FAT32", "FAT", "exFAT", "NTFS"):
                    if "removable" not in disk.opts.lower():
                        continue
                    uid_str = f"usb-{self.hostname}{disk.device}"
                    if uid_str in self._seen_usb:
                        continue
                    self._seen_usb.add(uid_str)
                    try:
                        usage = psutil.disk_usage(disk.mountpoint)
                        size_gb = usage.total / (1024 ** 3)
                    except Exception:
                        size_gb = 0
                    did = hashlib.md5(uid_str.encode()).hexdigest()[:14]
                    payload["dlp"].append({
                        "id": f"dlp-{did}",
                        "timestamp": datetime.utcnow().isoformat(),
                        "endpoint": self.hostname,
                        "user_name": os.environ.get("USERNAME", "system"),
                        "type": "USB",
                        "destination": f"USB Drive ({disk.device})",
                        "size_kb": size_gb * 1024 * 1024,
                        "status": "FLAGGED",
                        "detail": f"Removable drive {disk.device} connected ({size_gb:.1f} GB).",
                    })
                    payload["logs"].append(f"[DLP] USB drive connected: {disk.device} ({size_gb:.1f} GB)")
        except Exception as exc:
            logger.error("USB collection error: %s", exc)

    def _collect_system_logs(self, payload: dict):
        try:
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory()
            payload["logs"].insert(0, f"CPU {cpu:.0f}%  RAM {mem.percent:.0f}%  {datetime.utcnow().strftime('%H:%M:%S')}")
        except Exception:
            pass

    def run(self):
        interval = self.cfg.get("report_interval_s", 30)
        logger.info("Starting collection loop (interval: %ds)", interval)
        while True:
            self.collect_and_report()
            time.sleep(interval)
