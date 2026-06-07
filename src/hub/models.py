from pydantic import BaseModel
from typing import Optional, List, Literal, Any, Dict


class HubStatus(BaseModel):
    version: str
    uptime_s: int
    connected_agents: int
    agents_healthy: int
    agents_alert: int
    agents_offline: int
    alerts_open: int
    alerts_high: int
    vault_used_gb: float
    threat_level: Literal["CRITICAL", "ELEVATED", "GUARDED", "LOW"]
    last_event_ts: str


class Agent(BaseModel):
    id: str
    hostname: str
    user: str
    os: str
    ip: str
    lastHeartbeat: str
    licenseStatus: Literal["active", "expiring", "expired"]
    licenseExpiry: str
    alertCount: int
    status: Literal["healthy", "alert", "offline"]
    logs: List[str]


class HubAlert(BaseModel):
    id: str
    timestamp: str
    severity: Literal["HIGH", "MED", "LOW"]
    type: str
    source: str
    sourceType: Literal["endpoint", "camera"]
    description: str
    status: Literal["open", "investigating", "resolved"]
    assignee: Optional[str] = None


class VaultEntry(BaseModel):
    id: str
    agentId: str
    hostname: str
    timestamp: str
    duration: str
    sizeBytes: int
    hash: str
    status: Literal["sealed", "flagged"]


class TrafficEntry(BaseModel):
    id: str
    timestamp: str
    endpoint: str
    user: str
    method: Literal["GET", "POST", "PUT", "CONNECT"]
    domain: str
    path: str
    category: str
    status: Literal["ALLOWED", "BLOCKED", "WARNED", "FLAGGED"]
    sizeKb: float
    ssl: bool
    reason: Optional[str] = None


class DlpAlert(BaseModel):
    id: str
    timestamp: str
    endpoint: str
    user: str
    type: Literal["UPLOAD", "EMAIL", "USB", "PRINT"]
    destination: str
    sizeKb: float
    status: Literal["BLOCKED", "FLAGGED", "ALLOWED"]
    detail: str


class HubEvent(BaseModel):
    date: str
    type: str
    detail: str
    severity: Literal["HIGH", "MED", "LOW"]


class UserRiskScore(BaseModel):
    id: str
    username: str
    displayName: str
    department: str
    role: str
    score: int
    level: Literal["CRITICAL", "HIGH", "ELEVATED", "NORMAL"]
    trend: Literal["UP", "DOWN", "STABLE"]
    trendDelta: int
    lastActive: str
    alertCount: int
    keywordCount: int
    bulkCount: int
    afterHoursCount: int
    blockedCount: int
    linkedIncidents: List[str]
    vaultRecordings: int
    recommendation: str
    recommendationLevel: Literal["URGENT", "REVIEW", "MONITOR", "CLEAR"]
    recentEvents: List[HubEvent]
