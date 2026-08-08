
import asyncio
import hmac
import json
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel

from fusion       import fuse
from ml_detector  import AnomalyDetector
from rules        import (
    AdaptiveRuleEngine,
    get_current_thresholds,
    get_default_settings,
    get_settings,
    update_settings,
)

API_SECRET_KEY = os.environ.get("NETWATCH_API_SECRET_KEY", "")

# Client is considered online if last ping was within this many seconds
HEARTBEAT_TIMEOUT = 10

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="NetWatch Remote EDR Backend", version="3.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ── State ─────────────────────────────────────────────────────────────────────
detectors: dict[str, AnomalyDetector] = {}
rule_engines: dict[str, AdaptiveRuleEngine] = {}
history_by_agent: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
ws_clients: dict[WebSocket, str] = {}
agent_dashboard_tokens: dict[str, str] = {}
STATE_ROOT  = os.environ.get("NETWATCH_STATE_DIR", "data")
ALERTS_DIR  = os.path.join(STATE_ROOT, "alert_reports")
os.makedirs(ALERTS_DIR, exist_ok=True)
AGENT_INSTALLER_PATH = os.environ.get(
    "AGENT_INSTALLER_PATH", os.path.join("dist", "NetWatchSetup-v4.0.exe")
)

# Heartbeat state, isolated per agent.
agent_last_seen: dict[str, tuple[float, str]] = {}

SEVERITY_ORDER = {"OK": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _get_detector(agent_id: str) -> AnomalyDetector:
    if agent_id not in detectors:
        detectors[agent_id] = AnomalyDetector(agent_id)
    return detectors[agent_id]


def _get_rule_engine(agent_id: str) -> AdaptiveRuleEngine:
    if agent_id not in rule_engines:
        rule_engines[agent_id] = AdaptiveRuleEngine()
    return rule_engines[agent_id]


def _safe_agent_id(agent_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", agent_id).strip("._") or "unknown-agent"


# ── Auth helper ───────────────────────────────────────────────────────────────
def _check_auth(request: Request):
    if not API_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Server API key is not configured")
    key = request.headers.get("X-API-Key", "")
    if key != API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing API key")


# ── Heartbeat helpers ─────────────────────────────────────────────────────────
def _touch_heartbeat(agent_id: str):
    agent_last_seen[agent_id] = (time.monotonic(), datetime.now(timezone.utc).isoformat())


def _client_online(agent_id: str) -> bool:
    last_seen = agent_last_seen.get(agent_id)
    if last_seen is None:
        return False
    return (time.monotonic() - last_seen[0]) < HEARTBEAT_TIMEOUT


def _check_dashboard_token(agent_id: str, token: str):
    expected = agent_dashboard_tokens.get(agent_id, "")
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise HTTPException(status_code=401, detail="A valid private device link is required")


def _agent_from_dashboard_request(request: Request, agent_id: str) -> str:
    _check_dashboard_token(agent_id, request.headers.get("X-Dashboard-Token", ""))
    return agent_id


# ── Pydantic ──────────────────────────────────────────────────────────────────
class AgentEvent(BaseModel):
    timestamp:   str
    source_tier: str
    agent_id:    str
    features:    dict


# ── Alert report ──────────────────────────────────────────────────────────────
def _make_alert_title(enriched: dict) -> str:
    sev   = enriched.get("fused_severity", "UNKNOWN")
    hits  = enriched.get("rule_hits", [])
    ts    = enriched.get("timestamp", "")[:19].replace("T", " ")
    if hits:
        rule_ids = ", ".join(h["rule_id"] for h in hits[:2])
        return f"{sev}_{rule_ids}_{ts}".replace(" ", "_").replace(":", "-").replace(",", "")
    elif enriched.get("ml_score", 0) < -0.35:
        return f"{sev}_ML_ANOMALY_{ts}".replace(" ", "_").replace(":", "-")
    return f"{sev}_ALERT_{ts}".replace(" ", "_").replace(":", "-")


def _save_alert_report(enriched: dict):
    title    = _make_alert_title(enriched)
    filename = f"{title}.json"
    agent_dir = os.path.join(ALERTS_DIR, _safe_agent_id(enriched["agent_id"]))
    os.makedirs(agent_dir, exist_ok=True)
    path     = os.path.join(agent_dir, filename)
    report = {
        "title":     title,
        "generated": datetime.now(timezone.utc).isoformat(),
        "event":     enriched,
        "summary": {
            "severity":       enriched.get("fused_severity"),
            "confidence":     enriched.get("fused_confidence"),
            "fusion_reason":  enriched.get("fusion_reason"),
            "context":        enriched.get("context"),
            "ml_score":       enriched.get("ml_score"),
            "rules_fired":    [h["rule_id"] for h in enriched.get("rule_hits", [])],
            "features":       enriched.get("features"),
            "timestamp":      enriched.get("timestamp"),
        }
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return filename


# ── WebSocket broadcast ───────────────────────────────────────────────────────
async def broadcast(payload: dict):
    dead    = set()
    message = json.dumps(payload)
    agent_id = payload.get("agent_id")
    for ws, paired_agent_id in ws_clients.items():
        if paired_agent_id != agent_id:
            continue
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    for ws in dead:
        ws_clients.pop(ws, None)


# ── Background heartbeat broadcaster ─────────────────────────────────────────
async def _heartbeat_broadcaster():
    """Push client_online status to all dashboards every 2 seconds."""
    while True:
        await asyncio.sleep(2)
        for agent_id, (_, last_seen_ts) in list(agent_last_seen.items()):
            await broadcast({
                "__type":        "heartbeat",
                "client_online": _client_online(agent_id),
                "last_seen_ts":  last_seen_ts,
                "agent_id":      agent_id,
            })


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(_heartbeat_broadcaster())


# ── Ingest ────────────────────────────────────────────────────────────────────
@app.post("/ingest")
async def ingest(event: AgentEvent, request: Request):
    _check_auth(request)
    dashboard_token = request.headers.get("X-Dashboard-Token", "")
    if len(dashboard_token) < 24:
        raise HTTPException(status_code=401, detail="Agent dashboard token is missing or invalid")
    agent_dashboard_tokens[event.agent_id] = dashboard_token

    # Update heartbeat
    _touch_heartbeat(event.agent_id)

    features = event.features
    detector = _get_detector(event.agent_id)
    rule_engine = _get_rule_engine(event.agent_id)
    context  = detector.current_context
    hits     = rule_engine.evaluate(features, context)
    ml_score, ml_severity = detector.score(features)
    context  = detector.current_context
    fusion_result = fuse(hits, ml_score, ml_severity, context)

    enriched = {
        "timestamp":   event.timestamp,
        "source_tier": event.source_tier,
        "agent_id":    event.agent_id,
        "features":    features,
        "rule_hits": [
            {
                "rule_id":     (h.get("rule_id") if isinstance(h, dict) else h.rule_id),
                "description": (h.get("description") if isinstance(h, dict) else h.description),
                "severity":    (h.get("severity") if isinstance(h, dict) else h.severity),
                "confidence":  (h.get("confidence") if isinstance(h, dict) else h.confidence),
            }
            for h in hits
        ],
        "ml_score":            round(ml_score, 4),
        "ml_severity":         ml_severity,
        "ml_warmed_up":        detector.is_warmed_up,
        "ml_warmup_remaining": detector.warmup_needed,
        "context":             context,
        "score_stats":         detector.score_stats,
        "ema":                 detector.ema_snapshot,
        **fusion_result,
    }

    history_by_agent[event.agent_id].append(enriched)
    asyncio.create_task(broadcast(enriched))

    alert_file = None
    if SEVERITY_ORDER.get(enriched.get("fused_severity", "OK"), 0) >= 2:
        alert_file = _save_alert_report(enriched)
        asyncio.create_task(broadcast({
            "__type":   "alert_file",
            "filename": alert_file,
            "title":    alert_file.replace(".json", "").replace("_", " "),
            "severity": enriched.get("fused_severity"),
            "ts":       enriched.get("timestamp"),
        }))

    return enriched


# ── REST ──────────────────────────────────────────────────────────────────────
@app.get("/history")
async def get_history(agent_id: str, request: Request, n: int = 100):
    _agent_from_dashboard_request(request, agent_id)
    return list(history_by_agent[agent_id])[-n:]


@app.get("/status")
async def get_status(agent_id: str, request: Request):
    _agent_from_dashboard_request(request, agent_id)
    detector = _get_detector(agent_id)
    rule_engine = _get_rule_engine(agent_id)
    last_seen = agent_last_seen.get(agent_id)
    return {
        "ml_warmed_up":        detector.is_warmed_up,
        "ml_samples":          detector.samples_collected,
        "ml_warmup_remaining": detector.warmup_needed,
        "current_context":     detector.current_context,
        "score_stats":         detector.score_stats,
        "ema":                 detector.ema_snapshot,
        "event_count":         len(history_by_agent[agent_id]),
        "connected_dashboards":len(ws_clients),
        "thresholds":          rule_engine.current_thresholds(),
        # Heartbeat fields
        "client_online":       _client_online(agent_id),
        "last_seen_ts":        last_seen[1] if last_seen else None,
        "client_agent_id":     agent_id,
    }


# ── Alert downloads ───────────────────────────────────────────────────────────
@app.get("/alerts")
async def list_alerts(agent_id: str, request: Request):
    _agent_from_dashboard_request(request, agent_id)
    files = []
    agent_dir = os.path.join(ALERTS_DIR, _safe_agent_id(agent_id))
    if not os.path.isdir(agent_dir):
        return files
    for fn in sorted(os.listdir(agent_dir), reverse=True):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(agent_dir, fn)
        try:
            with open(path) as f:
                data = json.load(f)
            files.append({
                "filename":  fn,
                "title":     data.get("title", fn),
                "severity":  data.get("summary", {}).get("severity"),
                "timestamp": data.get("summary", {}).get("timestamp"),
                "rules":     data.get("summary", {}).get("rules_fired", []),
                "size_kb":   round(os.path.getsize(path) / 1024, 1),
            })
        except Exception:
            pass
    return files


@app.get("/alerts/{filename}")
async def download_alert(filename: str, agent_id: str, request: Request):
    _agent_from_dashboard_request(request, agent_id)
    if os.path.basename(filename) != filename:
        raise HTTPException(status_code=404, detail="Alert file not found")
    path = os.path.join(ALERTS_DIR, _safe_agent_id(agent_id), filename)
    if not os.path.exists(path) or not filename.endswith(".json"):
        raise HTTPException(status_code=404, detail="Alert file not found")
    return FileResponse(path, media_type="application/json", filename=filename)


@app.get("/downloads/netwatch-agent")
async def download_agent_installer():
    """Download the Windows agent after the dashboard's consent disclosure."""
    if not os.path.isfile(AGENT_INSTALLER_PATH):
        raise HTTPException(status_code=404, detail="Agent installer is not available")
    return FileResponse(
        AGENT_INSTALLER_PATH,
        media_type="application/vnd.microsoft.portable-executable",
        filename="NetWatchSetup-v4.0.exe",
    )


@app.delete("/alerts/{filename}")
async def delete_alert(filename: str, agent_id: str, request: Request):
    _agent_from_dashboard_request(request, agent_id)
    if os.path.basename(filename) != filename:
        raise HTTPException(status_code=404, detail="Alert file not found")
    path = os.path.join(ALERTS_DIR, _safe_agent_id(agent_id), filename)
    if os.path.exists(path):
        os.remove(path)
    return {"deleted": filename}


# ── Settings ──────────────────────────────────────────────────────────────────
@app.get("/settings")
async def get_settings_endpoint():
    return get_settings()


@app.post("/settings")
async def post_settings(body: dict):
    return update_settings(body)


@app.get("/settings/defaults")
async def get_defaults():
    return get_default_settings()


@app.get("/settings/thresholds")
async def get_thresholds():
    return get_current_thresholds()


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    agent_id = websocket.query_params.get("agent_id", "")
    token = websocket.query_params.get("token", "")
    expected = agent_dashboard_tokens.get(agent_id, "")
    if not agent_id or not expected or not hmac.compare_digest(expected, token):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    ws_clients[websocket] = agent_id
    try:
        # Send recent history
        for event in list(history_by_agent[agent_id])[-80:]:
            await websocket.send_text(json.dumps(event))
        # Send current heartbeat state immediately
        last_seen = agent_last_seen.get(agent_id)
        await websocket.send_text(json.dumps({
            "__type":        "heartbeat",
            "client_online": _client_online(agent_id),
            "last_seen_ts":  last_seen[1] if last_seen else None,
            "agent_id":      agent_id,
        }))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_clients.pop(websocket, None)
    except Exception:
        ws_clients.pop(websocket, None)


# ── Pages ─────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    for name in ("dashboard.html",):
        try:
            with open(name, encoding="utf-8") as f:
                return HTMLResponse(f.read())
        except FileNotFoundError:
            pass
    return HTMLResponse("<h2>dashboard.html not found</h2>", 404)


@app.get("/settings-page", response_class=HTMLResponse)
async def serve_settings():
    try:
        with open("settings_page.html", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h2>settings_page.html not found</h2>", 404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="0.0.0.0", port=8000, reload=False, log_level="warning")
