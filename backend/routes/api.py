"""
API Routes for the Digital Forensics Time Machine.
Handles log upload, event retrieval, timeline, graph, analysis, replay,
real log sources, and real-time monitoring.
"""
import uuid
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import get_db
from models.event import Event, AttackChain, AnalysisResult
from services.parser import parse_logs
from services.detector import detect_suspicious_events, calculate_risk_score
from services.analyzer import build_attack_chains, get_attack_narrative
from services.graph import build_attack_graph, generate_weaponized_attack_graph
from services.ai_explainer import generate_explanation, explain_single_event
from services.log_fetcher import get_real_log, list_available_sources, get_windows_log_channels
from services.monitor import start_monitoring, stop_monitoring, get_monitor_stats

router = APIRouter()

# ── In-memory session store for fast access ────────────────────────────────
session_cache = {}


@router.post("/upload-logs")
async def upload_logs(
    file: Optional[UploadFile] = File(None),
    log_type: str = Form("auto"),
    source_id: Optional[str] = Form(None),
    use_sample: Optional[str] = Form(None),
    live_events: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Ingest real log files, live Windows/Linux channels, or real-time monitor streams.
    """
    session_id = str(uuid.uuid4())[:8]
    target_source = source_id or use_sample
    events = []

    if live_events:
        try:
            import json
            parsed_raw = json.loads(live_events) if isinstance(live_events, str) else live_events
            if isinstance(parsed_raw, list):
                events = parsed_raw
        except Exception as e:
            raise HTTPException(400, f"Invalid live events data: {str(e)}")
    elif target_source:
        content = await run_in_threadpool(get_real_log, target_source)
        if not content:
            raise HTTPException(400, f"Live log source '{target_source}' is not accessible on this machine")
        events = await run_in_threadpool(parse_logs, content, log_type)
    elif file:
        raw = await file.read()
        content = raw.decode("utf-8", errors="ignore")
        if not content or not content.strip():
            raise HTTPException(400, "Uploaded log file is empty")
        events = await run_in_threadpool(parse_logs, content, log_type)
    else:
        raise HTTPException(400, "Provide a real log file, select a live system channel, or stream from Live Monitor")

    if not events:
        raise HTTPException(400, "Could not parse any events from the provided logs")

    # Step 2: Detect suspicious events
    events = await run_in_threadpool(detect_suspicious_events, events)

    # Step 3: Calculate risk
    risk_score, risk_level = await run_in_threadpool(calculate_risk_score, events)

    # Step 4: Build attack chains
    chains = await run_in_threadpool(build_attack_chains, events)

    # Step 5: Generate graph
    graph_data = await run_in_threadpool(build_attack_graph, events)

    # Step 6: Generate AI explanation
    explanation_data = await run_in_threadpool(generate_explanation, events, chains, risk_score, risk_level)

    # Step 7: Get attack narrative
    narrative = await run_in_threadpool(get_attack_narrative, chains)

    # Persist events to database
    for event in events:
        db_event = Event(
            session_id=session_id,
            timestamp=event["timestamp"],
            source_type=event["source_type"],
            user=event.get("user"),
            process=event.get("process"),
            ip_address=event.get("ip_address"),
            action=event["action"],
            raw_log=event["raw_log"],
            severity=event.get("severity", "low"),
            is_suspicious=event.get("is_suspicious", 0),
            detection_rule=event.get("detection_rule"),
            mitre_tactic=event.get("mitre_tactic"),
            mitre_technique=event.get("mitre_technique"),
        )
        db.add(db_event)

    # Persist chains
    for chain in chains:
        db_chain = AttackChain(
            session_id=session_id,
            chain_name=chain["chain_name"],
            phase=chain["phase"],
            event_ids=chain["event_ids"],
            description=chain["description"],
            severity=chain["severity"],
            mitre_tactic=chain.get("mitre_tactic"),
            order_index=chain["order_index"],
        )
        db.add(db_chain)

    # Persist analysis
    db_analysis = AnalysisResult(
        session_id=session_id,
        summary=explanation_data["explanation"],
        risk_score=risk_score,
        risk_level=risk_level,
        attack_narrative=narrative,
        mitre_mapping=[e.get("mitre_technique") for e in events if e.get("mitre_technique")],
        recommendations=None,
        graph_data=graph_data,
    )
    db.add(db_analysis)
    db.commit()

    # Cache for fast access
    session_cache[session_id] = {
        "events": events,
        "chains": chains,
        "graph": graph_data,
        "explanation": explanation_data,
        "narrative": narrative,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

    return {
        "session_id": session_id,
        "total_events": len(events),
        "suspicious_events": sum(1 for e in events if e.get("is_suspicious")),
        "attack_phases": len(chains),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "message": f"Successfully analyzed {len(events)} events",
    }


@router.post("/analyze-live-stream")
async def analyze_live_stream(
    payload: dict,
    db: Session = Depends(get_db)
):
    """
    Directly analyze real events collected from the live WebSocket monitor.
    Constructs attack graph, timeline, and AI narrative for the live stream.
    """
    events = payload.get("events", [])
    if not events:
        raise HTTPException(400, "No live events provided for analysis")

    session_id = str(uuid.uuid4())[:8]

    # Run detection, risk, graph, AI explanation
    events = detect_suspicious_events(events)
    risk_score, risk_level = calculate_risk_score(events)
    chains = build_attack_chains(events)
    graph_data = build_attack_graph(events)
    explanation_data = generate_explanation(events, chains, risk_score, risk_level)
    narrative = get_attack_narrative(chains)

    # Persist events
    for event in events:
        ts = event.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now()

        db_event = Event(
            session_id=session_id,
            timestamp=ts or datetime.now(),
            source_type=event.get("source_type", "live"),
            user=event.get("user"),
            process=event.get("process"),
            ip_address=event.get("ip_address"),
            action=event.get("action", "live_event"),
            raw_log=event.get("raw_log", ""),
            severity=event.get("severity", "low"),
            is_suspicious=event.get("is_suspicious", 0),
            detection_rule=event.get("detection_rule"),
            mitre_tactic=event.get("mitre_tactic"),
            mitre_technique=event.get("mitre_technique"),
        )
        db.add(db_event)

    for chain in chains:
        db_chain = AttackChain(
            session_id=session_id,
            chain_name=chain["chain_name"],
            phase=chain["phase"],
            event_ids=chain["event_ids"],
            description=chain["description"],
            severity=chain["severity"],
            mitre_tactic=chain.get("mitre_tactic"),
            order_index=chain["order_index"],
        )
        db.add(db_chain)

    db_analysis = AnalysisResult(
        session_id=session_id,
        summary=explanation_data["explanation"],
        risk_score=risk_score,
        risk_level=risk_level,
        attack_narrative=narrative,
        mitre_mapping=[e.get("mitre_technique") for e in events if e.get("mitre_technique")],
        recommendations=None,
        graph_data=graph_data,
    )
    db.add(db_analysis)
    db.commit()

    session_cache[session_id] = {
        "events": events,
        "chains": chains,
        "graph": graph_data,
        "explanation": explanation_data,
        "narrative": narrative,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

    return {
        "session_id": session_id,
        "total_events": len(events),
        "suspicious_events": sum(1 for e in events if e.get("is_suspicious")),
        "attack_phases": len(chains),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "message": f"Successfully analyzed {len(events)} live stream events",
    }


class ExplainEventRequest(BaseModel):
    event: Dict[str, Any]
    use_ai: Optional[bool] = False


@router.post("/explain-event")
async def explain_event_endpoint(req: ExplainEventRequest):
    """
    Generate an authoritative, detailed cybersecurity explanation of a single log event.
    Provides immediate rich rule-based DFIR breakdown, plus optional Gemini AI deep-dive.
    """
    try:
        explanation = await run_in_threadpool(
            explain_single_event,
            req.event,
            req.use_ai,
            os.getenv("GEMINI_API_KEY")
        )
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to explain log event: {str(e)}")


@router.get("/events")
async def get_events(
    session_id: str = Query(...),
    suspicious_only: bool = Query(False),
    db: Session = Depends(get_db)
):
    """Get all parsed events for a session."""
    if session_id in session_cache:
        events = session_cache[session_id]["events"]
        if suspicious_only:
            events = [e for e in events if e.get("is_suspicious")]
        return {
            "session_id": session_id,
            "events": _serialize_events(events),
            "count": len(events),
        }

    query = db.query(Event).filter(Event.session_id == session_id)
    if suspicious_only:
        query = query.filter(Event.is_suspicious == 1)
    db_events = query.order_by(Event.timestamp).all()

    return {
        "session_id": session_id,
        "events": [_db_event_to_dict(e) for e in db_events],
        "count": len(db_events),
    }


@router.get("/timeline")
async def get_timeline(
    session_id: str = Query(...),
    db: Session = Depends(get_db)
):
    """Get timeline data for visualization."""
    if session_id in session_cache:
        events = session_cache[session_id]["events"]
    else:
        db_events = db.query(Event).filter(
            Event.session_id == session_id
        ).order_by(Event.timestamp).all()
        events = [_db_event_to_dict(e) for e in db_events]

    timeline_data = []
    for i, event in enumerate(events):
        ts = event["timestamp"]
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()

        timeline_data.append({
            "index": i,
            "timestamp": ts,
            "action": event.get("action", "unknown"),
            "user": event.get("user"),
            "ip_address": event.get("ip_address"),
            "process": event.get("process"),
            "severity": event.get("severity", "low"),
            "is_suspicious": event.get("is_suspicious", 0),
            "detection_rule": event.get("detection_rule"),
            "raw_log": event.get("raw_log", ""),
            "mitre_tactic": event.get("mitre_tactic"),
            "mitre_technique": event.get("mitre_technique"),
        })

    return {
        "session_id": session_id,
        "timeline": timeline_data,
        "total": len(timeline_data),
    }


@router.get("/graph")
async def get_graph(
    session_id: str = Query(...),
    recalculate: bool = Query(False),
    sample: bool = Query(False),
    db: Session = Depends(get_db)
):
    """Get attack graph data for Cytoscape.js visualization."""
    if sample or session_id in ("demo", "sample", "simulation", "apt"):
        return {
            "session_id": session_id,
            "graph": generate_weaponized_attack_graph(),
        }

    # If recalculate requested or session not in cache, rebuild with latest engine
    if recalculate or (session_id not in session_cache):
        db_events = db.query(Event).filter(
            Event.session_id == session_id
        ).order_by(Event.timestamp).all()
        if db_events:
            events = [_db_event_to_dict(e) for e in db_events]
            graph_data = build_attack_graph(events)

            analysis = db.query(AnalysisResult).filter(AnalysisResult.session_id == session_id).first()
            if analysis:
                analysis.graph_data = graph_data
                db.commit()

            if session_id in session_cache:
                session_cache[session_id]["graph"] = graph_data
            else:
                session_cache[session_id] = {"graph": graph_data, "events": events}

            return {
                "session_id": session_id,
                "graph": graph_data,
            }

    if session_id in session_cache and "graph" in session_cache[session_id]:
        cached = session_cache[session_id]["graph"]
        if cached.get("elements", {}).get("edges"):
            return {
                "session_id": session_id,
                "graph": cached,
            }

    # Fetch and auto-upgrade any legacy stored graph
    db_events = db.query(Event).filter(Event.session_id == session_id).order_by(Event.timestamp).all()
    if db_events:
        events = [_db_event_to_dict(e) for e in db_events]
        graph_data = build_attack_graph(events)
        analysis = db.query(AnalysisResult).filter(AnalysisResult.session_id == session_id).first()
        if analysis:
            analysis.graph_data = graph_data
            db.commit()
        return {
            "session_id": session_id,
            "graph": graph_data,
        }

    analysis = db.query(AnalysisResult).filter(
        AnalysisResult.session_id == session_id
    ).first()

    if not analysis or not analysis.graph_data:
        raise HTTPException(404, "Graph data not found for this session")

    return {
        "session_id": session_id,
        "graph": analysis.graph_data,
    }


@router.get("/analysis")
async def get_analysis(
    session_id: str = Query(...),
    db: Session = Depends(get_db)
):
    """Get full analysis including AI explanation and attack narrative."""
    if session_id in session_cache:
        cache = session_cache[session_id]
        return {
            "session_id": session_id,
            "explanation": cache["explanation"]["explanation"],
            "model_used": cache["explanation"]["model_used"],
            "narrative": cache["narrative"],
            "risk_score": cache["risk_score"],
            "risk_level": cache["risk_level"],
            "chains": cache["chains"],
        }

    analysis = db.query(AnalysisResult).filter(
        AnalysisResult.session_id == session_id
    ).first()

    if not analysis:
        raise HTTPException(404, "Analysis not found for this session")

    chains = db.query(AttackChain).filter(
        AttackChain.session_id == session_id
    ).order_by(AttackChain.order_index).all()

    return {
        "session_id": session_id,
        "explanation": analysis.summary,
        "narrative": analysis.attack_narrative,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "chains": [{
            "chain_name": c.chain_name,
            "phase": c.phase,
            "description": c.description,
            "severity": c.severity,
            "mitre_tactic": c.mitre_tactic,
            "order_index": c.order_index,
            "event_ids": c.event_ids,
        } for c in chains],
    }


@router.get("/replay")
async def get_replay(
    session_id: str = Query(...),
    db: Session = Depends(get_db)
):
    """Get events in order for replay mode."""
    if session_id in session_cache:
        events = session_cache[session_id]["events"]
        chains = session_cache[session_id]["chains"]
    else:
        db_events = db.query(Event).filter(
            Event.session_id == session_id
        ).order_by(Event.timestamp).all()
        events = [_db_event_to_dict(e) for e in db_events]
        chains = []

    replay_steps = []
    for i, event in enumerate(events):
        if not event.get("is_suspicious"):
            continue

        ts = event["timestamp"]
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()

        replay_steps.append({
            "step": len(replay_steps) + 1,
            "timestamp": ts,
            "action": event.get("action", "unknown"),
            "user": event.get("user"),
            "ip_address": event.get("ip_address"),
            "process": event.get("process"),
            "severity": event.get("severity", "low"),
            "detection_rule": event.get("detection_rule"),
            "mitre_tactic": event.get("mitre_tactic"),
            "mitre_technique": event.get("mitre_technique"),
            "raw_log": event.get("raw_log", ""),
            "description": _get_step_description(event),
        })

    return {
        "session_id": session_id,
        "total_steps": len(replay_steps),
        "steps": replay_steps,
        "chains": [{
            "chain_name": c.get("chain_name") if isinstance(c, dict) else c.chain_name,
            "phase": c.get("phase") if isinstance(c, dict) else c.phase,
            "severity": c.get("severity") if isinstance(c, dict) else c.severity,
        } for c in chains] if chains else [],
    }


# ── Real Log Sources ────────────────────────────────────────────────────────

@router.get("/log-sources")
async def get_log_sources():
    """Get available real log sources (replaces old sample-logs)."""
    sources = list_available_sources()
    return {"sources": sources}


@router.get("/extract-local-logs")
async def get_local_log_channels():
    """Get available Windows Event Log channels for local extraction."""
    channels = await run_in_threadpool(get_windows_log_channels)
    return {"channels": channels, "platform": __import__('platform').system()}


@router.get("/monitor/status")
async def get_monitor_status():
    """Get real-time monitor status."""
    return get_monitor_stats()


# ── WebSocket for Real-Time Monitoring ──────────────────────────────────────

@router.websocket("/ws/monitor")
async def websocket_monitor(websocket: WebSocket):
    """
    WebSocket endpoint for real-time log monitoring.
    Streams new log events as they appear in system logs.
    """
    await websocket.accept()
    try:
        await start_monitoring(websocket)
        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()
                # Handle client commands
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
                elif data == "stop":
                    break
            except WebSocketDisconnect:
                break
    finally:
        await stop_monitoring(websocket)


# ── Settings endpoints ──────────────────────────────────────────────────────

@router.get("/settings")
async def get_settings():
    """Get current AI configuration."""
    from dotenv import dotenv_values
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    env = dotenv_values(env_path) if os.path.exists(env_path) else {}
    return {
        "ai_model": env.get("AI_MODEL", "auto"),
        "gemini_key": _mask_key(env.get("GEMINI_API_KEY", "")),
        "openai_key": _mask_key(env.get("OPENAI_API_KEY", "")),
        "ollama_url": env.get("OLLAMA_URL", "http://localhost:11434"),
    }


@router.post("/settings")
async def save_settings(data: dict):
    """Save AI configuration to .env file."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    lines = []
    # Read existing
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            lines = f.readlines()

    updates = {}
    if "ai_model" in data:
        updates["AI_MODEL"] = data["ai_model"]
    if "gemini_key" in data and not data["gemini_key"].startswith("***"):
        updates["GEMINI_API_KEY"] = data["gemini_key"]
    if "openai_key" in data and not data["openai_key"].startswith("***"):
        updates["OPENAI_API_KEY"] = data["openai_key"]
    if "ollama_url" in data:
        updates["OLLAMA_URL"] = data["ollama_url"]

    # Merge with existing
    existing_keys = set()
    new_lines = []
    for line in lines:
        key = line.split("=")[0].strip() if "=" in line else None
        if key and key in updates:
            new_lines.append(f"{key}={updates[key]}\n")
            existing_keys.add(key)
        else:
            new_lines.append(line)

    # Append new keys
    for key, value in updates.items():
        if key not in existing_keys:
            new_lines.append(f"{key}={value}\n")

    try:
        with open(env_path, "w") as f:
            f.writelines(new_lines)
    except Exception:
        pass

    # Reload env in memory
    os.environ.update(updates)

    return {"status": "ok", "message": "Settings saved"}


@router.post("/test-ai")
async def test_ai():
    """Test AI model connectivity."""
    try:
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            return {"success": False, "message": "No API key configured. Set a Gemini API key in Settings."}

        from google import genai
        client = genai.Client(api_key=api_key)

        models_to_try = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-2.5-flash"]
        last_error = None

        for model in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents="Respond with only: OK"
                )
                if response and response.text:
                    return {
                        "success": True,
                        "model": model,
                        "message": f"Connection verified! {model} responded: {response.text.strip()}"
                    }
            except Exception as err:
                last_error = err
                continue

        return {"success": False, "message": str(last_error or "Empty response from model")}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _mask_key(key: str) -> str:
    """Mask API key for safe display."""
    if not key or len(key) < 8:
        return ""
    return key[:6] + "***" + key[-4:]


# ── Helper functions ────────────────────────────────────────────────────────

def _serialize_events(events):
    """Serialize events list for JSON response."""
    result = []
    for e in events:
        ts = e["timestamp"]
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()
        result.append({
            **{k: v for k, v in e.items() if k != "timestamp"},
            "timestamp": ts,
        })
    return result


def _db_event_to_dict(event: Event) -> dict:
    """Convert DB Event object to dictionary."""
    return {
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "source_type": event.source_type,
        "user": event.user,
        "process": event.process,
        "ip_address": event.ip_address,
        "action": event.action,
        "raw_log": event.raw_log,
        "severity": event.severity,
        "is_suspicious": event.is_suspicious,
        "detection_rule": event.detection_rule,
        "mitre_tactic": event.mitre_tactic,
        "mitre_technique": event.mitre_technique,
    }


def _get_step_description(event: dict) -> str:
    """Generate human-readable description for a replay step."""
    action = event.get("action", "unknown")
    user = event.get("user", "unknown")
    ip = event.get("ip_address", "unknown")
    process = event.get("process", "")

    descriptions = {
        "ssh_failed_login": f"Failed SSH login attempt for user '{user}' from IP {ip}",
        "ssh_invalid_user": f"SSH login attempt with invalid user '{user}' from IP {ip}",
        "ssh_accepted_login": f"Successful SSH login as '{user}' from IP {ip}",
        "sudo_command": f"User '{user}' executed sudo command: {process}",
        "su_attempt": f"Switch user attempt to '{user}'",
        "process_execution": f"Process executed: {process}",
        "network_drop": f"Firewall dropped connection from {ip}",
        "outbound_connection": f"Outbound connection detected to external IP",
        "auth_failure": f"Authentication failure for '{user}' from {ip}",
        "windows_logon_failure": f"Windows logon failure for '{user}' from {ip}",
        "windows_logon_success": f"Windows logon success for '{user}' from {ip}",
        "windows_logoff": f"Windows logoff for '{user}'",
        "windows_explicit_logon": f"Explicit logon (RunAs) by '{user}' from {ip}",
        "windows_privilege_assigned": f"Special privileges assigned to '{user}'",
        "windows_process_created": f"Process created by '{user}': {process}",
        "windows_process_terminated": f"Process terminated by '{user}': {process}",
        "windows_user_created": f"New user account created: '{user}'",
        "windows_group_member_added": f"User '{user}' added to privileged group",
        "windows_account_modified": f"Account '{user}' was modified",
        "windows_credential_validation": f"Credential validation for '{user}' from {ip}",
        "windows_log_cleared": f"Windows Event Log was cleared — potential anti-forensics",
        "windows_service_installed": f"New service installed: {process}",
        "windows_service_state_change": f"Service state changed: {process}",
        "windows_dcom_error": f"DCOM permission error from {process}",
        "windows_powershell_scriptblock": f"PowerShell script block executed by '{user}'",
        "windows_powershell_module": f"PowerShell module loaded by '{user}'",
        "windows_powershell_pipeline": f"PowerShell pipeline executed by '{user}'",
        "windows_defender_detection": f"Windows Defender detected a threat: {process}",
        "windows_firewall_allowed": f"Firewall allowed connection from {ip}",
        "windows_firewall_blocked": f"Firewall blocked connection from {ip}",
        "windows_error": f"Windows error event: {process}",
        "windows_warning": f"Windows warning event: {process}",
        "windows_event": f"Windows event from {process}",
    }

    return descriptions.get(action, f"Event: {action} by {user} from {ip}")
