"""
Real-Time Log Monitor Service
Watches local live system logs (Windows Event Logs or Linux syslog/auth.log)
and streams real events via WebSocket with live threat detection.
"""
import asyncio
import subprocess
import os
import platform
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Set, Optional, Dict, List

from services.parser import parse_linux_log, parse_windows_log
from services.detector import detect_suspicious_events

# Active WebSocket connections
active_connections: Set = set()

# Monitor state
_monitor_task: Optional[asyncio.Task] = None
_monitoring = False

# Stats
monitor_stats = {
    "total_events": 0,
    "suspicious_events": 0,
    "start_time": None,
    "is_running": False,
    "platform": platform.system(),
    "active_channel": "System & Application" if platform.system() == "Windows" else "/var/log",
}

# Windows tracking
_last_record_ids: Dict[str, int] = {}
WINDOWS_CHANNELS = [
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
]

# Linux tracking
LINUX_MONITOR_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
]


async def start_monitoring(websocket):
    """Register a new WebSocket connection for live monitoring."""
    active_connections.add(websocket)
    monitor_stats["is_running"] = True
    if not monitor_stats["start_time"]:
        monitor_stats["start_time"] = datetime.now().isoformat()

    # Send initial status
    await websocket.send_json({
        "type": "status",
        "message": f"Connected to real-time monitor ({platform.system()})",
        "stats": monitor_stats,
        "monitoring": WINDOWS_CHANNELS if platform.system() == "Windows" else list(_get_available_linux_paths()),
    })

    # On Windows, seed with recent real events so the user sees live data immediately
    if platform.system() == "Windows":
        initial_events = _fetch_recent_windows_events(limit=15)
        for evt in initial_events:
            await websocket.send_json({
                "type": "event",
                "event": evt,
                "stats": monitor_stats,
            })

    # Start the background watcher task if not already running
    global _monitor_task
    if _monitor_task is None or _monitor_task.done():
        _monitor_task = asyncio.create_task(_watch_logs())


async def stop_monitoring(websocket):
    """Unregister a WebSocket connection."""
    active_connections.discard(websocket)
    if not active_connections:
        global _monitoring
        _monitoring = False
        monitor_stats["is_running"] = False


async def _watch_logs():
    """Main watcher loop dispatching to Windows or Linux monitor."""
    global _monitoring
    _monitoring = True
    try:
        if platform.system() == "Windows":
            await _watch_windows_logs()
        else:
            await _watch_linux_logs()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        await _broadcast({
            "type": "error",
            "message": f"Monitor error: {str(e)}",
        })
    finally:
        _monitoring = False
        monitor_stats["is_running"] = False


def _fetch_recent_windows_events(limit: int = 15) -> List[Dict]:
    """Fetch the latest real Windows events on startup and record their IDs."""
    events = []
    for channel in ["System", "Application"]:
        try:
            cmd = ["wevtutil", "qe", channel, f"/c:{limit}", "/rd:true", "/f:xml"]
            res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                parsed = _parse_wevtutil_xml(res.stdout, channel)
                for evt, rec_id in parsed:
                    if rec_id > _last_record_ids.get(channel, 0):
                        _last_record_ids[channel] = rec_id
                    events.append(evt)
        except Exception:
            pass

    # Sort chronological
    events.sort(key=lambda x: x.get("timestamp", ""))
    return events[-limit:]


async def _watch_windows_logs():
    """Continuously poll Windows Event Logs for new events in real time."""
    # Initialize record IDs if not set
    for ch in WINDOWS_CHANNELS:
        if ch not in _last_record_ids:
            try:
                cmd = ["wevtutil", "qe", ch, "/c:1", "/rd:true", "/f:xml"]
                res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=4)
                if res.returncode == 0 and res.stdout.strip():
                    parsed = _parse_wevtutil_xml(res.stdout, ch)
                    if parsed:
                        _last_record_ids[ch] = parsed[0][1]
            except Exception:
                _last_record_ids[ch] = 0

    while _monitoring and active_connections:
        try:
            new_events = []
            for ch in WINDOWS_CHANNELS:
                last_id = _last_record_ids.get(ch, 0)
                try:
                    # Query recent 5 events
                    cmd = ["wevtutil", "qe", ch, "/c:5", "/rd:true", "/f:xml"]
                    res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=4)
                    if res.returncode == 0 and res.stdout.strip():
                        parsed = _parse_wevtutil_xml(res.stdout, ch)
                        for evt, rec_id in parsed:
                            if rec_id > last_id:
                                _last_record_ids[ch] = max(_last_record_ids.get(ch, 0), rec_id)
                                new_events.append(evt)
                except Exception:
                    pass

            if new_events:
                # Sort and broadcast new events
                new_events.sort(key=lambda x: x.get("timestamp", ""))
                for evt in new_events:
                    monitor_stats["total_events"] += 1
                    if evt.get("is_suspicious"):
                        monitor_stats["suspicious_events"] += 1

                    await _broadcast({
                        "type": "event",
                        "event": evt,
                        "stats": {
                            "total_events": monitor_stats["total_events"],
                            "suspicious_events": monitor_stats["suspicious_events"],
                        },
                    })
            else:
                # Send periodic heartbeat
                await _broadcast({
                    "type": "heartbeat",
                    "stats": {
                        "total_events": monitor_stats["total_events"],
                        "suspicious_events": monitor_stats["suspicious_events"],
                    },
                    "timestamp": datetime.now().isoformat(),
                })

            await asyncio.sleep(1.5)
        except Exception as e:
            await asyncio.sleep(2.0)


def _parse_wevtutil_xml(raw_xml: str, channel: str) -> List[tuple]:
    """Parse wevtutil XML output into normalized event dicts and record IDs."""
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    results = []

    for block in raw_xml.split("</Event>"):
        if "<Event" not in block:
            continue
        try:
            xml_text = block[block.find("<Event"):] + "</Event>"
            root = ET.fromstring(xml_text)
            sys_el = root.find("ns:System", ns)
            if sys_el is None:
                continue

            rec_id_str = sys_el.findtext("ns:EventRecordID", default="0", namespaces=ns)
            rec_id = int(rec_id_str) if rec_id_str.isdigit() else 0
            event_id = sys_el.findtext("ns:EventID", default="0", namespaces=ns)
            provider_el = sys_el.find("ns:Provider", ns)
            provider = provider_el.attrib.get("Name", "Windows") if provider_el is not None else "Windows"
            time_el = sys_el.find("ns:TimeCreated", ns)
            time_str = time_el.attrib.get("SystemTime", datetime.now().isoformat()) if time_el is not None else datetime.now().isoformat()

            # Level: 1=Crit, 2=Error, 3=Warn, 4=Info
            level_code = sys_el.findtext("ns:Level", default="4", namespaces=ns)
            severity = "critical" if level_code == "1" else ("high" if level_code == "2" else ("medium" if level_code == "3" else "low"))

            # User SID or Name
            sec_el = sys_el.find("ns:Security", ns)
            user = sec_el.attrib.get("UserID", "") if sec_el is not None else ""

            # Extract Data items
            data_el = root.find("ns:EventData", ns)
            data_items = [d.text for d in data_el.findall("ns:Data", ns) if d.text] if data_el is not None else []
            msg = " ".join(data_items[:4]) if data_items else f"{provider} Event {event_id}"

            # Format raw log line for detection
            raw_line = f"{time_str[:19].replace('T', ' ')} EventID={event_id} Level={severity.title()} Provider={provider} Message={msg}"

            event = {
                "timestamp": time_str[:19],
                "action": f"windows_{channel.lower().split('-')[-1]}_event",
                "source_type": "windows",
                "process": provider,
                "user": user or None,
                "ip_address": None,
                "severity": severity,
                "raw_log": raw_line,
                "is_suspicious": 1 if severity in ("high", "critical") else 0,
                "detection_rule": f"Windows {severity.title()} Event (ID {event_id})" if severity in ("high", "critical") else None,
                "mitre_technique": "T1059 - Command and Scripting Interpreter" if "PowerShell" in provider or "cmd" in msg.lower() else None,
            }

            results.append((event, rec_id))
        except Exception:
            continue

    return results


async def _watch_linux_logs():
    """Watch Linux syslog/auth.log files using tail -f."""
    paths = list(_get_available_linux_paths())
    if not paths:
        await _broadcast({
            "type": "error",
            "message": "No accessible Linux log files found (/var/log/auth.log, /var/log/syslog).",
        })
        return

    cmd = ["tail", "-f", "-n", "0"] + paths
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    await _broadcast({
        "type": "status",
        "message": f"Real-time monitoring started — watching {len(paths)} system log file(s)",
        "files": paths,
    })

    while _monitoring and active_connections:
        try:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=1.5)
            if line:
                decoded = line.decode("utf-8", errors="ignore").strip()
                if decoded:
                    event = parse_linux_log(decoded)
                    if event:
                        detected = detect_suspicious_events([event])
                        evt = detected[0] if detected else event
                        monitor_stats["total_events"] += 1
                        if evt.get("is_suspicious"):
                            monitor_stats["suspicious_events"] += 1

                        await _broadcast({
                            "type": "event",
                            "event": evt,
                            "stats": monitor_stats,
                        })
        except asyncio.TimeoutError:
            await _broadcast({
                "type": "heartbeat",
                "stats": monitor_stats,
                "timestamp": datetime.now().isoformat(),
            })
        except Exception:
            break

    try:
        process.terminate()
        await process.wait()
    except Exception:
        pass


def _get_available_linux_paths():
    """Get readable Linux log paths."""
    for path in LINUX_MONITOR_PATHS:
        if os.path.exists(path) and os.access(path, os.R_OK):
            yield path


async def _broadcast(data: dict):
    """Broadcast JSON payload to all connected WebSocket clients."""
    dead = set()
    for ws in list(active_connections):
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    active_connections.difference_update(dead)


def get_monitor_stats() -> dict:
    """Get current live monitoring statistics."""
    return {
        **monitor_stats,
        "connected_clients": len(active_connections),
    }
