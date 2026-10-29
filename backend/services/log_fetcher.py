"""
Real Log Fetcher Service
Fetches real security logs from public datasets and local system.
Sources:
  - Loghub Linux (GitHub) — real honeypot SSH auth failures
  - Elastic Security Examples (GitHub) — real auth.log with attacks
  - Local system logs (/var/log/auth.log, /var/log/syslog)
  - Windows Event Logs (Security, System, Application, PowerShell)
  - Previously downloaded log files in real_logs/
"""
import os
import platform
import subprocess
from pathlib import Path
from typing import Optional
from datetime import datetime

# Paths to downloaded real logs (use /tmp/real_logs in serverless Vercel environment)
REAL_LOGS_DIR = Path("/tmp/real_logs") if os.getenv("VERCEL") else Path(__file__).parent.parent / "real_logs"

# Real local system log sources
LOG_SOURCES = {
    "local_auth": {
        "name": "💻 Local System Auth Log",
        "description": "Live authentication log from this machine (/var/log/auth.log) — real-time PAM, sudo, and login events",
        "file": None,
        "local_path": "/var/log/auth.log",
        "type": "linux",
    },
    "local_syslog": {
        "name": "📋 Local System Syslog",
        "description": "Live system log from this machine (/var/log/syslog) — kernel, service, and daemon events",
        "file": None,
        "local_path": "/var/log/syslog",
        "type": "linux",
    },
}

# Windows Event Log channels available for extraction
WINDOWS_LOG_CHANNELS = {
    "win_security": {
        "name": "🛡️ Windows Security Log",
        "description": "Login attempts, privilege escalation, account lockouts, audit policy changes — the most critical log for forensics",
        "channel": "Security",
        "type": "windows",
        "event_ids": [4624, 4625, 4634, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756, 4776],
        "needs_admin": True,
    },
    "win_system": {
        "name": "⚙️ Windows System Log",
        "description": "Service start/stop, driver failures, unexpected shutdowns, kernel events — system health and stability indicators",
        "channel": "System",
        "type": "windows",
        "event_ids": None,
        "needs_admin": False,
    },
    "win_application": {
        "name": "📦 Windows Application Log",
        "description": "Application crashes, .NET runtime errors, installer events — detect malicious software behavior",
        "channel": "Application",
        "type": "windows",
        "event_ids": None,
        "needs_admin": False,
    },
    "win_powershell": {
        "name": "⚡ PowerShell Log",
        "description": "Script execution, command history, remote sessions — detect living-off-the-land attacks and fileless malware",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "type": "windows",
        "event_ids": None,
        "needs_admin": False,
    },
    "win_defender": {
        "name": "🦠 Windows Defender Log",
        "description": "Malware detections, scan results, real-time protection events — antivirus activity on this machine",
        "channel": "Microsoft-Windows-Windows Defender/Operational",
        "type": "windows",
        "event_ids": None,
        "needs_admin": False,
    },
    "win_firewall": {
        "name": "🔥 Windows Firewall Log",
        "description": "Allowed and blocked connections, rule changes — network security boundary events",
        "channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "type": "windows",
        "event_ids": None,
        "needs_admin": False,
    },
}


def _build_extraction_script(channel: str, max_events: int) -> str:
    """
    Build a PowerShell script that extracts Windows Event Logs.
    Uses a temp .ps1 file approach to avoid shell escaping issues.
    """
    return f"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
try {{
    $events = Get-WinEvent -LogName '{channel}' -MaxEvents {max_events} 2>$null
    if ($events -and $events.Count -gt 0) {{
        foreach ($e in $events) {{
            $ts = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $id = $e.Id
            $level = if ($e.LevelDisplayName) {{ $e.LevelDisplayName }} else {{ 'Unknown' }}
            $provider = if ($e.ProviderName) {{ $e.ProviderName -replace ' ', '-' }} else {{ 'Unknown' }}
            $rawMsg = if ($e.Message) {{ $e.Message }} else {{ 'No message available' }}
            $msg = ($rawMsg -replace "[`r`n]+", ' ')
            if ($msg.Length -gt 500) {{ $msg = $msg.Substring(0, 500) }}
            $user = ''
            if ($rawMsg -match 'Account Name:\\s+([^\\s\\r\\n]+)') {{ $user = $Matches[1] }}
            elseif ($rawMsg -match 'User Name:\\s+([^\\s\\r\\n]+)') {{ $user = $Matches[1] }}
            $ip = ''
            if ($rawMsg -match 'Source Network Address:\\s+(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})') {{
                $ip = $Matches[1]
            }}
            $outline = "$ts EventID=$id Level=$level Provider=$provider"
            if ($user -and $user -ne '-' -and $user -ne 'N/A') {{ $outline += " User=$user" }}
            if ($ip -and $ip -ne '-') {{ $outline += " IP=$ip" }}
            $outline += " Message=$msg"
            Write-Output $outline
        }}
    }} else {{
        Write-Output "NO_EVENTS_FOUND"
    }}
}} catch {{
    Write-Output "ERROR: $($_.Exception.Message)"
}}
"""


def extract_windows_logs(channel_id: str, max_events: int = 500) -> Optional[str]:
    """
    Extract Windows Event Logs from the local machine using PowerShell.
    Converts events into a parseable text format for the forensics pipeline.
    Returns log content as a string, or None if unavailable.
    """
    if platform.system() != "Windows":
        return None

    channel_info = WINDOWS_LOG_CHANNELS.get(channel_id)
    if not channel_info:
        return None

    channel = channel_info["channel"]

    try:
        # Write PS script to a temp file to avoid shell escaping issues
        import tempfile
        ps_script = _build_extraction_script(channel, max_events)
        
        temp_dir = Path("/tmp/temp") if os.getenv("VERCEL") else Path(__file__).parent.parent / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        ps_file = temp_dir / f"extract_{channel_id}.ps1"
        
        try:
            ps_file.write_text(ps_script, encoding='utf-8')
            
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps_file)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
            )
            
            if result.returncode == 0 and result.stdout and result.stdout.strip():
                output = result.stdout.strip()
                if output == "NO_EVENTS_FOUND":
                    return None
                if output.startswith("ERROR:"):
                    print(f"[log_fetcher] PowerShell error for {channel_id}: {output}")
                    # Fall through to wevtutil
                else:
                    return output
        finally:
            # Clean up temp file
            try:
                ps_file.unlink(missing_ok=True)
            except Exception:
                pass

        # Fallback: try wevtutil for simpler extraction
        result = subprocess.run(
            ["wevtutil", "qe", channel, "/c:" + str(max_events), "/rd:true", "/f:text"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        )
        if result.returncode == 0 and result.stdout and result.stdout.strip():
            # Convert wevtutil output to our format
            return _convert_wevtutil_output(result.stdout)

    except subprocess.TimeoutExpired:
        print(f"[log_fetcher] Timeout extracting {channel_id}")
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[log_fetcher] Error extracting {channel_id}: {e}")
        return None

    return None


def _convert_wevtutil_output(raw_output: str) -> Optional[str]:
    """Convert wevtutil /f:text output into our standard line format."""
    import re
    lines = []
    current_event = {}
    
    for line in raw_output.split('\n'):
        line = line.strip().replace('\x00', '')  # Remove null bytes
        if not line:
            continue
        
        if line.startswith('Event['):
            # Save previous event
            if current_event.get('date'):
                formatted = _format_wevtutil_event(current_event)
                if formatted:
                    lines.append(formatted)
            current_event = {}
        elif ':' in line:
            key, _, value = line.partition(':')
            key = key.strip()
            value = value.strip()
            if key == 'Date':
                current_event['date'] = value
            elif key == 'Event ID':
                current_event['event_id'] = value
            elif key == 'Level':
                current_event['level'] = value
            elif key == 'Source':
                current_event['source'] = value
            elif key == 'User Name':
                current_event['user'] = value
            elif key == 'Description':
                current_event['description'] = value
    
    # Don't forget the last event
    if current_event.get('date'):
        formatted = _format_wevtutil_event(current_event)
        if formatted:
            lines.append(formatted)
    
    return '\n'.join(lines) if lines else None


def _format_wevtutil_event(event: dict) -> Optional[str]:
    """Format a single wevtutil event into our standard line format."""
    date = event.get('date', '')
    # Parse the wevtutil date format: 2026-04-18T12:08:42.3430000Z
    try:
        # Take just the datetime part
        dt_str = date[:19].replace('T', ' ')
    except Exception:
        dt_str = date
    
    event_id = event.get('event_id', '0')
    level = event.get('level', 'Unknown')
    source = event.get('source', 'Unknown')
    user = event.get('user', '')
    desc = event.get('description', 'No description').replace('\n', ' ').replace('\r', '')[:500]
    
    line = f"{dt_str} EventID={event_id} Level={level} Provider={source}"
    if user:
        line += f" User={user}"
    line += f" Message={desc}"
    return line


def get_windows_log_channels() -> list:
    """
    List available Windows Event Log channels with availability status.
    Only returns results on Windows systems.
    Uses a single batched PowerShell call for performance.
    """
    if platform.system() != "Windows":
        return []

    # Build a single PowerShell script that checks all channels at once
    channel_ids = list(WINDOWS_LOG_CHANNELS.keys())
    channel_names = [WINDOWS_LOG_CHANNELS[cid]["channel"] for cid in channel_ids]
    
    # Build batch check script
    checks = []
    for i, ch_name in enumerate(channel_names):
        checks.append(
            f"try {{ $log = Get-WinEvent -ListLog '{ch_name}' -ErrorAction Stop; "
            f"Write-Output \"CHANNEL_{i}=$($log.RecordCount)\" }} "
            f"catch {{ Write-Output \"CHANNEL_{i}=UNAVAILABLE\" }}"
        )
    
    ps_script = "; ".join(checks)
    
    results = {}
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20
        )
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line.startswith('CHANNEL_') and '=' in line:
                    idx_part, _, val = line.partition('=')
                    try:
                        idx = int(idx_part.replace('CHANNEL_', ''))
                        if val.strip() == 'UNAVAILABLE':
                            results[channel_ids[idx]] = (False, 0)
                        else:
                            count = int(val.strip())
                            results[channel_ids[idx]] = (count > 0, count)
                    except (ValueError, IndexError):
                        pass
    except Exception as e:
        print(f"[log_fetcher] Error checking channels: {e}")

    channels = []
    for channel_id, info in WINDOWS_LOG_CHANNELS.items():
        available, event_count = results.get(channel_id, (False, 0))
        
        channels.append({
            "id": channel_id,
            "name": info["name"],
            "description": info["description"],
            "channel": info["channel"],
            "type": "windows",
            "available": available,
            "event_count": event_count,
            "is_live": True,
            "needs_admin": info.get("needs_admin", False),
        })

    return channels


def get_real_log(source_id: str, max_lines: int = 500) -> Optional[str]:
    """
    Read a real log source by ID.
    Returns the log content as a string, or None if unavailable.
    """
    # Check if it's a Windows channel extraction
    if source_id in WINDOWS_LOG_CHANNELS:
        return extract_windows_logs(source_id, max_events=max_lines)

    source = LOG_SOURCES.get(source_id)
    if not source:
        return None

    # Local system log
    local_path = source.get("local_path")
    if local_path:
        return _read_local_log(local_path, max_lines)

    return None


def _read_local_log(path: str, max_lines: int) -> Optional[str]:
    """Read local system log file (tail last N lines)."""
    try:
        # Use tail to get recent entries (more relevant than head)
        result = subprocess.run(
            ["tail", "-n", str(max_lines), path],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        # Try with sudo if permission denied
        result = subprocess.run(
            ["sudo", "tail", "-n", str(max_lines), path],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass

    # Direct read fallback
    try:
        with open(path, 'r', errors='ignore') as f:
            lines = f.readlines()
            return "".join(lines[-max_lines:])
    except PermissionError:
        return None
    except Exception:
        return None


def _read_file(filepath: Path, max_lines: int) -> Optional[str]:
    """Read a downloaded log file."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
            # Return last max_lines for large files
            if len(lines) > max_lines:
                lines = lines[:max_lines]
            return "".join(lines)
    except Exception:
        return None


def _download_and_read(url: str, filepath: Path, max_lines: int) -> Optional[str]:
    """Download a log file from URL and read it."""
    try:
        import httpx
        filepath.parent.mkdir(parents=True, exist_ok=True)
        response = httpx.get(url, timeout=30, follow_redirects=True)
        if response.status_code == 200:
            filepath.write_text(response.text)
            return _read_file(filepath, max_lines)
    except Exception:
        pass
    return None


def list_available_sources() -> list:
    """List available real local log sources with availability status."""
    sources = []
    for source_id, source in LOG_SOURCES.items():
        available = False
        line_count = 0

        # Check local path
        local_path = source.get("local_path")
        if local_path and os.path.exists(local_path):
            try:
                available = os.access(local_path, os.R_OK)
                if available:
                    with open(local_path, 'r', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
            except Exception:
                available = False

        if available:
            sources.append({
                "id": source_id,
                "name": source["name"],
                "description": source["description"],
                "type": source.get("type", "linux"),
                "available": available,
                "line_count": line_count,
                "is_live": True,
            })

    return sources

    return sources
