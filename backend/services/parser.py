"""
Log Parser Service
Parses various log formats (Linux auth, syslog, Windows Event, network/firewall)
into structured Event objects. Handles real-world log formats from:
- Loghub Linux dataset (pam_unix style)
- Elastic auth.log (standard sshd)
- Local system logs (ISO timestamps with timezone)
- SecRepo auth logs
"""
import re
from datetime import datetime
from typing import List, Dict, Optional

# ── Linux Auth / Syslog patterns ────────────────────────────────────────────
# Standard syslog with process[pid]
SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)"
)

# pam_unix style: process(pam_unix)[pid]  (Loghub / real honeypots)
PAM_UNIX_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\((?P<pam_module>[^)]+)\))?\[(?P<pid>\d+)\]\s*:\s*(?P<message>.*)"
)

# ISO timestamp syslog (modern systemd / Kali format)
# e.g. 2026-04-05T00:23:54.912700+05:30 Ghosti sshd[1234]: ...
ISO_SYSLOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[^\s]*)\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)"
)

# SSH specific patterns
SSH_FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
SSH_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)")
SSH_DISCONNECT = re.compile(r"Disconnected from (?:authenticating )?user (\S+) (\S+) port (\d+)")
SSH_INVALID_USER = re.compile(r"Invalid user (\S+) from (\S+)")

# pam_unix auth patterns (from real logs)
PAM_AUTH_FAILURE = re.compile(r"authentication failure;.*?(?:user=(\S+))?.*?(?:rhost=(\S+))?")
PAM_CHECK_PASS = re.compile(r"check pass; user (\S+)")
PAM_SESSION_OPEN = re.compile(r"session opened for user (\S+)")
PAM_SESSION_CLOSE = re.compile(r"session closed for user (\S+)")

# Sudo / privilege escalation
SUDO_PATTERN = re.compile(r"(\S+)\s*:\s*.*COMMAND=(.*)")
SU_PATTERN = re.compile(r"su\[\d+\]:\s*(?:Successful|FAILED) su for (\S+) by (\S+)")

# CRON
CRON_PATTERN = re.compile(r"CRON\[(\d+)\].*session (\S+) for user (\S+)")

# Process execution
EXEC_PATTERN = re.compile(r"(?:exe|COMMAND)=['\"]?(/\S+)")

# ── Windows Event Log patterns ──────────────────────────────────────────────
WINDOWS_LOGON = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+.*"
    r"(?:EventID[=:]?\s*(?P<event_id>\d+)).*"
    r"(?:Account Name[=:]?\s*(?P<user>\S+))?"
)

# ── Network / firewall patterns ─────────────────────────────────────────────
NETFLOW_PATTERN = re.compile(
    r"(?P<timestamp>\S+\s+\S+)\s+(?P<action>\S+)\s+"
    r"(?:SRC=)?(?P<src_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<src_port>\d+))?\s*"
    r"(?:DST=)?(?P<dst_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<dst_port>\d+))?"
)

IPTABLES_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"kernel:.*(?P<action>IN|OUT|DROP|ACCEPT).*"
    r"SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+.*"
    r"(?:SPT=(?P<src_port>\d+))?\s*(?:DPT=(?P<dst_port>\d+))?"
)

# Generic timestamp patterns
ISO_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
ISO_TIMESTAMP_FULL = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
SYSLOG_TIMESTAMP = re.compile(r"(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")

# Current year (syslog doesn't include year)
CURRENT_YEAR = datetime.now().year


def parse_syslog_timestamp(month_str: str, day_str: str, time_str: str) -> datetime:
    """Parse a syslog-style timestamp into a datetime object."""
    try:
        ts_string = f"{CURRENT_YEAR} {month_str} {day_str} {time_str}"
        return datetime.strptime(ts_string, "%Y %b %d %H:%M:%S")
    except ValueError:
        return datetime.now()


def parse_iso_timestamp(ts_str: str) -> datetime:
    """Parse an ISO-style timestamp (strips timezone)."""
    # Strip timezone suffix for simple parsing
    clean = re.sub(r'[+-]\d{2}:\d{2}$', '', ts_str)
    clean = re.sub(r'\.\d+', '', clean)  # strip microseconds
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
        try:
            return datetime.strptime(clean, fmt)
        except ValueError:
            continue
    return datetime.now()


def extract_timestamp(line: str) -> datetime:
    """Extract timestamp from a log line."""
    iso = ISO_TIMESTAMP.search(line)
    if iso:
        return parse_iso_timestamp(iso.group())
    syslog = SYSLOG_TIMESTAMP.search(line)
    if syslog:
        return parse_syslog_timestamp(syslog.group(1), syslog.group(2), syslog.group(3))
    return datetime.now()


def _classify_message(message: str, event: Dict) -> Dict:
    """Classify a syslog message into an action type."""
    msg_lower = message.lower()

    # SSH failed login
    m = SSH_FAILED.search(message)
    if m:
        event["user"] = m.group(1)
        event["ip_address"] = m.group(2)
        event["action"] = "ssh_failed_login"
        return event

    # SSH accepted login
    m = SSH_ACCEPTED.search(message)
    if m:
        event["user"] = m.group(1)
        event["ip_address"] = m.group(2)
        event["action"] = "ssh_accepted_login"
        return event

    # SSH invalid user
    m = SSH_INVALID_USER.search(message)
    if m:
        event["user"] = m.group(1)
        event["ip_address"] = m.group(2)
        event["action"] = "ssh_invalid_user"
        return event

    # pam_unix authentication failure (Loghub / real honeypot format)
    m = PAM_AUTH_FAILURE.search(message)
    if m and "authentication failure" in msg_lower:
        user = m.group(1)
        rhost = m.group(2)
        event["user"] = user if user else "unknown"
        event["ip_address"] = rhost
        event["action"] = "ssh_failed_login"
        return event

    # pam check pass (user unknown)
    m = PAM_CHECK_PASS.search(message)
    if m:
        event["user"] = m.group(1)
        event["action"] = "ssh_invalid_user"
        return event

    # Sudo commands
    m = SUDO_PATTERN.search(message)
    if m:
        event["user"] = m.group(1)
        event["action"] = "sudo_command"
        event["process"] = m.group(2).strip()
        return event

    # su attempts
    m = SU_PATTERN.search(message)
    if m:
        event["user"] = m.group(1)
        event["action"] = "su_attempt"
        return event

    # CRON sessions
    m = CRON_PATTERN.search(message)
    if m:
        event["user"] = m.group(3)
        event["action"] = f"cron_session_{m.group(2)}"
        event["process"] = "CRON"
        return event

    # Process execution
    m = EXEC_PATTERN.search(message)
    if m:
        event["action"] = "process_execution"
        event["process"] = m.group(1)
        return event

    # Session events
    m = PAM_SESSION_OPEN.search(message)
    if m:
        event["user"] = m.group(1)
        event["action"] = "session_opened"
        return event

    m = PAM_SESSION_CLOSE.search(message)
    if m:
        event["user"] = m.group(1)
        event["action"] = "session_closed"
        return event

    # Generic classification
    if "session opened" in msg_lower:
        event["action"] = "session_opened"
    elif "session closed" in msg_lower:
        event["action"] = "session_closed"
    elif "authentication failure" in msg_lower:
        event["action"] = "auth_failure"
        # Try to extract rhost
        rhost_match = re.search(r"rhost=(\S+)", message)
        if rhost_match:
            event["ip_address"] = rhost_match.group(1)
        user_match = re.search(r"user=(\S+)", message)
        if user_match:
            event["user"] = user_match.group(1)
    elif "connection" in msg_lower:
        event["action"] = "connection"
    elif "listening" in msg_lower:
        event["action"] = "service_start"
    elif "error" in msg_lower or "fail" in msg_lower:
        event["action"] = "error"
    elif "new seat" in msg_lower or "new session" in msg_lower:
        event["action"] = "session_opened"
    else:
        event["action"] = "syslog_event"

    return event


def parse_linux_log(line: str) -> Optional[Dict]:
    """Parse a Linux auth/syslog line into a structured event dict.
    Handles standard syslog, pam_unix, and ISO-timestamp formats.
    """
    line = line.strip()
    if not line:
        return None

    # Try ISO timestamp format first (modern systemd / Kali)
    iso_match = ISO_SYSLOG_PATTERN.match(line)
    if iso_match:
        data = iso_match.groupdict()
        timestamp = parse_iso_timestamp(data["timestamp"])
        message = data.get("message", "")
        process = data.get("process", "unknown").strip()
        event = {
            "timestamp": timestamp,
            "source_type": "linux",
            "user": None,
            "process": process,
            "ip_address": None,
            "action": "unknown",
            "raw_log": line,
        }
        return _classify_message(message, event)

    # Try pam_unix format: process(pam_module)[pid]
    pam_match = PAM_UNIX_PATTERN.match(line)
    if pam_match:
        data = pam_match.groupdict()
        timestamp = parse_syslog_timestamp(data["month"], data["day"], data["time"])
        message = data.get("message", "")
        process = data.get("process", "unknown").strip()
        event = {
            "timestamp": timestamp,
            "source_type": "linux",
            "user": None,
            "process": process,
            "ip_address": None,
            "action": "unknown",
            "raw_log": line,
        }
        return _classify_message(message, event)

    # Standard syslog format
    match = SYSLOG_PATTERN.match(line)
    if match:
        data = match.groupdict()
        timestamp = parse_syslog_timestamp(data["month"], data["day"], data["time"])
        message = data.get("message", "")
        process = data.get("process", "unknown").strip()
        event = {
            "timestamp": timestamp,
            "source_type": "linux",
            "user": None,
            "process": process,
            "ip_address": None,
            "action": "unknown",
            "raw_log": line,
        }
        return _classify_message(message, event)

    return None


def parse_network_log(line: str) -> Optional[Dict]:
    """Parse a network/firewall log line."""
    # Try iptables format
    m = IPTABLES_PATTERN.search(line)
    if m:
        data = m.groupdict()
        timestamp = parse_syslog_timestamp(data["month"], data["day"], data["time"])
        dst_port = data.get("dst_port", "")
        return {
            "timestamp": timestamp,
            "source_type": "network",
            "user": None,
            "process": f"port_{dst_port}" if dst_port else "firewall",
            "ip_address": data["src_ip"],
            "action": f"network_{data['action'].lower()}",
            "raw_log": line.strip(),
        }

    # Try generic netflow/connection format
    m = NETFLOW_PATTERN.search(line)
    if m:
        data = m.groupdict()
        timestamp = extract_timestamp(line)
        return {
            "timestamp": timestamp,
            "source_type": "network",
            "user": None,
            "process": f"port_{data.get('dst_port', 'unknown')}",
            "ip_address": data["src_ip"],
            "action": data.get("action", "connection").lower(),
            "raw_log": line.strip(),
        }

    return None


def parse_windows_log(line: str) -> Optional[Dict]:
    """Parse a Windows event log line.
    
    Handles our extracted format:
      2026-04-18 12:08:42 EventID=10016 Level=Warning Provider=Microsoft-Windows-X User=DOMAIN\\user IP=1.2.3.4 Message=...
    Also handles raw wevtutil and other Windows log formats.
    """
    line = line.strip()
    if not line:
        return None

    timestamp = extract_timestamp(line)
    event = {
        "timestamp": timestamp,
        "source_type": "windows",
        "user": None,
        "process": None,
        "ip_address": None,
        "action": "windows_event",
        "raw_log": line,
    }

    # Extract structured fields from our format: EventID=X Level=Y Provider=Z User=U IP=I Message=M
    event_id = None
    eid_match = re.search(r"EventID[=:]?\s*(\d+)", line, re.IGNORECASE)
    if eid_match:
        try:
            event_id = int(eid_match.group(1))
        except ValueError:
            pass

    # Split line into structured fields and message
    # Format: "TIMESTAMP EventID=X Level=Y Provider=Z User=U IP=I Message=..."
    msg_start = line.find('Message=')
    header_part = line[:msg_start] if msg_start > 0 else line
    message_part = line[msg_start + 8:] if msg_start > 0 else ''

    # Extract Provider/Source as process (from header only)
    provider_match = re.search(r"Provider[=:]?\s*(\S+(?:-\S+)*)", header_part, re.IGNORECASE)
    if provider_match:
        event["process"] = provider_match.group(1)
    else:
        source_match = re.search(r"Source[=:]?\s*(\S+(?:-\S+)*)", header_part, re.IGNORECASE)
        if source_match:
            event["process"] = source_match.group(1)

    # Extract User field (only from header, must be "User=" not part of another word)
    user_match = re.search(r"(?:^|\s)User[=:]?\s*(\S+)", header_part, re.IGNORECASE)
    if user_match:
        user_val = user_match.group(1)
        # Skip system/machine accounts and noise
        if user_val not in ('-', 'N/A', '$', 'SYSTEM', 'LOCAL', 'Unknown'):
            event["user"] = user_val
    else:
        # Also try Account Name in Message for Security logs
        acct_match = re.search(r"Account Name[=:]\s*(\S+)", message_part, re.IGNORECASE)
        if acct_match:
            acct_val = acct_match.group(1)
            if acct_val not in ('-', 'N/A', '$', 'SYSTEM', 'LOCAL'):
                event["user"] = acct_val

    # Extract IP address (from header first, then message)
    ip_match = re.search(r"(?:^|\s)IP[=:]?\s*(\d+\.\d+\.\d+\.\d+)", header_part, re.IGNORECASE)
    if ip_match:
        event["ip_address"] = ip_match.group(1)
    else:
        ip_msg = re.search(r"Source Network Address[=:]\s*(\d+\.\d+\.\d+\.\d+)", message_part, re.IGNORECASE)
        if ip_msg:
            event["ip_address"] = ip_msg.group(1)
        else:
            # Fallback: find any IP in the message (not header, to avoid matching provider names)
            ip_fallback = re.search(r"(?<![.\w])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![.\w])", message_part)
            if ip_fallback:
                ip = ip_fallback.group(1)
                if not ip.startswith("0.") and ip != "127.0.0.1":
                    event["ip_address"] = ip

    # Extract Level
    level_match = re.search(r"Level[=:]?\s*(\S+)", line, re.IGNORECASE)
    severity = "low"
    if level_match:
        level = level_match.group(1).lower()
        if level in ("critical", "error"):
            severity = "critical" if level == "critical" else "high"
        elif level == "warning":
            severity = "medium"

    # Classify action based on EventID (precise) or message content (fallback)
    msg_lower = line.lower()

    if event_id:
        # Security events
        if event_id == 4624:
            event["action"] = "windows_logon_success"
        elif event_id == 4625:
            event["action"] = "windows_logon_failure"
            severity = "high"
        elif event_id == 4634:
            event["action"] = "windows_logoff"
        elif event_id == 4648:
            event["action"] = "windows_explicit_logon"
            severity = "medium"
        elif event_id == 4672:
            event["action"] = "windows_privilege_assigned"
            severity = "medium"
        elif event_id == 4688:
            event["action"] = "windows_process_created"
        elif event_id == 4689:
            event["action"] = "windows_process_terminated"
        elif event_id == 4720:
            event["action"] = "windows_user_created"
            severity = "high"
        elif event_id in (4722, 4723, 4724, 4725, 4726):
            event["action"] = "windows_account_modified"
            severity = "medium"
        elif event_id in (4728, 4732, 4756):
            event["action"] = "windows_group_member_added"
            severity = "high"
        elif event_id == 4776:
            event["action"] = "windows_credential_validation"
        elif event_id == 1102:
            event["action"] = "windows_log_cleared"
            severity = "critical"
        elif event_id == 7045:
            event["action"] = "windows_service_installed"
            severity = "medium"
        elif event_id in (7036, 7040):
            event["action"] = "windows_service_state_change"
        elif event_id == 10016:
            event["action"] = "windows_dcom_error"
        elif event_id == 4104:
            event["action"] = "windows_powershell_scriptblock"
            severity = "medium"
        elif event_id == 4103:
            event["action"] = "windows_powershell_module"
        elif event_id in (800, 40961, 40962, 53504):
            event["action"] = "windows_powershell_pipeline"
        elif event_id in (1116, 1117):
            event["action"] = "windows_defender_detection"
            severity = "critical"
        elif event_id in (1006, 1007, 1008, 1009, 1010, 1013, 1015):
            event["action"] = "windows_defender_event"
        elif event_id == 5156:
            event["action"] = "windows_firewall_allowed"
        elif event_id == 5157:
            event["action"] = "windows_firewall_blocked"
            severity = "medium"
        elif event_id in (2004, 2005, 2006, 2033):
            event["action"] = "windows_firewall_rule_change"
            severity = "medium"
        else:
            # Use Provider name as secondary classifier
            provider = (event.get("process") or "").lower()
            if "powershell" in provider:
                event["action"] = "windows_powershell_pipeline"
            elif "defender" in provider:
                event["action"] = "windows_defender_event"
            elif "firewall" in provider:
                event["action"] = "windows_firewall_event"
            elif 4600 <= event_id <= 4699:
                event["action"] = "windows_logon_event"
            elif 4700 <= event_id <= 4799:
                event["action"] = "windows_account_event"
            else:
                event["action"] = "windows_event"
    else:
        # Fallback to message-based classification (no EventID found)
        if "logon" in msg_lower and ("success" in msg_lower or "4624" in msg_lower):
            event["action"] = "windows_logon_success"
        elif "logon" in msg_lower and ("fail" in msg_lower or "4625" in msg_lower):
            event["action"] = "windows_logon_failure"
            severity = "high"
        elif "special privileges" in msg_lower:
            event["action"] = "windows_privilege_assigned"
            severity = "medium"
        elif "process" in msg_lower and "creat" in msg_lower:
            event["action"] = "windows_process_created"
        elif "malware" in msg_lower or "threat" in msg_lower or "detected" in msg_lower:
            event["action"] = "windows_defender_detection"
            severity = "critical"
        elif "service" in msg_lower and ("start" in msg_lower or "stop" in msg_lower):
            event["action"] = "windows_service_state_change"
        elif "error" in msg_lower or "fail" in msg_lower:
            event["action"] = "windows_error"
            severity = "medium"
        elif "warning" in msg_lower:
            event["action"] = "windows_warning"

    event["severity"] = severity
    return event


def detect_log_type(lines: List[str]) -> str:
    """Auto-detect log type from content."""
    sample = "\n".join(lines[:20]).lower()
    if "sshd" in sample or "pam_unix" in sample or "sudo" in sample or "cron" in sample:
        return "linux"
    elif "eventid" in sample or "windows" in sample or "4624" in sample or "4625" in sample:
        return "windows"
    elif "src=" in sample or "dst=" in sample or "iptables" in sample or "firewall" in sample:
        return "network"
    if SYSLOG_PATTERN.match(lines[0] if lines else ""):
        return "linux"
    if PAM_UNIX_PATTERN.match(lines[0] if lines else ""):
        return "linux"
    if ISO_SYSLOG_PATTERN.match(lines[0] if lines else ""):
        return "linux"
    return "linux"


def parse_logs(content: str, log_type: str = "auto") -> List[Dict]:
    """
    Main entry point: parse log content into structured events.
    Auto-detects log type if not specified.
    """
    lines = [l for l in content.strip().split("\n") if l.strip()]
    if not lines:
        return []

    if log_type == "auto":
        log_type = detect_log_type(lines)

    parser_map = {
        "linux": parse_linux_log,
        "windows": parse_windows_log,
        "network": parse_network_log,
    }

    parser = parser_map.get(log_type, parse_linux_log)
    events = []
    for line in lines:
        event = parser(line)
        if event:
            events.append(event)

    events.sort(key=lambda e: e["timestamp"])
    return events
