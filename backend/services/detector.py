"""
Suspicious Event Detector
Rule-based + heuristic detection for identifying suspicious activity in parsed events.
Maps detections to MITRE ATT&CK tactics and techniques.
"""
from typing import List, Dict, Tuple
from collections import defaultdict
from datetime import timedelta

# ── MITRE ATT&CK Mapping ────────────────────────────────────────────────────
MITRE_MAP = {
    "ssh_failed_login":       ("Initial Access",       "T1078 - Valid Accounts / Brute Force"),
    "ssh_invalid_user":       ("Initial Access",       "T1078.001 - Default Accounts"),
    "ssh_accepted_login":     ("Initial Access",       "T1078 - Valid Accounts"),
    "sudo_command":           ("Privilege Escalation",  "T1548.003 - Sudo and Sudo Caching"),
    "su_attempt":             ("Privilege Escalation",  "T1548 - Abuse Elevation Control"),
    "process_execution":      ("Execution",            "T1059 - Command and Scripting Interpreter"),
    "network_drop":           ("Discovery",            "T1046 - Network Service Discovery"),
    "network_accept":         ("Lateral Movement",     "T1021 - Remote Services"),
    "outbound_connection":    ("Exfiltration",         "T1041 - Exfiltration Over C2 Channel"),
    "windows_logon_failure":  ("Initial Access",       "T1078 - Valid Accounts / Brute Force"),
    "windows_logon_success":  ("Initial Access",       "T1078 - Valid Accounts"),
    "windows_privilege_assigned": ("Privilege Escalation", "T1134 - Access Token Manipulation"),
    "windows_explicit_logon": ("Lateral Movement",     "T1078 - Valid Accounts"),
    "windows_process_created": ("Execution",           "T1059 - Command and Scripting Interpreter"),
    "windows_user_created":   ("Persistence",          "T1136 - Create Account"),
    "windows_group_member_added": ("Persistence",      "T1098 - Account Manipulation"),
    "windows_account_modified": ("Persistence",        "T1098 - Account Manipulation"),
    "windows_log_cleared":    ("Defense Evasion",      "T1070.001 - Clear Windows Event Logs"),
    "windows_service_installed": ("Persistence",       "T1543.003 - Windows Service"),
    "windows_powershell_scriptblock": ("Execution",    "T1059.001 - PowerShell"),
    "windows_powershell_module": ("Execution",         "T1059.001 - PowerShell"),
    "windows_powershell_pipeline": ("Execution",       "T1059.001 - PowerShell"),
    "windows_defender_detection": ("Impact",            "T1562.001 - Disable or Modify Tools"),
    "windows_firewall_blocked": ("Discovery",          "T1046 - Network Service Discovery"),
    "windows_credential_validation": ("Credential Access", "T1110 - Brute Force"),
    "windows_dcom_error":     ("Lateral Movement",     "T1021.003 - Distributed Component Object Model"),
}

# Suspicious processes and commands
SUSPICIOUS_PROCESSES = {
    "/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/perl",
    "/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc", "/usr/bin/ncat",
    "/usr/bin/nmap", "/usr/sbin/tcpdump", "/usr/bin/base64",
    "powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe",
    "whoami", "id", "cat /etc/shadow", "cat /etc/passwd",
}

SUSPICIOUS_COMMANDS = [
    "wget", "curl", "nc ", "ncat", "nmap", "tcpdump", "base64",
    "/etc/shadow", "/etc/passwd", "chmod 777", "chmod +s",
    "reverse", "shell", "bind", "payload", "exploit",
    "powershell -enc", "certutil -urlcache", "bitsadmin /transfer",
]

# Known bad / internal IP ranges for detection
INTERNAL_RANGES = ["10.", "172.16.", "172.17.", "172.18.", "192.168.", "127."]


def is_internal_ip(ip: str) -> bool:
    """Check if an IP is in internal/private range."""
    if not ip:
        return True
    return any(ip.startswith(prefix) for prefix in INTERNAL_RANGES)


def detect_suspicious_events(events: List[Dict]) -> List[Dict]:
    """
    Analyze events and flag suspicious ones with severity ratings
    and MITRE ATT&CK mappings.
    """
    # Track patterns for correlation
    failed_logins = defaultdict(list)  # ip -> [timestamps]
    login_sources = defaultdict(set)   # user -> {ips}
    port_scans = defaultdict(list)     # ip -> [ports]

    for event in events:
        action = event.get("action", "")
        ip = event.get("ip_address")
        user = event.get("user")
        process = event.get("process", "")
        timestamp = event.get("timestamp")

        # Default values
        event["is_suspicious"] = 0
        event["severity"] = "low"
        event["detection_rule"] = None
        event["mitre_tactic"] = None
        event["mitre_technique"] = None

        # Apply MITRE mapping
        if action in MITRE_MAP:
            event["mitre_tactic"], event["mitre_technique"] = MITRE_MAP[action]

        # ── Rule 1: Failed login attempts ──
        if action in ("ssh_failed_login", "ssh_invalid_user", "windows_logon_failure"):
            event["is_suspicious"] = 1
            event["severity"] = "medium"
            event["detection_rule"] = "failed_login"
            if ip:
                failed_logins[ip].append(timestamp)

        # ── Rule 2: Brute force detection (5+ failures from same IP in 5 min) ──
        if ip and ip in failed_logins:
            recent = [t for t in failed_logins[ip]
                      if timestamp and t and abs((timestamp - t).total_seconds()) < 300]
            if len(recent) >= 5:
                event["severity"] = "critical"
                event["detection_rule"] = "brute_force"
                event["mitre_technique"] = "T1110 - Brute Force"

        # ── Rule 3: Login from unknown/external IP ──
        if action in ("ssh_accepted_login", "windows_logon_success") and ip:
            if not is_internal_ip(ip):
                event["is_suspicious"] = 1
                event["severity"] = "high"
                event["detection_rule"] = "external_login"
            if user:
                login_sources[user].add(ip)

        # ── Rule 4: Multiple login sources for same user ──
        if user and len(login_sources.get(user, set())) > 2:
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "multiple_login_sources"

        # ── Rule 5: Privilege escalation ──
        if action in ("sudo_command", "su_attempt", "windows_privilege_assigned"):
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "privilege_escalation"

        # ── Rule 6: Suspicious process execution ──
        if process:
            proc_lower = process.lower()
            if any(sp in proc_lower for sp in SUSPICIOUS_COMMANDS):
                event["is_suspicious"] = 1
                event["severity"] = "high"
                event["detection_rule"] = "suspicious_process"
            if process in SUSPICIOUS_PROCESSES:
                event["is_suspicious"] = 1
                event["severity"] = "medium"
                event["detection_rule"] = "known_suspicious_binary"

        # ── Rule 7: Port scanning behavior ──
        if action in ("network_drop", "connection") and ip:
            dst_port = event.get("process", "").replace("port_", "")
            if dst_port.isdigit():
                port_scans[ip].append(int(dst_port))
                if len(set(port_scans[ip])) > 10:
                    event["is_suspicious"] = 1
                    event["severity"] = "critical"
                    event["detection_rule"] = "port_scan"
                    event["mitre_tactic"] = "Discovery"
                    event["mitre_technique"] = "T1046 - Network Service Discovery"

        # ── Rule 8: Outbound connections to external IPs ──
        if action in ("network_accept", "connection"):
            dst_ip = None
            raw = event.get("raw_log", "")
            import re
            dst_match = re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", raw)
            if dst_match:
                dst_ip = dst_match.group(1)
            if dst_ip and not is_internal_ip(dst_ip):
                event["is_suspicious"] = 1
                event["severity"] = "high"
                event["detection_rule"] = "outbound_external"
                event["action"] = "outbound_connection"
                event["mitre_tactic"] = "Exfiltration"
                event["mitre_technique"] = "T1041 - Exfiltration Over C2 Channel"

        # ── Rule 9: Account creation / manipulation ──
        if action in ("windows_user_created", "windows_group_member_added", "windows_account_modified"):
            event["is_suspicious"] = 1
            event["severity"] = "high"
            event["detection_rule"] = "account_manipulation"

        # ── Rule 11: Windows log cleared (anti-forensics) ──
        if action == "windows_log_cleared":
            event["is_suspicious"] = 1
            event["severity"] = "critical"
            event["detection_rule"] = "log_tampering"

        # ── Rule 12: Windows Defender detection ──
        if action == "windows_defender_detection":
            event["is_suspicious"] = 1
            event["severity"] = "critical"
            event["detection_rule"] = "malware_detected"

        # ── Rule 13: PowerShell script execution ──
        if action in ("windows_powershell_scriptblock", "windows_powershell_module"):
            event["is_suspicious"] = 1
            event["severity"] = "medium"
            event["detection_rule"] = "powershell_execution"

        # ── Rule 14: Service installation ──
        if action == "windows_service_installed":
            event["is_suspicious"] = 1
            event["severity"] = "medium"
            event["detection_rule"] = "service_installation"

        # ── Rule 10: Post-exploitation indicators ──
        if process and any(cmd in process.lower() for cmd in
                          ["shadow", "passwd", "whoami", " id", "ifconfig", "ipconfig"]):
            event["is_suspicious"] = 1
            event["severity"] = "critical"
            event["detection_rule"] = "post_exploitation_recon"
            event["mitre_tactic"] = "Discovery"
            event["mitre_technique"] = "T1087 - Account Discovery"

    return events


def calculate_risk_score(events: List[Dict]) -> Tuple[float, str]:
    """Calculate overall risk score (0-100) and risk level."""
    if not events:
        return 0.0, "low"

    severity_weights = {"low": 1, "medium": 3, "high": 7, "critical": 15}
    total_score = 0
    suspicious_count = 0

    for event in events:
        if event.get("is_suspicious"):
            suspicious_count += 1
            total_score += severity_weights.get(event.get("severity", "low"), 1)

    # Normalize: max reasonable score = 100
    max_possible = len(events) * 15
    normalized = min(100, (total_score / max(max_possible, 1)) * 100 * 5)

    # Boost score based on attack chain indicators
    unique_rules = set(e.get("detection_rule") for e in events if e.get("detection_rule"))
    chain_bonus = len(unique_rules) * 5
    normalized = min(100, normalized + chain_bonus)

    if normalized >= 75:
        level = "critical"
    elif normalized >= 50:
        level = "high"
    elif normalized >= 25:
        level = "medium"
    else:
        level = "low"

    return round(normalized, 1), level
