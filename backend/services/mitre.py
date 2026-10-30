"""
MITRE ATT&CK Enterprise Matrix Engine
Provides full Enterprise matrix taxonomy, session correlation, dynamic heatmaps,
kill chain telemetry, and automated Sigma rule synthesis.
"""
from typing import List, Dict, Any, Optional, Tuple
import re

# ── 1. The 14 Official Enterprise Tactics in Kill Chain Sequence ─────────────
MITRE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "RECON", "description": "Gathering victim intelligence to plan operations"},
    {"id": "TA0042", "name": "Resource Development", "short": "RESOURCE_DEV", "description": "Establishing infrastructure, accounts, and tools"},
    {"id": "TA0001", "name": "Initial Access", "short": "INITIAL_ACCESS", "description": "Techniques used to gain an initial foothold on the network"},
    {"id": "TA0002", "name": "Execution", "short": "EXECUTION", "description": "Techniques that result in adversary-controlled code running on a local or remote system"},
    {"id": "TA0003", "name": "Persistence", "short": "PERSISTENCE", "description": "Techniques used to maintain access across restarts and credential changes"},
    {"id": "TA0004", "name": "Privilege Escalation", "short": "PRIV_ESC", "description": "Techniques used to gain higher-level permissions (SYSTEM/Root/Admin)"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "DEF_EVASION", "description": "Techniques used to avoid detection by defenders and security controls"},
    {"id": "TA0006", "name": "Credential Access", "short": "CRED_ACCESS", "description": "Techniques for stealing credentials like passwords and hashes"},
    {"id": "TA0007", "name": "Discovery", "short": "DISCOVERY", "description": "Techniques used to observe the system and internal environment"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "LATERAL_MVMT", "description": "Techniques used to pivot and control remote systems on a network"},
    {"id": "TA0009", "name": "Collection", "short": "COLLECTION", "description": "Techniques used to gather data of interest prior to exfiltration"},
    {"id": "TA0011", "name": "Command and Control", "short": "C2", "description": "Techniques communicating with systems under adversary control"},
    {"id": "TA0010", "name": "Exfiltration", "short": "EXFILTRATION", "description": "Techniques used to steal and extract sensitive data"},
    {"id": "TA0040", "name": "Impact", "short": "IMPACT", "description": "Techniques used to disrupt availability or compromise integrity"},
]

# ── 2. Comprehensive Technique Directory by Tactic ───────────────────────────
TACTIC_TECHNIQUES = {
    "TA0043": [
        {"id": "T1595", "name": "Active Scanning", "sub": "Port & IP Sweeping", "desc": "Probing networks for vulnerable ports and exposed endpoints."},
        {"id": "T1592", "name": "Gather Victim Host Info", "sub": "Hardware/OS Discovery", "desc": "Enumerating operating system version and architecture."},
        {"id": "T1589", "name": "Gather Victim Identity", "sub": "Email & User Harvest", "desc": "Collecting target usernames and administrative credentials."},
    ],
    "TA0042": [
        {"id": "T1583", "name": "Acquire Infrastructure", "sub": "VPS & DNS Setup", "desc": "Purchasing bulletproof VPS or renting C2 domains."},
        {"id": "T1584", "name": "Compromise Infrastructure", "sub": "Botnet Relays", "desc": "Hijacking legitimate third-party servers as proxy relays."},
        {"id": "T1587", "name": "Develop Capabilities", "sub": "Malware & Stagers", "desc": "Compiling custom droppers, loaders, and encrypted payloads."},
    ],
    "TA0001": [
        {"id": "T1078", "name": "Valid Accounts", "sub": "Compromised Credentials", "desc": "Adversaries obtain and abuse credentials of existing legitimate accounts."},
        {"id": "T1190", "name": "Exploit Public-Facing App", "sub": "RCE / Web Vulnerability", "desc": "Exploiting weaknesses in Internet-connected software (e.g., Log4Shell, CVEs)."},
        {"id": "T1566", "name": "Phishing", "sub": "Spearphishing Attachment", "desc": "Sending weaponized emails to trick users into executing malicious attachments."},
        {"id": "T1133", "name": "External Remote Services", "sub": "VPN / RDP Exposure", "desc": "Leveraging externally exposed gateways like RDP (3389) or SSL VPNs."},
    ],
    "TA0002": [
        {"id": "T1059", "name": "Command & Scripting Interpreter", "sub": "Cmd / Shell", "desc": "Abusing command and script interpreters to execute arbitrary commands."},
        {"id": "T1059.001", "name": "PowerShell ScriptBlock", "sub": "Dynamic Memory Scripting", "desc": "Executing encoded or in-memory PowerShell commands to bypass static inspection."},
        {"id": "T1569.002", "name": "Service Execution", "sub": "PsExec / RPC Execution", "desc": "Abusing Windows Service Control Manager to launch processes remotely."},
        {"id": "T1204", "name": "User Execution", "sub": "Malicious Link/File", "desc": "User relies on social engineering to trigger malicious file execution."},
        {"id": "T1047", "name": "Windows Management Instrumentation", "sub": "WMI Execution", "desc": "Using WMI (wmic.exe or Win32_Process) to spawn processes locally or remotely."},
    ],
    "TA0003": [
        {"id": "T1547.001", "name": "Registry Run Keys / Startup", "sub": "Autorun Persistence", "desc": "Adding registry values in HKCU/HKLM Run keys to execute payload on boot."},
        {"id": "T1053.005", "name": "Scheduled Task", "sub": "schtasks.exe", "desc": "Configuring scheduled tasks to re-launch malicious binaries at fixed intervals."},
        {"id": "T1543.003", "name": "Windows Service", "sub": "New Service Creation", "desc": "Installing a new Windows system service to ensure background SYSTEM persistence."},
        {"id": "T1505.003", "name": "Web Shell", "sub": "JSP / PHP / ASPX Backdoor", "desc": "Dropping a persistent web shell into an exposed web server directory."},
        {"id": "T1136", "name": "Create Account", "sub": "Rogue Local/Domain User", "desc": "Creating a secondary user account (e.g. net user backdoor /add)."},
    ],
    "TA0004": [
        {"id": "T1548.003", "name": "Sudo and Sudo Caching", "sub": "Linux Elevation", "desc": "Abusing cached sudo tokens or misconfigured sudoers privileges."},
        {"id": "T1134", "name": "Access Token Manipulation", "sub": "Token Impersonation", "desc": "Duplicating or modifying Windows tokens (SeImpersonatePrivilege, RottenPotato)."},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "sub": "Kernel / Local Exploit", "desc": "Exploiting system software or kernel flaws to transition to SYSTEM context."},
        {"id": "T1055", "name": "Process Injection", "sub": "DLL Injection / Hollowing", "desc": "Injecting code into processes to run with the security context of the target."},
    ],
    "TA0005": [
        {"id": "T1070.001", "name": "Clear Windows Event Logs", "sub": "wevtutil cl Log Wiping", "desc": "Purging event logs to destroy audit trails and forensic evidence."},
        {"id": "T1562.001", "name": "Disable or Modify Tools", "sub": "Tamper Defender / EDR", "desc": "Disabling endpoint antivirus, firewall filters, or Windows Defender real-time scan."},
        {"id": "T1036", "name": "Masquerading", "sub": "Process Name Spoofing", "desc": "Naming malicious files after benign system binaries (svchost.exe, werfault.exe)."},
        {"id": "T1027", "name": "Obfuscated Files or Info", "sub": "Base64 / XOR Packing", "desc": "Encoding commands with Base64, encryption, or compression to evade signature filters."},
    ],
    "TA0006": [
        {"id": "T1003.001", "name": "LSASS Memory Dump", "sub": "Mimikatz / ProcDump", "desc": "Reading credentials and NTLM hashes directly from LSASS process memory."},
        {"id": "T1110", "name": "Brute Force", "sub": "Password Spraying", "desc": "Automated attempts to guess passwords through dictionary or spraying attacks."},
        {"id": "T1555", "name": "Credentials from Password Stores", "sub": "Browser / Vault Extraction", "desc": "Extracting saved passwords from Chrome, LSASS, or Windows Credential Manager."},
        {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "sub": "Kerberoasting / Golden Ticket", "desc": "Abusing Kerberos SPNs to crack Service Account tickets offline."},
    ],
    "TA0007": [
        {"id": "T1046", "name": "Network Service Discovery", "sub": "Port Scan / Nmap", "desc": "Scanning internal subnets to locate domain controllers and database ports."},
        {"id": "T1087", "name": "Account Discovery", "sub": "net user / domain", "desc": "Querying local or Active Directory users and group memberships."},
        {"id": "T1082", "name": "System Information Discovery", "sub": "systeminfo / hostname", "desc": "Querying detailed system configuration, patch levels, and installed updates."},
        {"id": "T1016", "name": "System Network Configuration", "sub": "ipconfig / route", "desc": "Looking up IP addresses, gateway routing, and network adapters."},
    ],
    "TA0008": [
        {"id": "T1021.002", "name": "SMB / Windows Admin Shares", "sub": "C$ / ADMIN$ Pivot", "desc": "Connecting to remote shares using compromised administrative credentials."},
        {"id": "T1021.001", "name": "Remote Desktop Protocol", "sub": "RDP Lateral Pivot", "desc": "Logging into workstations via graphical Remote Desktop sessions."},
        {"id": "T1021.003", "name": "Distributed COM (DCOM)", "sub": "MMC20.Application", "desc": "Using DCOM interfaces to invoke code execution on remote Windows machines."},
        {"id": "T1570", "name": "Lateral Tool Transfer", "sub": "Binary Dropping", "desc": "Transferring tools and secondary payloads from one host to another on the LAN."},
    ],
    "TA0009": [
        {"id": "T1005", "name": "Data from Local System", "sub": "Document Scraping", "desc": "Searching for files with extensions like .pdf, .docx, .kdbx, .sql on disk."},
        {"id": "T1114", "name": "Email Collection", "sub": "Outlook / Exchange Export", "desc": "Extracting sensitive emails, contact lists, and message attachments."},
        {"id": "T1560", "name": "Archive Collected Data", "sub": "Zip / 7z Compression", "desc": "Compressing gathered artifacts into password-protected archives before exfil."},
    ],
    "TA0011": [
        {"id": "T1071.001", "name": "Web Protocols (HTTP/HTTPS)", "sub": "Reverse HTTPS C2 Beacon", "desc": "Communicating with external command-and-control servers using encrypted web traffic."},
        {"id": "T1573", "name": "Encrypted Channel", "sub": "Custom TLS / SSH Tunnel", "desc": "Employing bespoke cryptography or SSH reverse tunnels to hide C2 commands."},
        {"id": "T1105", "name": "Ingress Tool Transfer", "sub": "certutil / curl Download", "desc": "Pulling down second-stage binaries from external adversary infrastructure."},
    ],
    "TA0010": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "sub": "FTP / DNS / ICMP Tunnel", "desc": "Stealing data via non-standard egress protocols like DNS tunneling or raw sockets."},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "sub": "POST Requests", "desc": "Sending stolen databases and tokens directly over existing C2 HTTP sessions."},
        {"id": "T1567", "name": "Exfiltration to Cloud Storage", "sub": "Mega / S3 / Dropbox Drop", "desc": "Uploading stolen archives to legitimate cloud storage providers to bypass DLP."},
    ],
    "TA0040": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "sub": "Ransomware Encryption", "desc": "Encrypting local disks, databases, and shares with symmetric ciphers."},
        {"id": "T1490", "name": "Inhibit System Recovery", "sub": "vssadmin delete shadows", "desc": "Deleting Volume Shadow Copies and system recovery points to prevent rollback."},
        {"id": "T1489", "name": "Service Stop", "sub": "net stop / sc stop", "desc": "Stopping databases, antivirus services, or line-of-business applications."},
    ],
}


def _match_event_to_mitre(event: Dict) -> List[Tuple[str, str]]:
    """
    Given an event dictionary, returns list of matching (tactic_id, technique_id) pairs.
    """
    matches = []
    
    # 1. Direct tag in event
    tech_str = str(event.get("mitre_technique") or "")
    tactic_str = str(event.get("mitre_tactic") or "")
    action = str(event.get("action") or "").lower()
    proc = str(event.get("process") or "").lower()
    rule = str(event.get("detection_rule") or "").lower()
    raw = str(event.get("raw_log") or "").lower()

    # Match by technique ID prefix if present
    found_tech_ids = re.findall(r"T\d{4}(?:\.\d{3})?", tech_str)
    for tid in found_tech_ids:
        for tac_id, techs in TACTIC_TECHNIQUES.items():
            for t in techs:
                if t["id"] == tid or t["id"].startswith(tid):
                    matches.append((tac_id, t["id"]))

    # Heuristic signature matches
    if "powershell" in proc or "powershell" in action or "4104" in raw:
        matches.append(("TA0002", "T1059.001"))
    if "mimikatz" in proc or "mktz" in proc or "lsass" in proc or "1003" in raw:
        matches.append(("TA0006", "T1003.001"))
    if "brute_force" in rule or "4625" in raw or "failed_login" in rule:
        matches.append(("TA0006", "T1110"))
    if "successful_login" in rule or "4624" in raw or "ssh_accepted" in action:
        matches.append(("TA0001", "T1078"))
    if "psexec" in proc or "1569" in raw:
        matches.append(("TA0002", "T1569.002"))
        matches.append(("TA0008", "T1021.002"))
    if "webshell" in proc or "cmd.jsp" in proc:
        matches.append(("TA0003", "T1505.003"))
    if "vssadmin" in proc or "delete shadows" in raw:
        matches.append(("TA0040", "T1490"))
    if "ransom" in proc or "blackcat" in proc or "encrypt" in raw:
        matches.append(("TA0040", "T1486"))
    if "firewall" in proc or "5156" in raw or "5157" in raw or "port_scan" in rule:
        matches.append(("TA0007", "T1046"))
    if "defender" in proc or "1116" in raw or "1117" in raw:
        matches.append(("TA0005", "T1562.001"))
    if "outbound" in rule or "c2" in rule or "beacon" in raw:
        matches.append(("TA0011", "T1071.001"))
    if "exfil" in rule or "exfiltration" in action or "1048" in raw:
        matches.append(("TA0010", "T1048"))
    if "werfault" in proc or "1001" in raw or "livekernelevent" in raw:
        matches.append(("TA0005", "T1036"))

    return list(set(matches))


def build_mitre_matrix(events: List[Dict], use_demo: bool = False) -> Dict:
    """
    Build complete Enterprise MITRE ATT&CK Matrix model with session detection states.
    """
    technique_events = {}  # tech_id -> list of events
    
    # Process events
    for ev in events:
        matched_pairs = _match_event_to_mitre(ev)
        for _, tech_id in matched_pairs:
            if tech_id not in technique_events:
                technique_events[tech_id] = []
            technique_events[tech_id].append(ev)

    # Build Tactic Columns
    tactics_output = []
    tactics_with_detections = set()
    total_detected_techniques = set()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for tac in MITRE_TACTICS:
        tac_id = tac["id"]
        techniques_list = TACTIC_TECHNIQUES.get(tac_id, [])
        tech_cards = []

        for t in techniques_list:
            t_id = t["id"]
            matched_evs = technique_events.get(t_id, [])
            
            # If demo mode is active and no real events, populate realistic APT flags
            is_demo_detected = False
            if use_demo and not events:
                if t_id in ("T1190", "T1059.001", "T1505.003", "T1055", "T1003.001", "T1569.002", "T1021.002", "T1071.001", "T1048", "T1486", "T1490", "T1562.001", "T1110"):
                    is_demo_detected = True

            has_detection = len(matched_evs) > 0 or is_demo_detected

            # Calculate technique severity
            sev = "low"
            if has_detection:
                tactics_with_detections.add(tac_id)
                total_detected_techniques.add(t_id)

                if is_demo_detected and not matched_evs:
                    if t_id in ("T1003.001", "T1486", "T1490", "T1055", "T1569.002"):
                        sev = "critical"
                    elif t_id in ("T1190", "T1059.001", "T1021.002", "T1048", "T1562.001"):
                        sev = "high"
                    else:
                        sev = "medium"
                    event_count = 12 if sev == "critical" else 6
                else:
                    event_count = len(matched_evs)
                    sevs = [e.get("severity", "low").lower() for e in matched_evs]
                    if "critical" in sevs:
                        sev = "critical"
                    elif "high" in sevs:
                        sev = "high"
                    elif "medium" in sevs:
                        sev = "medium"
                    else:
                        sev = "low"

                severity_counts[sev] += 1
            else:
                event_count = 0

            # Generate exportable Sigma Rule snippet for this technique
            sigma_rule = generate_sigma_rule(t_id, t["name"], tac["name"], matched_evs)

            tech_cards.append({
                "id": t_id,
                "name": t["name"],
                "sub": t.get("sub", ""),
                "description": t.get("desc", ""),
                "url": f"https://attack.mitre.org/techniques/{t_id.split('.')[0]}/",
                "is_detected": has_detection,
                "severity": sev if has_detection else "none",
                "event_count": event_count,
                "events_sample": [
                    {
                        "timestamp": str(e.get("timestamp", "")),
                        "action": e.get("action", ""),
                        "user": e.get("user", ""),
                        "process": e.get("process", ""),
                        "severity": e.get("severity", "low"),
                        "raw_log": e.get("raw_log", "")[:240],
                    }
                    for e in matched_evs[:10]
                ],
                "sigma_rule": sigma_rule
            })

        detected_in_col = sum(1 for c in tech_cards if c["is_detected"])
        tactics_output.append({
            "id": tac_id,
            "name": tac["name"],
            "short": tac["short"],
            "description": tac["description"],
            "total_techniques": len(tech_cards),
            "detected_techniques": detected_in_col,
            "has_detections": detected_in_col > 0,
            "techniques": tech_cards
        })

    # Summary Metrics
    total_tactics = len(MITRE_TACTICS)
    covered_tactics = len(tactics_with_detections)
    coverage_pct = round((covered_tactics / total_tactics) * 100, 1) if total_tactics > 0 else 0

    return {
        "summary": {
            "total_tactics": total_tactics,
            "covered_tactics": covered_tactics,
            "coverage_percentage": coverage_pct,
            "total_techniques_detected": len(total_detected_techniques),
            "critical_techniques": severity_counts["critical"],
            "high_techniques": severity_counts["high"],
            "medium_techniques": severity_counts["medium"],
            "low_techniques": severity_counts["low"],
            "total_events_analyzed": len(events),
            "is_demo": use_demo and not events
        },
        "tactics": tactics_output
    }


def generate_sigma_rule(tech_id: str, tech_name: str, tactic_name: str, events: List[Dict]) -> str:
    """
    Synthesize an enterprise-ready Sigma detection rule for SIEMs.
    """
    clean_id = tech_id.replace(".", "_").lower()
    
    # Collect sample processes or actions if available
    procs = list(set([e.get("process") for e in events if e.get("process")]))[:3]
    proc_filter = f"\n      Image|endswith:\n" + "\n".join([f"        - '{p}'" for p in procs]) if procs else "\n      CommandLine|contains: 'suspicious_activity'"

    yaml = f"""title: Detect {tech_name} ({tech_id})
id: sigma-{clean_id}-defense
status: production
description: Identifies hostile behavior matching MITRE ATT&CK technique {tech_id} ({tech_name}) under tactic {tactic_name}.
author: Chronos Forensics Engine (Autonomous Synthesizer)
references:
  - https://attack.mitre.org/techniques/{tech_id.split('.')[0]}/
tags:
  - attack.{tactic_name.lower().replace(' ', '_')}
  - attack.{clean_id}
logsource:
  category: process_creation
  product: windows
detection:
  selection:{proc_filter}
  condition: selection
falsepositives:
  - Legitimate administrative system orchestration
level: high
"""
    return yaml.strip()
