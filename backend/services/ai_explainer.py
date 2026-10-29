"""
AI Explanation Engine
Generates human-readable attack explanations.
Supports: Google Gemini (default), OpenAI, Ollama (local), or rule-based fallback.
"""
import os
import json
import httpx
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
AI_MODEL = os.getenv("AI_MODEL", "auto")  # "gemini", "openai", "ollama", "auto", "none"


def generate_explanation(events: List[Dict], chains: List[Dict],
                         risk_score: float, risk_level: str) -> Dict:
    """
    Generate AI-powered explanation of the attack.
    Priority: Gemini → OpenAI → Ollama → Rule-based
    """
    context = _build_context(events, chains, risk_score, risk_level)

    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    ai_model = os.getenv("AI_MODEL", "auto")

    explanation = None
    model_used = "rule-based"

    # 1. Try Gemini (Google AI)
    if ai_model in ("gemini", "auto") and gemini_key:
        explanation = _call_gemini(context, api_key=gemini_key)
        if explanation:
            model_used = "gemini"

    # 2. Try OpenAI
    if not explanation and ai_model in ("openai", "auto") and openai_key:
        explanation = _call_openai(context)
        if explanation:
            model_used = "openai"

    # 3. Try Ollama (local)
    if not explanation and ai_model in ("ollama", "auto"):
        explanation = _call_ollama(context)
        if explanation:
            model_used = "ollama"

    # 4. Fallback to rule-based
    if not explanation:
        explanation = _rule_based_explanation(events, chains, risk_score, risk_level)
        model_used = "rule-based"

    return {
        "explanation": explanation,
        "model_used": model_used,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def _build_context(events: List[Dict], chains: List[Dict],
                   risk_score: float, risk_level: str) -> str:
    """Build a context string for the AI model."""
    suspicious = [e for e in events if e.get("is_suspicious")]

    lines = [
        "You are a senior cybersecurity forensic analyst writing an incident report.",
        "Analyze these real log events and provide a detailed, structured report with:",
        "1. **Executive Summary** — a clear, plain-English summary of the attack",
        "2. **Attack Methodology** — step-by-step breakdown of what the attacker did",
        "3. **MITRE ATT&CK Mapping** — techniques observed with IDs",
        "4. **Indicators of Compromise (IOCs)** — IPs, users, processes involved",
        "5. **Recommended Response Actions** — prioritized incident response steps",
        "",
        "Format your response in Markdown with headers and bullet points.",
        "",
        f"Risk Score: {risk_score}/100 ({risk_level})",
        f"Total Events: {len(events)}",
        f"Suspicious Events: {len(suspicious)}",
        f"Attack Phases Detected: {len(chains)}",
        "",
        "Attack Chain Phases:",
    ]

    for chain in chains:
        lines.append(f"  - {chain['chain_name']} ({chain['severity']}): {chain['description'][:200]}")

    lines.append("\nKey Suspicious Events (sample):")
    for e in suspicious[:25]:
        ts = e["timestamp"].isoformat() if hasattr(e["timestamp"], "isoformat") else str(e["timestamp"])
        lines.append(
            f"  [{ts}] {e.get('action')} | User: {e.get('user')} | "
            f"IP: {e.get('ip_address')} | Severity: {e.get('severity')} | "
            f"Rule: {e.get('detection_rule')} | MITRE: {e.get('mitre_technique')}"
        )

    return "\n".join(lines)


def _call_gemini(context: str, api_key: Optional[str] = None) -> Optional[str]:
    """Call Google Gemini API for explanation generation using google-genai SDK."""
    try:
        from google import genai

        key = api_key or os.getenv("GEMINI_API_KEY")
        if not key:
            return None

        client = genai.Client(api_key=key)

        # Try active models in order of preference
        models_to_try = [
            "gemini-3.5-flash-lite",
            "gemini-3.5-flash",
            "gemini-2.5-flash",
            "gemini-flash-latest",
        ]

        for model_name in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=context,
                    config={
                        "temperature": 0.3,
                        "max_output_tokens": 2000,
                    },
                )

                if response and response.text:
                    print(f"[INFO] Gemini ({model_name}) response received ({len(response.text)} chars)")
                    return response.text

            except Exception as model_err:
                err_str = str(model_err)
                if "429" in err_str or "quota" in err_str.lower():
                    print(f"[WARN] Gemini {model_name} quota exceeded, trying next model...")
                    continue
                elif "404" in err_str or "not found" in err_str.lower():
                    print(f"[WARN] Gemini model {model_name} not available, trying next...")
                    continue
                else:
                    print(f"[WARN] Gemini {model_name} error: {model_err}")
                    continue

    except ImportError:
        print("[WARN] google-genai package not installed. Run: pip install google-genai")
    except Exception as e:
        print(f"[WARN] Gemini API error: {e}")

    return None


def _call_openai(context: str) -> Optional[str]:
    """Call OpenAI API for explanation generation."""
    try:
        response = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are an expert cybersecurity forensic analyst."},
                    {"role": "user", "content": context},
                ],
                "temperature": 0.3,
                "max_tokens": 1500,
            },
            timeout=30,
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[WARN] OpenAI API error: {e}")
    return None


def _call_ollama(context: str) -> Optional[str]:
    """Call local Ollama model for explanation generation."""
    try:
        response = httpx.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": "llama3.2",
                "prompt": context,
                "stream": False,
            },
            timeout=60,
        )
        if response.status_code == 200:
            return response.json().get("response", "")
    except Exception:
        pass
    return None


def _rule_based_explanation(events: List[Dict], chains: List[Dict],
                            risk_score: float, risk_level: str) -> str:
    """Generate explanation using rule-based logic (no AI needed)."""
    suspicious = [e for e in events if e.get("is_suspicious")]
    if not suspicious:
        return (
            "## Analysis Complete\n\n"
            "No significant suspicious activity was detected in the provided logs. "
            "The events appear to represent normal system operations.\n\n"
            f"**Risk Score:** {risk_score}/100 ({risk_level})\n"
            f"**Total Events Analyzed:** {len(events)}"
        )

    # Collect unique indicators
    unique_ips = set(e.get("ip_address") for e in suspicious if e.get("ip_address"))
    unique_users = set(e.get("user") for e in suspicious if e.get("user"))
    unique_rules = set(e.get("detection_rule") for e in suspicious if e.get("detection_rule"))

    # Build narrative
    parts = [f"## 🚨 Security Incident Analysis\n"]
    parts.append(f"**Risk Score:** {risk_score}/100 (**{risk_level.upper()}**)\n")
    parts.append(f"**Suspicious Events:** {len(suspicious)} out of {len(events)} total events\n")

    # Executive summary
    parts.append("### Executive Summary\n")
    summary_sentences = []

    if "brute_force" in unique_rules or "failed_login" in unique_rules:
        fail_count = sum(1 for e in suspicious if e.get("detection_rule") in ("brute_force", "failed_login"))
        summary_sentences.append(
            f"Multiple failed authentication attempts ({fail_count} events) were detected, "
            f"consistent with a brute-force attack."
        )

    if "external_login" in unique_rules:
        ext_ips = [e.get("ip_address") for e in suspicious if e.get("detection_rule") == "external_login"]
        summary_sentences.append(
            f"Successful login(s) from external IP(s) ({', '.join(set(str(ip) for ip in ext_ips if ip))}) "
            f"indicate potential unauthorized access."
        )

    if "privilege_escalation" in unique_rules:
        summary_sentences.append(
            "Privilege escalation activity was detected, suggesting the attacker "
            "gained elevated access to the system."
        )

    if "suspicious_process" in unique_rules or "known_suspicious_binary" in unique_rules:
        procs = set(e.get("process") for e in suspicious
                    if e.get("detection_rule") in ("suspicious_process", "known_suspicious_binary"))
        summary_sentences.append(
            f"Suspicious process execution was observed: {', '.join(str(p) for p in procs if p)}."
        )

    if "outbound_external" in unique_rules:
        summary_sentences.append(
            "Outbound connections to external IP addresses were detected, "
            "possibly indicating data exfiltration."
        )

    if "port_scan" in unique_rules:
        summary_sentences.append(
            "Port scanning behavior was identified, suggesting network reconnaissance."
        )

    if "post_exploitation_recon" in unique_rules:
        summary_sentences.append(
            "Post-exploitation reconnaissance commands were executed, "
            "indicating the attacker was gathering system information."
        )

    parts.append(" ".join(summary_sentences) + "\n")

    # Attack timeline
    if chains:
        parts.append("### Attack Kill Chain\n")
        for i, chain in enumerate(chains):
            parts.append(f"**{i+1}. {chain['chain_name']}** — Severity: {chain['severity'].upper()}")
            parts.append(f"   {chain['description'][:300]}\n")

    # IOCs
    parts.append("### Indicators of Compromise (IOCs)\n")
    if unique_ips:
        parts.append(f"**Suspicious IPs:** {', '.join(str(ip) for ip in unique_ips)}")
    if unique_users:
        parts.append(f"**Targeted Accounts:** {', '.join(str(u) for u in unique_users)}")

    # MITRE ATT&CK
    mitre = set()
    for e in suspicious:
        if e.get("mitre_technique"):
            mitre.add(e["mitre_technique"])
    if mitre:
        parts.append("\n### MITRE ATT&CK Techniques\n")
        for t in sorted(mitre):
            parts.append(f"- {t}")

    # Recommendations
    parts.append("\n### Recommended Response Actions\n")
    recommendations = []
    if "brute_force" in unique_rules:
        recommendations.append("1. Block source IPs at the firewall level")
        recommendations.append("2. Implement account lockout policies")
        recommendations.append("3. Enable multi-factor authentication")
    if "external_login" in unique_rules:
        recommendations.append("4. Investigate external login sessions for unauthorized activity")
        recommendations.append("5. Reset credentials for affected accounts")
    if "privilege_escalation" in unique_rules:
        recommendations.append("6. Audit sudo/admin policies and remove unnecessary privileges")
    if "outbound_external" in unique_rules:
        recommendations.append("7. Investigate outbound connections for data exfiltration")
        recommendations.append("8. Block suspicious external IPs")
    if not recommendations:
        recommendations.append("1. Continue monitoring for further suspicious activity")
        recommendations.append("2. Review access logs for the involved accounts")

    parts.extend(recommendations)

    return "\n".join(parts)


# ============================================================================
# SINGLE-EVENT DEEP FORENSIC EXPLANATION ENGINE
# ============================================================================

def _parse_event_tokens(raw_log: str) -> Dict[str, str]:
    """Extract standard key-value tokens from Windows/Syslog strings."""
    tokens = {}
    if not raw_log:
        return tokens
    
    # Try EventID=..., Provider=..., Level=..., Message=...
    import re
    eid_match = re.search(r"EventID[=:\s]+(\d+)", raw_log, re.IGNORECASE)
    if eid_match:
        tokens["event_id"] = eid_match.group(1)
        
    prov_match = re.search(r"Provider[=:\s]+([^\s/]+)", raw_log, re.IGNORECASE)
    if prov_match:
        tokens["provider"] = prov_match.group(1).strip()
        
    level_match = re.search(r"Level[=:\s]+([^\s/]+)", raw_log, re.IGNORECASE)
    if level_match:
        tokens["level"] = level_match.group(1).strip()
        
    msg_match = re.search(r"Message[=:\s]+(.+)$", raw_log, re.IGNORECASE)
    if msg_match:
        tokens["message"] = msg_match.group(1).strip()

    return tokens


def explain_single_event(event: Dict, use_ai: bool = False, api_key: Optional[str] = None) -> Dict:
    """
    Generate an authoritative, detailed cybersecurity explanation of a single log event.
    Provides immediate rich rule-based DFIR breakdown, plus optional Gemini AI deep-dive.
    """
    raw_log = event.get("raw_log", "")
    action = event.get("action", "unknown_event")
    user = event.get("user") or "N/A"
    process = event.get("process") or "N/A"
    ip = event.get("ip_address") or "N/A"
    severity = (event.get("severity") or "low").upper()
    is_suspicious = bool(event.get("is_suspicious"))
    detection_rule = event.get("detection_rule")
    mitre_tech = event.get("mitre_technique")
    mitre_tactic = event.get("mitre_tactic")
    timestamp = str(event.get("timestamp", ""))

    tokens = _parse_event_tokens(raw_log)
    event_id = tokens.get("event_id")

    # If action has event_id or numbers, extract
    if not event_id:
        import re
        id_search = re.search(r"(\d{3,5})", action)
        if id_search:
            event_id = id_search.group(1)

    provider = tokens.get("provider") or process or "System Subsystem"
    message = tokens.get("message") or raw_log

    # Default knowledge base data
    event_name = "System Telemetry Event"
    subsystem = "Host Kernel / OS Telemetry Subsystem"
    summary = f"System recorded action '{action}' at {timestamp}."
    technical_mechanics = "The host operating system telemetry layer generated this diagnostic record as part of routine system instrumentation or audit policy."
    threat_perspective = "No direct exploitation signatures were matched. This event represents normal host activity unless correlated with subsequent privilege escalation or lateral movement."
    artifacts = [
        "Windows Event Viewer -> System / Application / Security logs",
        "Correlated parent-child process tree via Sysmon or EDR",
    ]
    investigation_steps = [
        "Verify if the user context matches expected operational baselines.",
        "Check whether adjacent telemetry from the same timestamp indicates unusual spikes.",
        "Ensure host time synchronization is accurate for multi-host correlation."
    ]
    mitre_description = "Unclassified or routine system telemetry."

    # Specific Knowledge Base Mappings
    if event_id == "1001" or "error reporting" in str(process).lower() or "livekernelevent" in raw_log.lower():
        event_name = "Windows Error Reporting (WER) / Diagnostic Telemetry (Event 1001)"
        subsystem = "Windows Error Reporting Service (WerFault.exe)"
        summary = "Windows Error Reporting captured a kernel diagnostic event or non-fatal hardware/subsystem failure (LiveKernelEvent)."
        technical_mechanics = (
            "When a subsystem (such as the GPU display driver, storage controller, or kernel memory manager) "
            "experiences a hang, crash, or watchdog timeout, the Windows Kernel initiates a LiveKernelEvent. "
            "WerFault.exe compiles a diagnostic minidump without initiating a full Blue Screen of Death (BSOD), "
            "and commits event ID 1001 to the Application event log."
        )
        threat_perspective = (
            "While frequently triggered by graphics driver timeouts (TDR) or hardware instability, "
            "advanced attackers also trigger purposeful subsystem crashes to flush in-memory forensic traces, "
            "or abuse WerFault.exe as a Living-off-the-Land binary (LOLBin) for DLL side-loading and process hollowing."
        )
        artifacts = [
            r"%LOCALAPPDATA%\CrashDumps",
            r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
            r"C:\Windows\Minidump",
            r"Windows System Event Log (Event ID 41 - Kernel-Power, Event ID 1001 - BugCheck)"
        ]
        investigation_steps = [
            "Verify the process path of WerFault.exe; it must strictly reside in C:\\Windows\\System32\\.",
            "Inspect the parent process ID (PPID) of WerFault (typically svchost.exe or services.exe).",
            "Check C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive for the exact bucket ID and failing module.",
            "Correlate with device driver updates or hardware telemetry to rule out benign GPU/disk faults."
        ]
        mitre_tech = mitre_tech or "T1059 / T1036"
        mitre_tactic = mitre_tactic or "Defense Evasion / Execution"
        mitre_description = "Subsystem crash logging or potential LOLBin abuse for evasion."

    elif event_id == "4624" or "successful_login" in str(detection_rule).lower():
        event_name = "Successful Security Account Logon (Event 4624)"
        subsystem = "Local Security Authority Subsystem Service (LSASS.exe)"
        summary = f"Account '{user}' successfully authenticated to the host."
        technical_mechanics = (
            "LSASS authenticates the user credentials via Kerberos, NTLM, or Cloud AP. "
            "The event details provide the Logon Type (e.g., Type 2 for interactive console, Type 3 for network share, Type 10 for Remote Desktop)."
        )
        threat_perspective = (
            "Adversaries leverage stolen credentials, Pass-the-Hash, or Kerberoasting to authenticate as valid domain or local users (T1078). "
            "Anomalous logon hours, unexpected source IP addresses, or unusual Logon Types (e.g. Type 10 from untrusted network ranges) indicate account takeover."
        )
        artifacts = [
            "Security Event Log Event 4624 (Logon Type, Source Network Address, Target Domain)",
            "LSASS memory and Kerberos ticket cache (klist)",
            r"C:\Windows\System32\winevt\Logs\Security.evtx"
        ]
        investigation_steps = [
            "Verify the source IP address and workstation name in the logon packet.",
            "Determine the Logon Type (Interactive vs Remote Interactive / RDP vs Network Share).",
            "Check if this account usually accesses this host or exhibits impossible travel velocity."
        ]
        mitre_tech = mitre_tech or "T1078"
        mitre_tactic = mitre_tactic or "Initial Access / Lateral Movement"
        mitre_description = "Valid Accounts: Adversaries obtain and abuse credentials of existing accounts."

    elif event_id == "4625" or "failed_login" in str(detection_rule).lower() or "brute_force" in str(detection_rule).lower():
        event_name = "Failed Security Account Logon (Event 4625)"
        subsystem = "Local Security Authority Subsystem Service (LSASS.exe)"
        summary = f"Logon attempt for account '{user}' was rejected by the authentication subsystem."
        technical_mechanics = (
            "LSASS evaluated the authentication attempt and rejected it due to unknown username, bad password, "
            "account lockout, or logon restrictions (Status / Substatus code, e.g. 0xC000006A = bad password, 0xC0000064 = user name does not exist)."
        )
        threat_perspective = (
            "A burst of 4625 events targeting single or multiple accounts indicates brute-force or password spraying attacks (T1110). "
            "Attackers attempt common wordlists or credential stuffing against exposed RDP, SMB, or SSH interfaces."
        )
        artifacts = [
            "Security Event Log Event 4625 (Failure Status and Substatus codes)",
            "Firewall connection logs matching the source IP address",
            "Account Lockout Status in Active Directory"
        ]
        investigation_steps = [
            "Check the Substatus code: 0xC000006A (bad password) vs 0xC0000064 (account does not exist).",
            "Calculate the frequency of failed attempts within the preceding 10 minutes to detect automated spraying.",
            "Block or rate-limit the originating source IP at the edge firewall."
        ]
        mitre_tech = mitre_tech or "T1110"
        mitre_tactic = mitre_tactic or "Credential Access"
        mitre_description = "Brute Force: Password spraying or automated credential testing."

    elif event_id == "4688" or "process" in str(detection_rule).lower() or "process_creation" in action.lower():
        event_name = "New Process Creation Audit (Event 4688)"
        subsystem = "Windows Process Management Subsystem"
        summary = f"New process '{process}' was created and initialized by user '{user}'."
        technical_mechanics = (
            "The Windows kernel logs process instantiation with the new Process ID, Creator Process ID (PPID), "
            "Mandatory Integrity Level, and complete command-line arguments (when Audit Process Creation CommandLine logging is enabled via GPO)."
        )
        threat_perspective = (
            "Process execution is the backbone of adversary command execution. Attackers invoke living-off-the-land binaries "
            "(certutil, bitsadmin, mshta, wmic, powershell) with obfuscated or Base64 encoded flags to evade detection."
        )
        artifacts = [
            "Security Event Log Event 4688 (CommandLine & ParentProcessName)",
            "Sysmon Event ID 1 (Process Create with file hashes and parent lineage)",
            r"C:\Windows\Prefetch\*.pf",
            "AMCACHE.hve registry hive"
        ]
        investigation_steps = [
            "Inspect the full CommandLine argument for encoded parameters (-enc, -w hidden, download cradles).",
            "Validate whether the parent process is expected (e.g. Word or Excel spawning cmd/powershell is high risk).",
            "Check the binary signature and hash against VirusTotal or enterprise reputation databases."
        ]
        mitre_tech = mitre_tech or "T1059"
        mitre_tactic = mitre_tactic or "Execution"
        mitre_description = "Command and Scripting Interpreter: Process execution via shell or script engine."

    elif event_id in ("4104", "4103") or "powershell" in str(process).lower() or "powershell" in action.lower():
        event_name = "PowerShell ScriptBlock Execution (Event 4104/4103)"
        subsystem = "Microsoft-Windows-PowerShell Engine"
        summary = f"PowerShell engine compiled and executed script block code under user context '{user}'."
        technical_mechanics = (
            "Windows PowerShell Script Block Logging (Event 4104) captures the complete content of script blocks "
            "as they are executed, including code passed dynamically via Invoke-Expression, downloaded payloads, or deobfuscated strings."
        )
        threat_perspective = (
            "PowerShell is a primary adversary tool for memory-resident malware, credential dumping (Mimikatz), "
            "and lateral movement. Attackers use XOR encoding, character substitution, and AMSI bypasses to evade static detection."
        )
        artifacts = [
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
            r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "Antimalware Scan Interface (AMSI) telemetry buffer"
        ]
        investigation_steps = [
            "Review the full ScriptBlock text for known indicators (Net.WebClient, DownloadString, IEX, VirtualAlloc).",
            "Inspect the PSReadLine command history file for previous interactive commands run by the user.",
            "Verify whether AMSI was disabled or bypassed prior to execution."
        ]
        mitre_tech = mitre_tech or "T1059.001"
        mitre_tactic = mitre_tactic or "Execution"
        mitre_description = "Command and Scripting: PowerShell ScriptBlock compilation."

    elif event_id in ("1116", "1117") or "defender" in str(process).lower() or "malware" in str(detection_rule).lower():
        event_name = "Microsoft Defender Antivirus Detection (Event 1116/1117)"
        subsystem = "Windows Defender Antivirus Engine (MsMpEng.exe)"
        summary = "Windows Defender detected potentially malicious software or active malware behavior."
        technical_mechanics = (
            "The Defender real-time scanning engine matched an on-access file, memory buffer, or network packet "
            "against behavioral signatures or cloud heuristics. Event 1116 registers detection; Event 1117 registers the remediation action."
        )
        threat_perspective = (
            "Indicates active compromise attempt or weaponized file drop. Even if quarantined by Defender, "
            "investigators must verify if secondary droppers, persistence mechanisms, or credential dumps executed prior to detection."
        )
        artifacts = [
            r"C:\ProgramData\Microsoft\Windows Defender\Support",
            r"C:\ProgramData\Microsoft\Windows Defender\Quarantine",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows%20Defender%4Operational.evtx"
        ]
        investigation_steps = [
            "Identify the threat name, path, and hash of the flagged file.",
            "Check if Defender quarantined the file successfully (Event 1117 action status).",
            "Perform host-wide sweep for identical file hashes or lateral movement from the same source IP."
        ]
        mitre_tech = mitre_tech or "T1204"
        mitre_tactic = mitre_tactic or "Execution / Defense Evasion"
        mitre_description = "Malicious file execution intercepted by endpoint security controls."

    elif event_id in ("5156", "5157") or "firewall" in str(process).lower() or "firewall" in action.lower():
        event_name = "Windows Filtering Platform Network Audit (Event 5156/5157)"
        subsystem = "Windows Filtering Platform (WFP) / Windows Advanced Firewall"
        summary = f"Network packet connection was {'permitted' if event_id == '5156' else 'blocked'} by host firewall filters."
        technical_mechanics = (
            "The WFP kernel driver inspects inbound and outbound network flows at the socket layer, "
            "logging the application path, local IP/port, remote IP/port, protocol, and filter run-time ID."
        )
        threat_perspective = (
            "Inbound blocked connections identify external port scanning or vulnerability probes. "
            "Outbound allowed connections from unexpected binaries (e.g. notepad.exe or certutil.exe) signal C2 beaconing or exfiltration."
        )
        artifacts = [
            r"C:\Windows\System32\winevt\Logs\Security.evtx (Filtering Platform Connection events)",
            r"netsh advfirewall monitor logs",
            "Active socket connections (netstat -ano)"
        ]
        investigation_steps = [
            "Check the remote IP address and destination port against threat intelligence blacklists.",
            "Identify which local process initiated the socket connection via PID.",
            "Review firewall rules to ensure default-deny egress policies are intact."
        ]
        mitre_tech = mitre_tech or "T1071 / T1041"
        mitre_tactic = mitre_tactic or "Command and Control / Exfiltration"
        mitre_description = "Application layer network communication or firewall filter intervention."

    # Perform optional AI Deep Dive
    ai_explanation = None
    model_used = "rule-based"

    if use_ai:
        ai_key = api_key or os.getenv("GEMINI_API_KEY")
        if ai_key:
            ai_explanation = _call_gemini_single_event(event, ai_key)
            if ai_explanation:
                model_used = "gemini"

    return {
        "event_id": event_id or "N/A",
        "event_name": event_name,
        "subsystem": subsystem,
        "action": action,
        "timestamp": timestamp,
        "severity": severity,
        "is_suspicious": is_suspicious,
        "user": user,
        "process": process,
        "ip_address": ip,
        "detection_rule": detection_rule or "None (Routine Baseline)",
        "summary": summary,
        "technical_mechanics": technical_mechanics,
        "threat_perspective": threat_perspective,
        "mitre_details": {
            "technique": mitre_tech or "N/A",
            "tactic": mitre_tactic or "N/A",
            "description": mitre_description
        },
        "artifacts_to_check": artifacts,
        "investigation_steps": investigation_steps,
        "ai_explanation": ai_explanation,
        "model_used": model_used,
        "raw_log": raw_log
    }


def _call_gemini_single_event(event: Dict, api_key: str) -> Optional[str]:
    """Call Google Gemini to generate a dedicated forensic analysis of this single event."""
    try:
        from google import genai

        client = genai.Client(api_key=api_key)

        prompt = f"""
You are an elite Digital Forensics and Incident Response (DFIR) specialist and Senior SOC Analyst.
Analyze this single operating system log event in thorough technical detail:

[EVENT TELEMETRY METRICS]
- Timestamp: {event.get("timestamp")}
- Action / Event Class: {event.get("action")}
- Severity: {event.get("severity")}
- Is Suspicious Flag: {event.get("is_suspicious")}
- Security Context / User: {event.get("user")}
- Process / Binary: {event.get("process")}
- Network IP / Destination: {event.get("ip_address")}
- Detection Rule: {event.get("detection_rule")}
- MITRE Technique: {event.get("mitre_technique")}
- Raw Log Buffer: {event.get("raw_log")}

Please provide a structured, high-contrast, markdown-formatted forensic report covering:
1. ### 🔍 Executive Breakdown
   Explain in plain English exactly what happened on this computer.
2. ### ⚙️ Subsystem & OS Mechanics
   How Windows or the operating system generates this record, what kernel/service layer is responsible, and what internal state it reflects.
3. ### 🛡️ Threat & Adversary Tradecraft
   Is this normal baseline OS behavior or potential weaponization? How do attackers exploit, mimic, or evade around this event?
4. ### 📁 Key Forensic Artifacts to Inspect
   Specific directories, event log channels, registry keys, minidumps, or memory locations to verify on disk.
5. ### 🚨 SOC Incident Response Playbook
   Concrete, prioritized checklist of next actions for the security investigator.
"""

        models_to_try = [
            "gemini-3.5-flash-lite",
            "gemini-3.5-flash",
            "gemini-2.5-flash"
        ]

        for model in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config={
                        "temperature": 0.2,
                        "max_output_tokens": 1500
                    }
                )
                if response and response.text:
                    print(f"[INFO] Gemini single-event explanation received ({len(response.text)} chars via {model})")
                    return response.text
            except Exception as err:
                print(f"[WARN] Gemini model {model} attempt error: {err}")
                continue

    except Exception as e:
        print(f"[WARN] Gemini single event explanation error: {e}")

    return None
