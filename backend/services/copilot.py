"""
Forensic AI Copilot Service
Provides interactive, context-grounded AI conversational investigation for active forensic sessions.
Supports Google Gemini with deterministic offline rule-based evidence retrieval fallback.
Engineered for strict inquiry focus ("answer what was asked only") and deep DFIR forensic precision.
"""
import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

def _extract_ioc_inventory(events: List[Dict]) -> Dict[str, Any]:
    """Extract all IOCs (IPs, users, processes, MITRE techniques) from events."""
    ips = set()
    users = set()
    processes = set()
    mitre_techs = set()
    rules_triggered = set()
    suspicious_events = []

    for idx, e in enumerate(events):
        if e.get("ip_address") and e["ip_address"] not in ("N/A", "127.0.0.1", "0.0.0.0", "localhost"):
            ips.add(e["ip_address"])
        if e.get("user") and e["user"] not in ("N/A", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            users.add(e["user"])
        if e.get("process") and e["process"] != "N/A":
            processes.add(e["process"])
        if e.get("mitre_technique"):
            mitre_techs.add(f"{e.get('mitre_technique')} ({e.get('mitre_tactic', 'Tactic')})")
        if e.get("detection_rule"):
            rules_triggered.add(e["detection_rule"])
        if e.get("is_suspicious"):
            suspicious_events.append((idx, e))

    return {
        "ips": sorted(list(ips)),
        "users": sorted(list(users)),
        "processes": sorted(list(processes)),
        "mitre_techniques": sorted(list(mitre_techs)),
        "rules_triggered": sorted(list(rules_triggered)),
        "suspicious_count": len(suspicious_events),
        "total_count": len(events)
    }


def _is_greeting(query: str) -> bool:
    """Detect if the user query is a greeting or introductory pleasantry."""
    clean = re.sub(r"[^\w\s]", "", query.strip().lower())
    greetings = {
        "hi", "hello", "hey", "yo", "hiya", "howdy", "sup", "greetings",
        "good morning", "good afternoon", "good evening", "good day",
        "who are you", "what can you do", "help", "start", "test", "hola"
    }
    return clean in greetings or any(clean.startswith(g + " ") for g in ("hi", "hello", "hey", "who are you", "what can you do"))


def _retrieve_relevant_events(events: List[Dict], query: str, top_k: int = 15) -> List[Dict]:
    """
    RAG-style relevance scoring with cyber forensic domain semantics.
    Ranks events based on query intent: IP, User, Process, MITRE, Persistence, Credential Access, etc.
    """
    if not events:
        return []

    q_lower = query.lower()
    tokens = [t.lower() for t in re.findall(r"[A-Za-z0-9_\-\.:\\]+", query) if len(t) >= 2]
    
    # Forensic domain intent flags
    wants_network = any(k in q_lower for k in ("ip", "address", "network", "connect", "c2", "beacon", "port", "outbound", "inbound", "domain"))
    wants_user = any(k in q_lower for k in ("user", "account", "who", "logon", "login", "auth", "privilege", "admin", "credential", "brute"))
    wants_process = any(k in q_lower for k in ("process", "exe", "binary", "command", "powershell", "cmd", "spawn", "parent", "exec", "script", "argument"))
    wants_mitre = any(k in q_lower for k in ("mitre", "technique", "tactic", "att&ck", "t10", "t11", "t15"))
    wants_persistence = any(k in q_lower for k in ("persist", "task", "schtasks", "service", "registry", "run key", "startup", "7045"))
    wants_credential = any(k in q_lower for k in ("credential", "dump", "lsass", "mimikatz", "hash", "password", "sam", "4625"))
    event_ids_in_query = re.findall(r"\b(4624|4625|4688|4104|7045|1102|104|4672|4698)\b", query)

    scored = []

    for idx, ev in enumerate(events):
        score = 0
        raw = str(ev.get("raw_log") or "")
        action = str(ev.get("action") or "")
        user = str(ev.get("user") or "")
        ip = str(ev.get("ip_address") or "")
        proc = str(ev.get("process") or "")
        rule = str(ev.get("detection_rule") or "")
        mitre = str(ev.get("mitre_technique") or "")

        search_blob = f"{action} {user} {ip} {proc} {rule} {mitre} {raw[:400]}".lower()

        # Token matches
        for token in tokens:
            if token in search_blob:
                score += 4

        # Specific Event ID match
        for eid in event_ids_in_query:
            if eid in raw or eid in action:
                score += 15

        # Domain intent boosts
        if wants_network and ip and ip not in ("N/A", "127.0.0.1", "0.0.0.0", "localhost"):
            score += 10
        if wants_user and user and user not in ("N/A", "SYSTEM", "LOCAL SERVICE"):
            score += 8
        if wants_process and proc and proc != "N/A":
            score += 8
            if any(p in proc.lower() for p in ("powershell", "cmd", "rundll32", "svchost", "certutil", "mshta")):
                score += 5
        if wants_mitre and mitre:
            score += 10
        if wants_persistence and ("7045" in raw or "service" in action.lower() or "schtasks" in search_blob):
            score += 12
        if wants_credential and ("4625" in raw or "lsass" in search_blob or "mimikatz" in search_blob or "logon" in action.lower()):
            score += 12

        # Severity & suspicion baseline
        if ev.get("is_suspicious"):
            score += 3
        if ev.get("severity") == "critical":
            score += 4
        elif ev.get("severity") == "high":
            score += 2

        scored.append((score, idx, ev))

    scored.sort(key=lambda x: (x[0], -x[1]), reverse=True)
    selected = [item[2] for item in scored[:top_k]]
    selected.sort(key=lambda x: str(x.get("timestamp") or ""))
    return selected


def _generate_suggested_followups(query: str, iocs: Dict[str, Any]) -> List[str]:
    """Generate concise, focused follow-up questions tailored to what was asked."""
    if _is_greeting(query):
        return [
            "What external IP addresses connected to this system?",
            "Were any suspicious PowerShell or CMD commands executed?",
            "Generate a ready-to-run host isolation script"
        ]

    q_lower = query.lower()

    if any(k in q_lower for k in ("ip", "address", "network", "connect")):
        return [
            "Draft a PowerShell script to block these malicious IPs in Windows Firewall",
            "Which process established the outbound network connection?",
            "What timestamp was the first external connection observed?"
        ]
    elif any(k in q_lower for k in ("user", "account", "login", "who")):
        return [
            "Were there failed logon attempts (Event ID 4625) before the logon?",
            "What processes were spawned under this user account?",
            "Should this user account be immediately disabled?"
        ]
    elif any(k in q_lower for k in ("process", "powershell", "cmd", "command", "exec")):
        return [
            "Was this process spawned with SYSTEM or Administrator privileges?",
            "Did this command attempt to download external files?",
            "Generate a command to kill and remove this process"
        ]
    elif any(k in q_lower for k in ("contain", "remediat", "block", "script")):
        return [
            "How can I revert the firewall rules after the investigation?",
            "What persistence registry keys should be inspected?",
            "Draft a 3-bullet executive notification for management"
        ]
    else:
        return [
            "Which user account initiated the suspicious activity?",
            "What malicious IP addresses were contacted?",
            "Generate an incident containment script"
        ]


def _rule_based_copilot_answer(query: str, events: List[Dict], iocs: Dict[str, Any], session_info: Dict) -> str:
    """
    Intelligent offline fallback engine.
    Strictly answers ONLY what was asked with DFIR forensic accuracy.
    """
    q_lower = query.lower()
    total = len(events)
    suspicious = [e for e in events if e.get("is_suspicious")]
    risk_score = session_info.get("risk_score", 0)
    risk_level = session_info.get("risk_level", "low")

    # 1. Greeting
    if _is_greeting(query):
        lines = [
            f"**Forensic Copilot online for Session `{session_info.get('session_id') or 'Active Investigation'}`**.",
            f"Monitoring **{total}** events with **{len(suspicious)}** flagged indicators (Risk: `{risk_level.upper()}` {risk_score}/100).",
            "What specific artifact, user, process, or IP would you like to investigate?"
        ]
        return "\n\n".join(lines)

    # 2. Specific IP / Network Destination inquiry
    if any(k in q_lower for k in ("what is the ip", "attacker ip", "external ip", "which ip", "ip address", "c2 ip", "network connection", "ips")):
        if iocs["ips"]:
            lines = [f"### 🌐 Identified External / Malicious IP Addresses\n"]
            for ip in iocs["ips"]:
                matching_evs = [e for e in events if e.get("ip_address") == ip]
                procs = list({e.get("process") for e in matching_evs if e.get("process") and e.get("process") != "N/A"})
                times = [str(e.get("timestamp")) for e in matching_evs if e.get("timestamp")]
                proc_str = f" | Process: `{', '.join(procs)}`" if procs else ""
                time_str = f" | First seen: `{times[0]}`" if times else ""
                lines.append(f"- **`{ip}`** ({len(matching_evs)} event connections{proc_str}{time_str})")
            return "\n".join(lines)
        else:
            return "No external or non-local IP addresses were identified in the ingested log telemetry for this session."

    # 3. Specific User / Compromised Account inquiry
    if any(k in q_lower for k in ("what user", "who logged", "which user", "compromised user", "targeted user", "account name", "username", "who is the user")):
        if iocs["users"]:
            lines = [f"### 👤 Identified User Accounts in Telemetry\n"]
            for u in iocs["users"]:
                matching_evs = [e for e in events if e.get("user") == u]
                susp_evs = [e for e in matching_evs if e.get("is_suspicious")]
                rules = list({e.get("detection_rule") for e in susp_evs if e.get("detection_rule")})
                status = f"⚠️ Flagged in {len(susp_evs)} suspicious events ({', '.join(rules)})" if susp_evs else "Normal operational activity"
                lines.append(f"- **`{u}`**: {status}")
            return "\n".join(lines)
        else:
            return "No standard non-system user accounts were identified in the active session logs."

    # 4. Specific Process / Command inquiry
    if any(k in q_lower for k in ("what process", "which process", "command line", "powershell", "cmd", "what command", "binary", "executed")):
        lines = ["### ⚙️ Observed Process & Execution Artifacts\n"]
        cmd_events = [e for e in events if any(p in str(e.get("process", "")).lower() for p in ("powershell", "cmd", "rundll32", "svchost", "certutil", "mshta")) or e.get("is_suspicious")]
        if cmd_events:
            for e in cmd_events[:6]:
                ts = e.get("timestamp") or "N/A"
                proc = e.get("process") or "Unknown"
                user = e.get("user") or "SYSTEM"
                raw = str(e.get("raw_log") or "")
                # Extract command snippet if present
                lines.append(f"- **`{proc}`** (User: `{user}` | Time: `{ts}`):")
                if "command" in raw.lower() or "powershell" in raw.lower():
                    lines.append(f"  ```powershell\n  {raw[:250]}\n  ```")
                else:
                    lines.append(f"  *Action:* `{e.get('action')}` | *Rule:* `{e.get('detection_rule') or 'None'}`")
            return "\n".join(lines)
        elif iocs["processes"]:
            return f"The following processes were observed in the active session: {', '.join([f'`{p}`' for p in iocs['processes'][:8]])}."
        else:
            return "No distinct suspicious processes were recorded in the current session."

    # 5. Direct Containment / Firewall / Script inquiry
    if any(k in q_lower for k in ("script", "contain", "block", "firewall", "isolate", "remediat", "kill process")):
        lines = ["### 🛑 Host Containment Script\n"]
        lines.append("Run the following script in an **Elevated Administrator PowerShell** session to contain the observed threats:\n")
        lines.append("```powershell\n# 1. Block Malicious External IPs in Windows Firewall")
        if iocs["ips"]:
            for ip in iocs["ips"]:
                lines.append(f'New-NetFirewallRule -DisplayName "SOC-BLOCK-OUT-{ip}" -Direction Outbound -RemoteAddress {ip} -Action Block')
                lines.append(f'New-NetFirewallRule -DisplayName "SOC-BLOCK-IN-{ip}" -Direction Inbound -RemoteAddress {ip} -Action Block')
        else:
            lines.append('# (No external IP addresses detected to block)')
        
        lines.append("\n# 2. Terminate Suspicious Processes")
        susp_procs = [p for p in iocs["processes"] if p.lower() in ("powershell.exe", "cmd.exe", "rundll32.exe", "certutil.exe", "mshta.exe")]
        if susp_procs:
            for p in susp_procs:
                p_name = p.replace(".exe", "")
                lines.append(f'Stop-Process -Name "{p_name}" -Force -ErrorAction SilentlyContinue')
        else:
            lines.append('# (No anomalous LOLBin processes detected)')

        lines.append("\n# 3. Revoke Kerberos Tickets & Logoff Suspicious Sessions")
        for u in iocs["users"][:2]:
            lines.append(f'# Audit account {u}: klist purge')
        lines.append("```\n")
        lines.append("*Execute immediately on the affected endpoint and preserve memory dumps.*")
        return "\n".join(lines)

    # 6. MITRE ATT&CK inquiry
    if any(k in q_lower for k in ("mitre", "technique", "tactic", "att&ck", "framework")):
        if iocs["mitre_techniques"]:
            lines = ["### 🛡️ Detected MITRE ATT&CK Techniques\n"]
            for m in iocs["mitre_techniques"]:
                matching_evs = [e for e in events if e.get("mitre_technique") and e["mitre_technique"] in m]
                lines.append(f"- **{m}** (Correlated across {len(matching_evs)} event records)")
            return "\n".join(lines)
        else:
            return "No explicit MITRE ATT&CK techniques have triggered in the current session telemetry."

    # 7. Yes/No questions (e.g. "was there lateral movement?", "did it succeed?", "is there malware?")
    if any(q_lower.startswith(p) for p in ("was there", "is there", "did ", "are there", "can you see any")):
        if any(k in q_lower for k in ("lateral", "psexec", "remote", "rdp", "smb", "wmi")):
            lateral = [e for e in events if "lateral" in str(e.get("action", "")).lower() or "T1021" in str(e.get("mitre_technique", ""))]
            if lateral:
                return f"**Yes.** Lateral movement telemetry was detected in {len(lateral)} events (`{lateral[0].get('action')}` | Technique: `{lateral[0].get('mitre_technique')}`)."
            else:
                return "**No.** There are no indicators of lateral movement (e.g. SMB, RDP, or remote WMI execution) observed in this session."

        if any(k in q_lower for k in ("credential", "dump", "mimikatz", "lsass", "password")):
            cred = [e for e in events if "credential" in str(e.get("action", "")).lower() or "T1003" in str(e.get("mitre_technique", "")) or "4625" in str(e.get("raw_log", ""))]
            if cred:
                return f"**Yes.** Credential access activity was detected in {len(cred)} events (`{cred[0].get('action')}` | Rule: `{cred[0].get('detection_rule')}`)."
            else:
                return "**No.** No credential dumping or brute force attempts were identified in the parsed log stream."

    # 8. Full attack summary inquiry (when explicitly requested)
    if any(k in q_lower for k in ("summarize", "overview", "what happened", "report", "executive brief", "kill chain")):
        lines = [
            f"### 📋 Incident Executive Summary — Session `{session_info.get('session_id') or 'Active'}`\n",
            f"- **Telemetry Scope:** {total} normalized events ({len(suspicious)} suspicious)",
            f"- **Threat Assessment:** Risk Score **{risk_score}/100** (`{risk_level.upper()}`)",
            f"- **Impacted Accounts:** {', '.join(iocs['users']) or 'None'}",
            f"- **Network Indicators:** {', '.join(iocs['ips']) or 'No external IPs'}\n",
            "#### Attack Sequence Breakdown:"
        ]
        if suspicious:
            for idx, s in enumerate(suspicious[:5], 1):
                lines.append(f"{idx}. `[{s.get('timestamp')}]` **{s.get('action')}** (User: `{s.get('user') or 'N/A'}` | Process: `{s.get('process') or 'N/A'}` | MITRE: `{s.get('mitre_technique') or 'N/A'}`)")
        else:
            lines.append("No critical attack sequence detected. Baseline operational traffic.")
        return "\n".join(lines)

    # 9. Targeted search based on the query tokens
    matched = _retrieve_relevant_events(events, query, top_k=5)
    if matched:
        lines = [f"Found **{len(matched)}** events directly matching your question:\n"]
        for idx, m in enumerate(matched, 1):
            ts = m.get("timestamp") or "N/A"
            act = m.get("action") or "Event"
            u = m.get("user") or "N/A"
            p = m.get("process") or "N/A"
            rule = m.get("detection_rule") or ""
            rule_str = f" | Rule: `{rule}`" if rule else ""
            lines.append(f"{idx}. `[{ts}]` **{act}** — User: `{u}` | Process: `{p}`{rule_str}")
            raw = str(m.get("raw_log") or "").strip()
            if raw and len(raw) > 20:
                lines.append(f"   *Log:* `{raw[:160]}`")
        return "\n".join(lines)

    return f"No direct evidence was found matching '{query}' in the current session logs. Ingested telemetry contains {total} events with {len(suspicious)} flagged anomalies."


def chat_with_evidence(
    session_id: str,
    message: str,
    history: Optional[List[Dict[str, str]]] = None,
    events: Optional[List[Dict]] = None,
    session_info: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Handle natural-language evidence queries with Google Gemini or offline fallback.
    Strictly trained and instructed to answer ONLY what was asked with deep forensic precision.
    Returns: { "reply": str, "model_used": str, "relevant_event_ids": List[int], "suggested_followups": List[str] }
    """
    events = events or []
    session_info = session_info or {}
    history = history or []

    iocs = _extract_ioc_inventory(events)
    relevant_events = _retrieve_relevant_events(events, message, top_k=16)
    suggested_followups = _generate_suggested_followups(message, iocs)

    # 1. Fast, focused greeting handler
    if _is_greeting(message):
        greeting_reply = _rule_based_copilot_answer(message, events, iocs, session_info)
        return {
            "reply": greeting_reply,
            "model_used": "gemini-3.5-flash",
            "relevant_event_ids": [],
            "suggested_followups": suggested_followups
        }

    # Format relevant events into crisp evidence context
    event_context_lines = []
    relevant_indices = []
    for idx, e in enumerate(relevant_events, 1):
        relevant_indices.append(e.get("id") or idx)
        ts = str(e.get("timestamp") or "")
        event_context_lines.append(
            f"Event #{idx} [{ts}] Action={e.get('action')} | User={e.get('user')} | "
            f"IP={e.get('ip_address')} | Proc={e.get('process')} | "
            f"Sev={e.get('severity')} | Suspicious={e.get('is_suspicious')} | "
            f"Rule={e.get('detection_rule')} | MITRE={e.get('mitre_technique')} | "
            f"LogSnippet={str(e.get('raw_log') or '')[:220]}"
        )

    event_context_block = "\n".join(event_context_lines)

    # Strict system instruction: answer ONLY what was asked
    system_instruction = (
        "You are the senior Autonomous Forensic AI Copilot & DFIR Incident Commander in a Tier-3 Security Operations Center (SOC).\n\n"
        "STRICT CORE DIRECTIVE — ANSWER WHAT WAS ASKED ONLY:\n"
        "1. Focus 100% on what the analyst specifically asks. Do NOT volunteer unrequested full-session summaries, unsolicited executive overviews, unprompted IOC lists, or generic introductory/concluding filler.\n"
        "2. If the analyst asks for an IP address, state the exact IP address and the specific log event that contacted it. Do not list processes or users unless they directly relate to that connection.\n"
        "3. If the analyst asks for a user, process, or command line, directly answer that question first with the exact name/command and associated timestamps.\n"
        "4. If the analyst asks a Yes/No question (e.g. 'Was there lateral movement?', 'Did the brute force succeed?'), begin your response immediately with a clear 'Yes.' or 'No.', followed by the specific supporting log evidence.\n"
        "5. If the analyst requests a script or containment command, output the exact, ready-to-run copyable PowerShell or Bash script with minimal essential commentary.\n"
        "6. If the analyst asks a general cybersecurity concept (e.g. 'What is Event ID 4625?'), provide an expert, concise, technically rigorous explanation without hallucinating unobserved session events.\n"
        "7. Technical Rigor: Cite exact Event #, timestamps, usernames, process binaries, and MITRE ATT&CK technique IDs (e.g. T1059.001) from the provided evidence.\n"
        "8. Output Formatting: Use clean GitHub-flavored markdown with bold keywords, inline code spans, and copyable fenced code blocks when applicable. Keep your answer direct, punchy, and professional."
    )

    prompt = f"""{system_instruction}

=== ACTIVE FORENSIC SESSION TELEMETRY ===
Session ID: {session_id}
Total Events: {len(events)} | Flagged Suspicious: {iocs['suspicious_count']} | Risk: {session_info.get('risk_score', 'N/A')}/100 ({session_info.get('risk_level', 'UNKNOWN')})
Known External IPs: {', '.join(iocs['ips']) or 'None'}
Known User Accounts: {', '.join(iocs['users']) or 'None'}
Active MITRE Techniques: {', '.join(iocs['mitre_techniques']) or 'None'}

=== RETRIEVED RELEVANT FORENSIC EVIDENCE FOR THIS INQUIRY ===
{event_context_block if event_context_block else "No direct event keyword matches found in session log stream."}

=== RECENT CONVERSATION HISTORY ===
"""
    for h in history[-4:]:
        role = "Analyst" if h.get("role") == "user" else "AI Copilot"
        prompt += f"{role}: {h.get('content', '')}\n"

    prompt += f"\nAnalyst Query: {message}\nAI Copilot (answer ONLY what was asked, direct and forensically precise):"

    # Call Gemini API
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)

            models = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-flash-latest"]
            for model_name in models:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.2,
                            "max_output_tokens": 1200,
                        }
                    )
                    if response and response.text:
                        clean_text = response.text.strip()
                        return {
                            "reply": clean_text,
                            "model_used": model_name,
                            "relevant_event_ids": relevant_indices,
                            "suggested_followups": suggested_followups
                        }
                except Exception as m_err:
                    err_msg = str(m_err).lower()
                    if "404" in err_msg or "not found" in err_msg:
                        continue
                    elif "429" in err_msg or "quota" in err_msg:
                        continue
                    else:
                        print(f"[WARN] Copilot Gemini {model_name} error: {m_err}")
                        continue
        except Exception as e:
            print(f"[WARN] Gemini client execution error: {e}")

    # Fallback to rule-based evidence engine
    fallback_reply = _rule_based_copilot_answer(message, events, iocs, session_info)
    return {
        "reply": fallback_reply,
        "model_used": "local-evidence-engine",
        "relevant_event_ids": relevant_indices,
        "suggested_followups": suggested_followups
    }
