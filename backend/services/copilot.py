"""
Forensic AI Copilot Service
Provides interactive, context-grounded AI conversational investigation for active forensic sessions.
Supports Google Gemini with deterministic offline rule-based evidence retrieval fallback.
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


def _retrieve_relevant_events(events: List[Dict], query: str, top_k: int = 15) -> List[Dict]:
    """
    RAG-style relevance scoring: rank events by matching keywords against
    action, user, ip, process, detection rule, MITRE, and raw log.
    """
    if not events:
        return []

    tokens = [t.lower() for t in re.findall(r"[A-Za-z0-9_\-\.:\\]+", query) if len(t) > 2]
    scored = []

    for idx, ev in enumerate(events):
        score = 0
        search_blob = " ".join([
            str(ev.get("action") or ""),
            str(ev.get("user") or ""),
            str(ev.get("ip_address") or ""),
            str(ev.get("process") or ""),
            str(ev.get("detection_rule") or ""),
            str(ev.get("mitre_technique") or ""),
            str(ev.get("raw_log") or "")[:400]
        ]).lower()

        for token in tokens:
            if token in search_blob:
                score += 3

        # Suspicious events get natural priority
        if ev.get("is_suspicious"):
            score += 4
        if ev.get("severity") == "critical":
            score += 5
        elif ev.get("severity") == "high":
            score += 3
        elif ev.get("severity") == "medium":
            score += 1

        scored.append((score, idx, ev))

    # Sort descending by score, tiebreak by original index
    scored.sort(key=lambda x: (x[0], -x[1]), reverse=True)
    
    # Return top_k unique events, ordered chronologically
    selected = [item[2] for item in scored[:top_k]]
    # Sort chronologically
    selected.sort(key=lambda x: str(x.get("timestamp") or ""))
    return selected


def _generate_suggested_followups(query: str, iocs: Dict[str, Any]) -> List[str]:
    """Generate smart contextual follow-up questions based on the query and evidence."""
    q_lower = query.lower()

    if any(k in q_lower for k in ("ioc", "indicator", "ip", "hash", "network")):
        return [
            "What external IP addresses received outbound connections?",
            "Draft a PowerShell script to block these malicious IPs in Windows Firewall",
            "Which user account initiated the network connections?"
        ]
    elif any(k in q_lower for k in ("initial access", "how", "vector", "start", "origin")):
        return [
            "What happened immediately after initial access was gained?",
            "Were any scheduled tasks or persistence registry keys created?",
            "What MITRE ATT&CK techniques were used during execution?"
        ]
    elif any(k in q_lower for k in ("powershell", "cmd", "process", "execution", "command")):
        return [
            "Did any process execute with elevated SYSTEM privileges?",
            "Were any obfuscated or base64-encoded commands detected?",
            "What processes spawned under svchost or explorer?"
        ]
    elif any(k in q_lower for k in ("contain", "remediat", "action", "playbook", "fix")):
        return [
            "Generate a one-click host isolation script for this incident",
            "What user accounts should be immediately locked or reset?",
            "Draft an executive CISO briefing for this incident"
        ]
    else:
        return [
            "Summarize the complete attack kill chain step-by-step",
            "Extract all Indicators of Compromise (IOCs) into a table",
            "What are the top 3 containment actions for this system?"
        ]


def _rule_based_copilot_answer(query: str, events: List[Dict], iocs: Dict[str, Any], session_info: Dict) -> str:
    """Intelligent offline fallback engine if Gemini API is unreachable or no key is present."""
    q_lower = query.lower()
    total = len(events)
    suspicious = [e for e in events if e.get("is_suspicious")]
    risk_score = session_info.get("risk_score", 0)
    risk_level = session_info.get("risk_level", "low")

    lines = []

    if any(k in q_lower for k in ("ioc", "indicator", "ip", "address", "hash")):
        lines.append("### 🔍 Forensic Indicator of Compromise (IOC) Analysis\n")
        lines.append(f"Scanned **{total}** events in the active session. Extracted the following evidence:\n")
        
        if iocs["ips"]:
            lines.append("#### 🌐 Malicious / External IP Addresses:")
            for ip in iocs["ips"]:
                lines.append(f"- ` {ip} ` (Correlated in log telemetry)")
        else:
            lines.append("- *No non-local external IP addresses identified in current log channels.*")

        if iocs["processes"]:
            lines.append("\n#### ⚙️ Suspicious & Active Binaries:")
            for p in iocs["processes"][:10]:
                lines.append(f"- ` {p} `")

        if iocs["mitre_techniques"]:
            lines.append("\n#### 🛡️ MITRE ATT&CK Techniques:")
            for m in iocs["mitre_techniques"]:
                lines.append(f"- **{m}**")

    elif any(k in q_lower for k in ("initial access", "how", "origin", "vector", "start")):
        lines.append("### 🚪 Initial Access & Attack Vector Breakdown\n")
        lines.append(f"**Session Risk Level:** `{risk_level.upper()}` ({risk_score}/100)\n")
        
        # Look for earliest suspicious event
        if suspicious:
            first_susp = suspicious[0]
            lines.append(f"**Earliest Detected Anomaly:**\n")
            lines.append(f"- **Timestamp:** `{first_susp.get('timestamp')}`")
            lines.append(f"- **Action:** `{first_susp.get('action')}`")
            lines.append(f"- **User:** `{first_susp.get('user') or 'SYSTEM'}`")
            lines.append(f"- **Detection Rule:** `{first_susp.get('detection_rule')}`")
            lines.append(f"- **Process:** `{first_susp.get('process') or 'N/A'}`\n")
            lines.append("The adversary or anomalous process initiated execution via this vector before advancing into subsequent kill-chain stages.")
        else:
            lines.append("All parsed events appear to reflect normal baseline system operations with no confirmed intrusion vector.")

    elif any(k in q_lower for k in ("remediat", "contain", "playbook", "script", "kill", "block")):
        lines.append("### 🛑 Recommended Incident Response & Containment Playbook\n")
        lines.append("Based on the analyzed event artifacts, execute the following containment measures:\n")
        lines.append("#### 1. Host Isolation & Firewall Blocking:")
        lines.append("```powershell\n# Windows Firewall - Block Observed Malicious Telemetry")
        for ip in iocs["ips"][:3]:
            lines.append(f'New-NetFirewallRule -DisplayName "SOC-BLOCK-{ip}" -Direction Outbound -RemoteAddress {ip} -Action Block')
        lines.append("```\n")
        lines.append("#### 2. Process Termination & Integrity Check:")
        if iocs["processes"]:
            lines.append("Inspect and terminate non-baseline instances of:")
            for p in iocs["processes"][:5]:
                lines.append(f"- `Stop-Process -Name '{p.replace('.exe','')}' -Force -ErrorAction SilentlyContinue`")
        lines.append("\n#### 3. Account Review:")
        for u in iocs["users"][:4]:
            lines.append(f"- Reset credentials and audit Kerberos TGTs for user: ` {u} `")

    else:
        lines.append("### 🛡️ AI Forensic Copilot Incident Brief\n")
        lines.append(f"- **Total Events Analyzed:** {total}")
        lines.append(f"- **Suspicious Indicators:** {len(suspicious)} events flagged")
        lines.append(f"- **Risk Assessment:** {risk_score}/100 ({risk_level.upper()})")
        lines.append(f"- **Active MITRE Techniques:** {len(iocs['mitre_techniques'])}")
        
        if suspicious:
            lines.append("\n#### Key Suspicious Highlights:")
            for idx, s in enumerate(suspicious[:6], 1):
                lines.append(f"{idx}. `[{s.get('timestamp')}]` **{s.get('action')}** | User: `{s.get('user') or 'N/A'}` | Rule: `{s.get('detection_rule')}`")
        lines.append("\n*Feel free to ask specific questions about user accounts, processes, IP connections, or containment steps.*")

    return "\n".join(lines)


def chat_with_evidence(
    session_id: str,
    message: str,
    history: Optional[List[Dict[str, str]]] = None,
    events: Optional[List[Dict]] = None,
    session_info: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Handle natural-language evidence queries with Google Gemini or offline fallback.
    Returns: { "reply": str, "model_used": str, "relevant_event_ids": List[int], "suggested_followups": List[str] }
    """
    events = events or []
    session_info = session_info or {}
    history = history or []

    iocs = _extract_ioc_inventory(events)
    relevant_events = _retrieve_relevant_events(events, message, top_k=16)
    suggested_followups = _generate_suggested_followups(message, iocs)

    # Format relevant events into context
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
            f"Snippet={str(e.get('raw_log') or '')[:180]}"
        )

    event_context_block = "\n".join(event_context_lines)

    # Build prompt
    system_instruction = (
        "You are the senior Autonomous AI Forensic Copilot and Incident Commander on an elite DFIR SOC team. "
        "You are analyzing live/ingested digital forensic telemetry for an active incident session. "
        "Answer the analyst's question accurately, concisely, and STRICTLY grounded in the provided log evidence. "
        "Rules:\n"
        "1. Cite specific Event #, timestamps, usernames, IP addresses, process names, and MITRE ATT&CK IDs.\n"
        "2. If the user asks for IOCs, summarize them in clean markdown tables or bulleted lists.\n"
        "3. If the user asks for remediation or containment, provide copy-pasteable PowerShell, Bash, or firewall commands.\n"
        "4. If certain information is absent from the evidence, state clearly that it was not observed in the ingested channels.\n"
        "5. Keep the tone professional, technical, authoritative, and direct."
    )

    prompt = f"""{system_instruction}

=== FORENSIC SESSION OVERVIEW ===
Session ID: {session_id}
Total Events Ingested: {len(events)}
Flagged Suspicious Events: {iocs['suspicious_count']}
Risk Score: {session_info.get('risk_score', 'N/A')}/100 ({session_info.get('risk_level', 'UNKNOWN')})
Identified External IPs: {', '.join(iocs['ips']) or 'None'}
Identified User Accounts: {', '.join(iocs['users']) or 'None'}
Active MITRE Techniques: {', '.join(iocs['mitre_techniques']) or 'None'}

=== MOST RELEVANT FORENSIC EVIDENCE FOR THIS QUERY ===
{event_context_block if event_context_block else "No direct event matches found for keyword search; evaluating overall session telemetry."}

=== CONVERSATION HISTORY ===
"""
    for h in history[-4:]:
        role = "Analyst" if h.get("role") == "user" else "AI Copilot"
        prompt += f"{role}: {h.get('content', '')}\n"

    prompt += f"\nAnalyst: {message}\nAI Copilot:"

    # Call Gemini
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)

            # Prioritize fast, high-rate models
            models = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-flash-latest", "gemini-flash-lite-latest"]
            for model_name in models:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config={
                            "temperature": 0.25,
                            "max_output_tokens": 1500,
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
