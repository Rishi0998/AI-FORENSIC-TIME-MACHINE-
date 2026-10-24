"""
Attack Chain Analyzer
Groups related suspicious events into attack phases and reconstructs
the kill chain sequence.
"""
from typing import List, Dict, Optional
from datetime import timedelta
from collections import defaultdict

# ── Kill chain phases in order ──────────────────────────────────────────────
KILL_CHAIN_PHASES = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact",
]

# Map actions/rules to kill chain phases
ACTION_TO_PHASE = {
    # Reconnaissance
    "port_scan":               "reconnaissance",
    "network_drop":            "reconnaissance",
    # Initial Access
    "ssh_failed_login":        "initial_access",
    "ssh_invalid_user":        "initial_access",
    "ssh_accepted_login":      "initial_access",
    "windows_logon_failure":   "initial_access",
    "windows_logon_success":   "initial_access",
    "external_login":          "initial_access",
    "brute_force":             "initial_access",
    "failed_login":            "initial_access",
    "multiple_login_sources":  "initial_access",
    # Execution
    "process_execution":       "execution",
    "sudo_command":            "execution",
    "suspicious_process":      "execution",
    "known_suspicious_binary": "execution",
    "windows_process_created": "execution",
    # Persistence
    "windows_user_created":    "persistence",
    "account_manipulation":    "persistence",
    "windows_group_member_added": "persistence",
    # Privilege Escalation
    "privilege_escalation":    "privilege_escalation",
    "su_attempt":              "privilege_escalation",
    "windows_privilege_assigned": "privilege_escalation",
    # Discovery
    "post_exploitation_recon": "discovery",
    # Exfiltration
    "outbound_connection":     "exfiltration",
    "outbound_external":       "exfiltration",
}

# Phase display names
PHASE_DISPLAY = {
    "reconnaissance":       "🔍 Reconnaissance",
    "initial_access":       "🚪 Initial Access",
    "execution":           "⚡ Execution",
    "persistence":         "🔒 Persistence",
    "privilege_escalation": "⬆️ Privilege Escalation",
    "defense_evasion":     "🛡️ Defense Evasion",
    "credential_access":   "🔑 Credential Access",
    "discovery":           "🔭 Discovery",
    "lateral_movement":    "↔️ Lateral Movement",
    "collection":          "📦 Collection",
    "exfiltration":        "📤 Exfiltration",
    "impact":              "💥 Impact",
}

# Phase descriptions for narrative generation
PHASE_DESCRIPTIONS = {
    "reconnaissance":       "scanning the network to discover available services and targets",
    "initial_access":       "attempting to gain initial foothold through login attempts",
    "execution":           "executing commands and running suspicious processes",
    "persistence":         "establishing persistence through account creation or modification",
    "privilege_escalation": "escalating privileges to gain higher access levels",
    "defense_evasion":     "attempting to evade security controls and detection",
    "credential_access":   "harvesting credentials for further access",
    "discovery":           "discovering system information and network topology",
    "lateral_movement":    "moving laterally across the network to other systems",
    "collection":          "collecting and staging data for exfiltration",
    "exfiltration":        "exfiltrating data to external locations",
    "impact":              "causing damage or disruption to systems",
}


def build_attack_chains(events: List[Dict]) -> List[Dict]:
    """
    Group related events into attack chain phases.
    Returns a list of chain objects ordered by the kill chain.
    """
    # Group events by phase
    phase_events = defaultdict(list)

    for i, event in enumerate(events):
        if not event.get("is_suspicious"):
            continue

        # Determine phase from action or detection rule
        action = event.get("action", "")
        rule = event.get("detection_rule", "")

        phase = ACTION_TO_PHASE.get(rule) or ACTION_TO_PHASE.get(action) or "execution"
        phase_events[phase].append({
            "event_index": i,
            "event": event,
        })

    # Build chain objects in kill chain order
    chains = []
    order = 0

    for phase in KILL_CHAIN_PHASES:
        if phase not in phase_events:
            continue

        phase_data = phase_events[phase]
        event_indices = [pe["event_index"] for pe in phase_data]
        phase_event_list = [pe["event"] for pe in phase_data]

        # Calculate phase severity
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_severity = max(
            (e.get("severity", "low") for e in phase_event_list),
            key=lambda s: severity_order.get(s, 0)
        )

        # Generate description
        desc = _generate_phase_description(phase, phase_event_list)

        # Get MITRE tactic
        tactics = set(e.get("mitre_tactic") for e in phase_event_list if e.get("mitre_tactic"))

        chains.append({
            "chain_name": PHASE_DISPLAY.get(phase, phase),
            "phase": phase,
            "event_ids": event_indices,
            "event_count": len(event_indices),
            "description": desc,
            "severity": max_severity,
            "mitre_tactic": ", ".join(tactics) if tactics else None,
            "order_index": order,
            "time_range": {
                "start": min(e["timestamp"].isoformat() if hasattr(e["timestamp"], "isoformat") else str(e["timestamp"]) for e in phase_event_list),
                "end": max(e["timestamp"].isoformat() if hasattr(e["timestamp"], "isoformat") else str(e["timestamp"]) for e in phase_event_list),
            },
            "key_indicators": _extract_indicators(phase_event_list),
        })
        order += 1

    return chains


def _generate_phase_description(phase: str, events: List[Dict]) -> str:
    """Generate human-readable description for a phase."""
    action_counts = defaultdict(int)
    unique_ips = set()
    unique_users = set()

    for e in events:
        action_counts[e.get("action", "unknown")] += 1
        if e.get("ip_address"):
            unique_ips.add(e["ip_address"])
        if e.get("user"):
            unique_users.add(e["user"])

    base_desc = PHASE_DESCRIPTIONS.get(phase, "performing unknown activity")
    parts = [f"Attacker detected {base_desc}."]

    if unique_ips:
        parts.append(f"Source IPs: {', '.join(list(unique_ips)[:5])}")
    if unique_users:
        parts.append(f"Target accounts: {', '.join(list(unique_users)[:5])}")

    for action, count in action_counts.items():
        parts.append(f"  - {action}: {count} event(s)")

    return " ".join(parts)


def _extract_indicators(events: List[Dict]) -> Dict:
    """Extract key indicators of compromise from phase events."""
    ips = set()
    users = set()
    processes = set()

    for e in events:
        if e.get("ip_address"):
            ips.add(e["ip_address"])
        if e.get("user"):
            users.add(e["user"])
        if e.get("process"):
            processes.add(e["process"])

    return {
        "ips": list(ips),
        "users": list(users),
        "processes": list(processes)[:10],
    }


def get_attack_narrative(chains: List[Dict]) -> str:
    """
    Build a plain-English narrative of the entire attack from the chain phases.
    """
    if not chains:
        return "No suspicious activity detected in the provided logs."

    narrative_parts = []
    narrative_parts.append("## Attack Narrative\n")

    for i, chain in enumerate(chains):
        phase_name = chain["chain_name"]
        desc = chain["description"]
        severity = chain["severity"].upper()
        time_range = chain.get("time_range", {})
        indicators = chain.get("key_indicators", {})

        narrative_parts.append(f"### Step {i+1}: {phase_name}")
        narrative_parts.append(f"**Severity:** {severity}")
        if time_range:
            narrative_parts.append(f"**Time:** {time_range.get('start', '?')} → {time_range.get('end', '?')}")
        narrative_parts.append(f"\n{desc}\n")

    # Summary
    total_events = sum(c["event_count"] for c in chains)
    phases_hit = [c["phase"] for c in chains]
    max_sev = max((c["severity"] for c in chains),
                  key=lambda s: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0))

    narrative_parts.append("### Summary")
    narrative_parts.append(
        f"This attack involved **{total_events} suspicious events** across "
        f"**{len(chains)} kill chain phases**: {', '.join(phases_hit)}. "
        f"Maximum severity: **{max_sev.upper()}**."
    )

    return "\n".join(narrative_parts)
