"""
Cyber Threat Topological Attack Graph Generator
Uses NetworkX to build a multi-layered, directed cyber attack graph.
Correlates entities (Adversaries, Hosts, System Principals, IPs, Binaries/Processes)
with threat levels, blast radius, MITRE techniques, and flow directions.
Eliminates orphan nodes by systematically anchoring system processes to the host core.
"""
import networkx as nx
from typing import List, Dict, Optional
from collections import defaultdict


NODE_COLORS = {
    "host":       "#a855f7",   # Quantum Purple / Target Host Core
    "system":     "#6366f1",   # Neon Indigo / Kernel Security Principal
    "adversary":  "#ff0055",   # Flaming Crimson / External Attacker
    "user":       "#0284c7",   # Sky Cyan / Authenticated User
    "ip":         "#00f2fe",   # Electric Cyan / Network Endpoint
    "process":    "#05ffa1",   # Cyber Emerald / Benign Process
    "malware":    "#ff0055",   # Crimson / Malicious Binary
    "service":    "#f59e0b",   # Amber / System Service & Channel
}

NODE_SHAPES = {
    "host":       "hexagon",
    "system":     "barrel",
    "adversary":  "diamond",
    "user":       "round-diamond",
    "ip":         "ellipse",
    "process":    "round-rectangle",
    "malware":    "round-rectangle",
    "service":    "round-octagon",
}

NODE_ICONS = {
    "host":       "🖥️",
    "system":     "🛡️",
    "adversary":  "💀",
    "user":       "👤",
    "ip":         "🌐",
    "process":    "⚡",
    "malware":    "☣️",
    "service":    "⚙️",
}

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high":     25,
    "medium":   10,
    "low":      3,
    "info":     1,
}

SEVERITY_COLORS = {
    "critical": "#ff0055",
    "high":     "#ff5500",
    "medium":   "#eab308",
    "low":      "#06b6d4",
    "info":     "#64748b",
}

INVALID_ENTITIES = {
    "n/a", "none", "null", "-", "--", "unknown", "", "undefined", "nil", "n/d"
}

SYSTEM_USERS = {
    "system", "localsystem", "nt authority\\system",
    "nt authority\\local service", "nt authority\\network service", "root"
}

PROCESS_NORMALIZATION = {
    "schannel": ("Schannel [TLS Engine]", "service", "Cryptography & TLS Security Provider"),
    "windows error reporting": ("WER [Diagnostics]", "service", "Crash & Telemetry Subsystem"),
    "microsoft-windows-security-spp": ("Security-SPP [Licensing]", "service", "Platform Integrity Verification"),
    "edgeupdate": ("EdgeUpdate [Maintenance]", "service", "Scheduled Browser Maintenance Service"),
    "microsoft-windows-distributedcom": ("DCOM [RPC Subsystem]", "service", "Distributed Component Object Model Bus"),
    "microsoft-windows-powershell": ("PowerShell [Engine]", "process", "PowerShell Scripting Host"),
    "microsoft-windows-powershell/operational": ("PowerShell [Operational]", "service", "PowerShell Audit Log Channel"),
    "microsoft-windows-appmodel-state": ("AppModel [Runtime]", "service", "Windows AppModel State Service"),
    "microsoft-windows-appmodel": ("AppModel [Subsystem]", "service", "Windows Application Model Subsystem"),
    "netwtw14": ("Intel Wi-Fi [Driver]", "service", "Network Interface Adapter Driver"),
    "netwtw10": ("Intel Wi-Fi [Driver]", "service", "Network Interface Adapter Driver"),
    "powershell": ("PowerShell [Interpreter]", "process", "Dynamic Scripting Host"),
    "powershell.exe": ("PowerShell [Interpreter]", "process", "Dynamic Scripting Host"),
    "cmd": ("CMD [Command Shell]", "process", "Interactive Command Processor"),
    "cmd.exe": ("CMD [Command Shell]", "process", "Interactive Command Processor"),
    "svchost": ("svchost [Service Host]", "process", "Windows Shared Service Host"),
    "svchost.exe": ("svchost [Service Host]", "process", "Windows Shared Service Host"),
    "lsass": ("LSASS [Security Authority]", "process", "Local Security Authority Subsystem"),
    "lsass.exe": ("LSASS [Security Authority]", "process", "Local Security Authority Subsystem"),
    "explorer": ("Explorer [Desktop Shell]", "process", "User Desktop Shell Process"),
    "explorer.exe": ("Explorer [Desktop Shell]", "process", "User Desktop Shell Process"),
    "taskhostw": ("TaskHost [Worker Host]", "process", "Windows Task Host Worker"),
    "services": ("Services [SCM]", "process", "Service Control Manager"),
    "services.exe": ("Services [SCM]", "process", "Service Control Manager"),
    "csrss": ("CSRSS [Subsystem]", "process", "Client/Server Runtime Subsystem"),
    "smss": ("SMSS [Session Manager]", "process", "Session Management Subsystem"),
}

ACTION_MAPPINGS = {
    "windows_system_event": "System IPC",
    "windows_application_event": "App Telemetry",
    "windows_powershell/operational_event": "PowerShell Script",
    "powershell_execution": "Script Exec",
    "host_spawn": "Kernel Dispatch",
    "core_privilege": "Security Token",
    "logon_session": "User Session",
    "inbound_traffic": "Inbound Handshake",
    "failed_login": "Auth Failure",
    "sudo_execution": "Privilege Escalation",
    "connection_attempt": "TCP Handshake",
    "brute_force_ssh": "SSH Attack Vector",
    "malicious_command": "Exploit Injection",
}


def clean_entity(val: Optional[str]) -> Optional[str]:
    """Clean and validate entity string."""
    if not val:
        return None
    val = str(val).strip()
    if val.lower() in INVALID_ENTITIES:
        return None
    return val


def format_action_label(raw_action: str) -> str:
    """Format action string into a readable cyber tactical label."""
    if not raw_action:
        return "Interaction"
    clean = raw_action.lower().strip()
    if clean in ACTION_MAPPINGS:
        return ACTION_MAPPINGS[clean]
    return clean.replace("_", " ").replace("/", " ").title()


def build_attack_graph(events: List[Dict]) -> Dict:
    """
    Build a rich, connected, directed attack graph from security events.
    Returns Cytoscape.js-compatible JSON format with full topological telemetry.
    Ensures ZERO orphan nodes.
    """
    G = nx.DiGraph()

    if not events:
        return {"elements": {"nodes": [], "edges": []}, "metrics": {}}

    # ── 1. Anchor Primary Host Node ─────────────────────────────────────────
    primary_host_name = "WIN-ENDPOINT"
    for e in events:
        raw_h = clean_entity(e.get("host"))
        if raw_h and raw_h.lower() not in ("localhost", "127.0.0.1"):
            primary_host_name = raw_h.upper()
            break

    host_id = "host_root"
    G.add_node(
        host_id,
        label=f"HOST: {primary_host_name}",
        node_type="host",
        color=NODE_COLORS["host"],
        shape=NODE_SHAPES["host"],
        icon=NODE_ICONS["host"],
        event_count=len(events),
        threat_score=0,
        threat_level="info",
        mitre_techniques=[],
        is_compromised=False,
        role="Target System Core Architecture"
    )

    # ── 2. Entity Tracking Heuristics ──────────────────────────────────────
    entity_events = defaultdict(int)
    entity_threats = defaultdict(int)
    entity_severities = defaultdict(list)
    entity_mitre = defaultdict(set)
    edge_aggregates = defaultdict(lambda: {
        "count": 0,
        "actions": set(),
        "severities": set(),
        "mitre": set(),
        "suspicious": False,
        "first_idx": 999999,
        "last_idx": -1,
    })

    users = set()
    system_principals = set()
    ips = set()
    processes = set()

    for i, event in enumerate(events):
        user = clean_entity(event.get("user"))
        ip = clean_entity(event.get("ip_address"))
        process = clean_entity(event.get("process"))
        raw_action = event.get("action", "system_event")
        action = format_action_label(raw_action)
        severity = (event.get("severity") or "low").lower()
        is_suspicious = bool(event.get("is_suspicious", 0))
        mitre = event.get("mitre_technique")

        weight = SEVERITY_WEIGHTS.get(severity, 2)
        if is_suspicious:
            weight = max(weight, 18)

        # ── Network IP Node ──
        if ip and ip not in ("127.0.0.1", "::1", "localhost"):
            ip_id = f"ip_{ip}"
            if ip not in ips:
                ips.add(ip)
                G.add_node(
                    ip_id,
                    label=f"IP: {ip}",
                    node_type="ip",
                    color=NODE_COLORS["ip"],
                    shape=NODE_SHAPES["ip"],
                    icon=NODE_ICONS["ip"],
                    role="Remote Network Endpoint"
                )
            entity_events[ip_id] += 1
            entity_threats[ip_id] += weight if is_suspicious else 1
            entity_severities[ip_id].append(severity)
            if mitre:
                entity_mitre[ip_id].add(mitre)

        # ── User / Identity Node ──
        if user:
            is_sys = user.lower() in SYSTEM_USERS
            if is_sys:
                user_id = f"sys_{user}"
                if user not in system_principals:
                    system_principals.add(user)
                    G.add_node(
                        user_id,
                        label=f"SYSTEM [{user.upper()}]",
                        node_type="system",
                        color=NODE_COLORS["system"],
                        shape=NODE_SHAPES["system"],
                        icon=NODE_ICONS["system"],
                        role="OS Kernel Security Principal"
                    )
            else:
                user_id = f"user_{user}"
                if user not in users:
                    users.add(user)
                    G.add_node(
                        user_id,
                        label=f"USER: {user}",
                        node_type="user",
                        color=NODE_COLORS["user"],
                        shape=NODE_SHAPES["user"],
                        icon=NODE_ICONS["user"],
                        role="Authenticated Interactive User"
                    )
            entity_events[user_id] += 1
            entity_threats[user_id] += weight if is_suspicious else 1
            entity_severities[user_id].append(severity)
            if mitre:
                entity_mitre[user_id].add(mitre)

        # ── Process / Binary Node ──
        if process and len(processes) < 65:
            proc_id = f"proc_{process}"
            if process not in processes:
                processes.add(process)
                norm_key = process.lower().strip()
                if norm_key in PROCESS_NORMALIZATION:
                    label, ptype, prole = PROCESS_NORMALIZATION[norm_key]
                else:
                    clean_name = process.split("\\")[-1].split("/")[-1]
                    if clean_name.lower().startswith("microsoft-windows-"):
                        clean_name = clean_name[18:]
                    label = clean_name[:26]
                    ptype = "process"
                    prole = "Executable Binary / Process"

                G.add_node(
                    proc_id,
                    label=label,
                    node_type=ptype,
                    color=NODE_COLORS[ptype],
                    shape=NODE_SHAPES[ptype],
                    icon=NODE_ICONS.get(ptype, "⚡"),
                    role=prole
                )
            entity_events[proc_id] += 1
            entity_threats[proc_id] += weight if is_suspicious else 1
            entity_severities[proc_id].append(severity)
            if mitre:
                entity_mitre[proc_id].add(mitre)

        # ── 3. Edge Correlations (Topological Relationships) ────────────────
        user_node_id = (f"sys_{user}" if (user and user.lower() in SYSTEM_USERS) else f"user_{user}") if user else None
        proc_node_id = f"proc_{process}" if process else None
        ip_node_id = f"ip_{ip}" if (ip and ip not in ("127.0.0.1", "::1", "localhost")) else None

        # User -> Process Execution
        if user_node_id and proc_node_id:
            edge_key = (user_node_id, proc_node_id)
            _add_edge_record(edge_aggregates, edge_key, action, severity, is_suspicious, mitre, i)

        # IP -> User Access
        if ip_node_id and user_node_id:
            edge_key = (ip_node_id, user_node_id)
            _add_edge_record(edge_aggregates, edge_key, "Network Auth", severity, is_suspicious, mitre, i)

        # IP -> Process (Direct socket connection / listener)
        if ip_node_id and proc_node_id and not user_node_id:
            edge_key = (ip_node_id, proc_node_id)
            _add_edge_record(edge_aggregates, edge_key, "Network Packet", severity, is_suspicious, mitre, i)

        # Unparented Process -> Connect to Host Root (Eliminates Orphans!)
        if proc_node_id and not user_node_id and not ip_node_id:
            edge_key = (host_id, proc_node_id)
            _add_edge_record(edge_aggregates, edge_key, "Kernel Dispatch", severity, is_suspicious, mitre, i)

        # Unparented User -> Connect to Host Root
        if user_node_id and not proc_node_id and not ip_node_id:
            edge_key = (user_node_id, host_id)
            _add_edge_record(edge_aggregates, edge_key, "Logon Session", severity, is_suspicious, mitre, i)

        # Unparented IP -> Connect to Host Root
        if ip_node_id and not user_node_id and not proc_node_id:
            edge_key = (ip_node_id, host_id)
            _add_edge_record(edge_aggregates, edge_key, "Gateway Inbound", severity, is_suspicious, mitre, i)

    # ── 4. Guarantee Global Topology Connectivity ──────────────────────────
    # Link all System Principals to Host Root
    for sys_u in system_principals:
        sys_node_id = f"sys_{sys_u}"
        if G.has_node(sys_node_id) and not G.has_edge(host_id, sys_node_id) and not G.has_edge(sys_node_id, host_id):
            edge_key = (host_id, sys_node_id)
            _add_edge_record(edge_aggregates, edge_key, "Security Bus", "low", False, None, 0)

    # Link all Interactive Users to Host Root
    for reg_u in users:
        reg_node_id = f"user_{reg_u}"
        if G.has_node(reg_node_id) and not G.has_edge(host_id, reg_node_id) and not G.has_edge(reg_node_id, host_id):
            edge_key = (reg_node_id, host_id)
            _add_edge_record(edge_aggregates, edge_key, "User Session", "low", False, None, 0)

    # Ensure every single process is connected
    for proc_u in processes:
        p_id = f"proc_{proc_u}"
        if G.has_node(p_id):
            has_edges = any(k[0] == p_id or k[1] == p_id for k in edge_aggregates.keys())
            if not has_edges:
                edge_key = (host_id, p_id)
                _add_edge_record(edge_aggregates, edge_key, "Service Hook", "low", False, None, 0)

    # ── 5. Commit Aggregated Edges ─────────────────────────────────────────
    sev_priority = ["critical", "high", "medium", "low", "info"]

    for (src, dst), data in edge_aggregates.items():
        if not G.has_node(src) or not G.has_node(dst):
            continue

        dom_sev = "low"
        for s in sev_priority:
            if s in data["severities"]:
                dom_sev = s
                break

        action_label = list(data["actions"])[0] if data["actions"] else "Interaction"
        if data["count"] > 1:
            action_label = f"{action_label} (x{data['count']})"

        edge_color = SEVERITY_COLORS.get(dom_sev, "#64748b")
        if data["suspicious"]:
            edge_color = "#ff0055" if dom_sev in ("critical", "high") else "#ff5500"

        edge_width = 3.5 if data["suspicious"] else 2.2
        if data["count"] > 4:
            edge_width += 1.0

        G.add_edge(
            src, dst,
            key=f"{src}->{dst}",
            label=action_label,
            action=action_label,
            count=data["count"],
            severity=dom_sev,
            color=edge_color,
            width=edge_width,
            suspicious=data["suspicious"],
            mitre=list(data["mitre"]),
            first_idx=data["first_idx"],
            last_idx=data["last_idx"],
        )

    # ── 6. Threat Assessment & Blast Radius Computation ────────────────────
    for node_id in list(G.nodes()):
        try:
            in_deg = G.in_degree(node_id)
            out_deg = G.out_degree(node_id)
            descendants = nx.descendants(G, node_id)
            blast_radius = len(descendants)
        except Exception:
            in_deg, out_deg, blast_radius = 0, 0, 0

        threat_score = entity_threats.get(node_id, 0)
        mitre_list = sorted(list(entity_mitre.get(node_id, set())))
        severities = entity_severities.get(node_id, [])

        curr_type = G.nodes[node_id].get("node_type", "process")
        curr_label = G.nodes[node_id].get("label", node_id)
        curr_role = G.nodes[node_id].get("role", "Topological Entity")

        # Classify threat tier
        if threat_score >= 35 or any(s in ("critical", "high") for s in severities):
            threat_level = "critical"
            if curr_type == "user":
                color = "#ff5500"  # Blaze Orange for compromised user
                curr_role = "High-Risk / Compromised User Identity"
                curr_label = f"USER: {curr_label.replace('USER: ', '')} [⚠️ ALERT]"
            elif curr_type == "process" and "powershell" in node_id.lower():
                color = "#ff7700"
                curr_role = "Active Script Execution Vector"
            else:
                color = "#ff0055"
                if curr_type == "process":
                    curr_type = "malware"
        elif threat_score >= 18 or "medium" in severities:
            threat_level = "high"
            color = "#ff5500"
        elif threat_score > 4:
            threat_level = "medium"
            color = "#eab308"
        else:
            threat_level = "benign"
            color = NODE_COLORS.get(curr_type, "#05ffa1")

        icon = NODE_ICONS.get(curr_type, "⚡")

        G.nodes[node_id].update({
            "label": curr_label,
            "node_type": curr_type,
            "event_count": entity_events.get(node_id, 1),
            "threat_score": min(threat_score, 100),
            "threat_level": threat_level,
            "mitre_techniques": mitre_list,
            "is_compromised": threat_level in ("critical", "high"),
            "color": color,
            "icon": icon,
            "role": curr_role,
            "blast_radius": blast_radius,
            "in_degree": in_deg,
            "out_degree": out_deg,
        })

    return _to_cytoscape_json(G)


def _add_edge_record(aggregates, edge_key, action, severity, is_suspicious, mitre, idx):
    """Helper to record edge interactions."""
    data = aggregates[edge_key]
    data["count"] += 1
    data["actions"].add(action)
    data["severities"].add(severity)
    if is_suspicious:
        data["suspicious"] = True
    if mitre:
        data["mitre"].add(mitre)
    data["first_idx"] = min(data["first_idx"], idx)
    data["last_idx"] = max(data["last_idx"], idx)


def _to_cytoscape_json(G: nx.DiGraph) -> Dict:
    """Convert NetworkX graph to Cytoscape.js JSON format with advanced metadata."""
    elements = {"nodes": [], "edges": []}

    for node_id, data in G.nodes(data=True):
        elements["nodes"].append({
            "data": {
                "id": node_id,
                "label": data.get("label", node_id),
                "type": data.get("node_type", "unknown"),
                "color": data.get("color", "#95a5a6"),
                "shape": data.get("shape", "ellipse"),
                "icon": data.get("icon", "⚡"),
                "threat_level": data.get("threat_level", "benign"),
                "threat_score": data.get("threat_score", 0),
                "is_compromised": data.get("is_compromised", False),
                "blast_radius": data.get("blast_radius", 0),
                "event_count": data.get("event_count", 0),
                "mitre_techniques": data.get("mitre_techniques", []),
                "role": data.get("role", "Entity"),
                "degree": data.get("in_degree", 0) + data.get("out_degree", 0),
            }
        })

    for source, target, data in G.edges(data=True):
        elements["edges"].append({
            "data": {
                "id": data.get("key", f"{source}_{target}"),
                "source": source,
                "target": target,
                "label": data.get("label", ""),
                "action": data.get("action", ""),
                "count": data.get("count", 1),
                "severity": data.get("severity", "low"),
                "color": data.get("color", "#95a5a6"),
                "width": data.get("width", 2),
                "suspicious": data.get("suspicious", False),
                "mitre": data.get("mitre", []),
                "first_idx": data.get("first_idx", -1),
                "last_idx": data.get("last_idx", -1),
            }
        })

    total_nodes = G.number_of_nodes()
    total_edges = G.number_of_edges()
    critical_nodes = [n for n, d in G.nodes(data=True) if d.get("threat_level") in ("critical", "high")]

    metrics = {
        "node_count": total_nodes,
        "edge_count": total_edges,
        "density": round(nx.density(G), 4) if total_nodes > 1 else 0,
        "unique_users": len([n for n, d in G.nodes(data=True) if d.get("node_type") in ("user", "adversary")]),
        "unique_ips": len([n for n, d in G.nodes(data=True) if d.get("node_type") == "ip"]),
        "unique_processes": len([n for n, d in G.nodes(data=True) if d.get("node_type") in ("process", "malware", "service")]),
        "compromised_count": len(critical_nodes),
        "threat_ratio": round(len(critical_nodes) / max(total_nodes, 1) * 100, 1),
    }

    return {"elements": elements, "metrics": metrics}


def generate_weaponized_attack_graph() -> Dict:
    """
    Generate an epic multi-stage APT attack simulation graph.
    Demonstrates full tactical attack chain: Initial Access -> Execution -> Persistence
    -> Credential Access -> Lateral Movement -> Command & Control -> Impact.
    """
    elements = {
        "nodes": [
            {"data": {"id": "ip_attacker", "label": "ADV: 185.220.101.5", "type": "ip", "color": "#ff0055", "shape": "ellipse", "icon": "💀", "threat_level": "critical", "threat_score": 98, "is_compromised": True, "blast_radius": 14, "role": "TOR Exit Node / C2 Stager", "event_count": 84, "mitre_techniques": ["T1071.001", "T1190"], "degree": 4}},
            {"data": {"id": "ip_c2_exfil", "label": "C2: 45.33.32.156", "type": "ip", "color": "#ff0055", "shape": "ellipse", "icon": "🌐", "threat_level": "critical", "threat_score": 95, "is_compromised": True, "blast_radius": 0, "role": "Exfiltration Drop Server", "event_count": 42, "mitre_techniques": ["T1048", "T1567"], "degree": 3}},
            {"data": {"id": "host_dmz", "label": "HOST: DMZ-WEB-SRV01", "type": "host", "color": "#a855f7", "shape": "hexagon", "icon": "🖥️", "threat_level": "high", "threat_score": 75, "is_compromised": True, "blast_radius": 10, "role": "Public Facing Web Server", "event_count": 310, "mitre_techniques": ["T1190"], "degree": 7}},
            {"data": {"id": "host_dc", "label": "HOST: DC01-CORP-DOMAIN", "type": "host", "color": "#a855f7", "shape": "hexagon", "icon": "🖥️", "threat_level": "critical", "threat_score": 92, "is_compromised": True, "blast_radius": 6, "role": "Active Directory Domain Controller", "event_count": 180, "mitre_techniques": ["T1003", "T1486"], "degree": 6}},
            {"data": {"id": "user_apache", "label": "USER: www-data", "type": "user", "color": "#eab308", "shape": "round-diamond", "icon": "👤", "threat_level": "medium", "threat_score": 55, "is_compromised": True, "blast_radius": 7, "role": "Compromised Service Account", "event_count": 65, "mitre_techniques": ["T1078"], "degree": 3}},
            {"data": {"id": "user_admin", "label": "ADV: DOM\\Administrator", "type": "adversary", "color": "#ff0055", "shape": "diamond", "icon": "💀", "threat_level": "critical", "threat_score": 100, "is_compromised": True, "blast_radius": 9, "role": "Hijacked Enterprise Admin", "event_count": 112, "mitre_techniques": ["T1078.002", "T1098"], "degree": 6}},
            {"data": {"id": "sys_kernel", "label": "SYSTEM [OS KERNEL]", "type": "system", "color": "#6366f1", "shape": "barrel", "icon": "🛡️", "threat_level": "info", "threat_score": 10, "is_compromised": False, "blast_radius": 5, "role": "Operating System Core Authority", "event_count": 220, "mitre_techniques": [], "degree": 4}},
            {"data": {"id": "proc_nginx", "label": "nginx [Port 443]", "type": "process", "color": "#05ffa1", "shape": "round-rectangle", "icon": "⚡", "threat_level": "medium", "threat_score": 40, "is_compromised": True, "blast_radius": 8, "role": "Edge Web Server Daemon", "event_count": 150, "mitre_techniques": ["T1190"], "degree": 3}},
            {"data": {"id": "proc_webshell", "label": "cmd.jsp [Webshell]", "type": "malware", "color": "#ff0055", "shape": "round-rectangle", "icon": "☣️", "threat_level": "critical", "threat_score": 99, "is_compromised": True, "blast_radius": 7, "role": "Godzilla Web Shell Dropper", "event_count": 35, "mitre_techniques": ["T1505.003"], "degree": 3}},
            {"data": {"id": "proc_ps_stager", "label": "PowerShell [B64 Stager]", "type": "malware", "color": "#ff0055", "shape": "round-rectangle", "icon": "☣️", "threat_level": "critical", "threat_score": 95, "is_compromised": True, "blast_radius": 6, "role": "In-Memory Beacon Loader", "event_count": 28, "mitre_techniques": ["T1059.001", "T1027"], "degree": 4}},
            {"data": {"id": "proc_mimikatz", "label": "mktz.exe [LSASS Dumper]", "type": "malware", "color": "#ff0055", "shape": "round-rectangle", "icon": "☣️", "threat_level": "critical", "threat_score": 100, "is_compromised": True, "blast_radius": 5, "role": "Credential Dumping Utility", "event_count": 19, "mitre_techniques": ["T1003.001"], "degree": 3}},
            {"data": {"id": "proc_lsass", "label": "LSASS [Security Vault]", "type": "process", "color": "#ff5500", "shape": "round-rectangle", "icon": "⚡", "threat_level": "critical", "threat_score": 85, "is_compromised": True, "blast_radius": 4, "role": "Local Security Authority Subsystem", "event_count": 68, "mitre_techniques": ["T1003.001"], "degree": 3}},
            {"data": {"id": "proc_psexec", "label": "PsExec [Lateral Mover]", "type": "malware", "color": "#ff0055", "shape": "round-rectangle", "icon": "☣️", "threat_level": "critical", "threat_score": 94, "is_compromised": True, "blast_radius": 3, "role": "Remote Service Execution", "event_count": 15, "mitre_techniques": ["T1569.002", "T1021.002"], "degree": 3}},
            {"data": {"id": "proc_vssadmin", "label": "vssadmin [Shadow Delete]", "type": "malware", "color": "#ff0055", "shape": "round-rectangle", "icon": "☣️", "threat_level": "critical", "threat_score": 92, "is_compromised": True, "blast_radius": 1, "role": "Inhibit System Recovery", "event_count": 8, "mitre_techniques": ["T1490"], "degree": 2}},
            {"data": {"id": "proc_ransom", "label": "BlackCat.exe [Ransomware]", "type": "malware", "color": "#ff0055", "shape": "round-rectangle", "icon": "☣️", "threat_level": "critical", "threat_score": 100, "is_compromised": True, "blast_radius": 0, "role": "Mass Payload File Encryptor", "event_count": 320, "mitre_techniques": ["T1486"], "degree": 3}},
            {"data": {"id": "proc_defender", "label": "Defender [AV Agent]", "type": "service", "color": "#05ffa1", "shape": "round-octagon", "icon": "⚙️", "threat_level": "low", "threat_score": 15, "is_compromised": False, "blast_radius": 0, "role": "Endpoint Antivirus Sensor", "event_count": 45, "mitre_techniques": ["T1562.001"], "degree": 2}},
        ],
        "edges": [
            {"data": {"id": "e_exp", "source": "ip_attacker", "target": "proc_nginx", "label": "CVE-2023-RCE (x12)", "action": "Remote Exploit", "severity": "critical", "color": "#ff0055", "width": 4.0, "suspicious": True, "mitre": ["T1190"]}},
            {"data": {"id": "e_spawn_ws", "source": "proc_nginx", "target": "proc_webshell", "label": "Drops JSP Webshell", "action": "File Drop", "severity": "critical", "color": "#ff0055", "width": 4.0, "suspicious": True, "mitre": ["T1505.003"]}},
            {"data": {"id": "e_dmz_anchor", "source": "host_dmz", "target": "proc_nginx", "label": "Edge Listener", "action": "Host Binding", "severity": "info", "color": "#a855f7", "width": 2.0, "suspicious": False, "mitre": []}},
            {"data": {"id": "e_ws_ps", "source": "proc_webshell", "target": "proc_ps_stager", "label": "Spawns Encoded PowerShell", "action": "Process Injection", "severity": "critical", "color": "#ff0055", "width": 4.0, "suspicious": True, "mitre": ["T1059.001"]}},
            {"data": {"id": "e_ps_c2", "source": "proc_ps_stager", "target": "ip_attacker", "label": "Reverse HTTPS Beacon", "action": "C2 Callback", "severity": "critical", "color": "#ff0055", "width": 4.5, "suspicious": True, "mitre": ["T1071.001"]}},
            {"data": {"id": "e_ps_mktz", "source": "proc_ps_stager", "target": "proc_mimikatz", "label": "Reflective DLL Inject", "action": "Memory Injection", "severity": "critical", "color": "#ff0055", "width": 4.0, "suspicious": True, "mitre": ["T1055"]}},
            {"data": {"id": "e_mktz_lsass", "source": "proc_mimikatz", "target": "proc_lsass", "label": "Reads LSA Secrets (NTLM)", "action": "Memory Scrape", "severity": "critical", "color": "#ff0055", "width": 5.0, "suspicious": True, "mitre": ["T1003.001"]}},
            {"data": {"id": "e_lsass_admin", "source": "proc_lsass", "target": "user_admin", "label": "Harvested Domain Admin Hash", "action": "Credential Extract", "severity": "critical", "color": "#ff0055", "width": 4.5, "suspicious": True, "mitre": ["T1555"]}},
            {"data": {"id": "e_dmz_admin", "source": "user_admin", "target": "host_dmz", "label": "Privileged Session", "action": "Elevation", "severity": "high", "color": "#ff5500", "width": 3.0, "suspicious": True, "mitre": ["T1068"]}},
            {"data": {"id": "e_admin_psexec", "source": "user_admin", "target": "proc_psexec", "label": "Executes PsExec RPC", "action": "Lateral Dispatch", "severity": "critical", "color": "#ff0055", "width": 4.5, "suspicious": True, "mitre": ["T1569.002"]}},
            {"data": {"id": "e_psexec_dc", "source": "proc_psexec", "target": "host_dc", "label": "SMB Pivot (Port 445)", "action": "Remote Service", "severity": "critical", "color": "#ff0055", "width": 5.0, "suspicious": True, "mitre": ["T1021.002"]}},
            {"data": {"id": "e_dc_vss", "source": "host_dc", "target": "proc_vssadmin", "label": "vssadmin delete shadows /all", "action": "Shadow Wiping", "severity": "critical", "color": "#ff0055", "width": 4.0, "suspicious": True, "mitre": ["T1490"]}},
            {"data": {"id": "e_dc_ransom", "source": "host_dc", "target": "proc_ransom", "label": "Spawns BlackCat Encryptor", "action": "Payload Launch", "severity": "critical", "color": "#ff0055", "width": 5.0, "suspicious": True, "mitre": ["T1486"]}},
            {"data": {"id": "e_ransom_exfil", "source": "proc_ransom", "target": "ip_c2_exfil", "label": "Exfiltrates 18.4GB NTDS.dit", "action": "Exfiltration", "severity": "critical", "color": "#ff0055", "width": 4.5, "suspicious": True, "mitre": ["T1048"]}},
            {"data": {"id": "e_sys_def", "source": "sys_kernel", "target": "proc_defender", "label": "Security Telemetry Bus", "action": "EDR Audit", "severity": "info", "color": "#6366f1", "width": 2.0, "suspicious": False, "mitre": []}},
            {"data": {"id": "e_def_mktz", "source": "proc_defender", "target": "proc_mimikatz", "label": "Tamper: AntiVirus Disabled", "action": "Defense Evasion", "severity": "high", "color": "#ff5500", "width": 3.0, "suspicious": True, "mitre": ["T1562.001"]}},
        ]
    }

    metrics = {
        "node_count": len(elements["nodes"]),
        "edge_count": len(elements["edges"]),
        "density": 0.075,
        "unique_users": 2,
        "unique_ips": 2,
        "unique_processes": 9,
        "compromised_count": 13,
        "threat_ratio": 81.3,
    }

    return {"elements": elements, "metrics": metrics}
