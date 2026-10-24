"""
Attack Graph Generator
Uses NetworkX to build a directed graph of the attack, with nodes
representing users, IPs, processes and edges representing actions.
"""
import networkx as nx
from typing import List, Dict
from collections import defaultdict


# Node type colors for frontend visualization
NODE_COLORS = {
    "user":    "#e74c3c",   # Red
    "ip":      "#3498db",   # Blue
    "process": "#2ecc71",   # Green
    "host":    "#9b59b6",   # Purple
}

NODE_SHAPES = {
    "user":    "diamond",
    "ip":      "ellipse",
    "process": "rectangle",
    "host":    "hexagon",
}

SEVERITY_COLORS = {
    "low":      "#95a5a6",
    "medium":   "#f39c12",
    "high":     "#e67e22",
    "critical": "#e74c3c",
}


def build_attack_graph(events: List[Dict]) -> Dict:
    """
    Build a directed attack graph from events.
    Returns Cytoscape.js-compatible JSON format.
    """
    G = nx.DiGraph()

    # Track unique entities
    users = set()
    ips = set()
    processes = set()

    for i, event in enumerate(events):
        user = event.get("user")
        ip = event.get("ip_address")
        process = event.get("process")
        action = event.get("action", "unknown")
        severity = event.get("severity", "low")
        is_suspicious = event.get("is_suspicious", 0)

        # Add nodes
        if ip and ip not in ips:
            ips.add(ip)
            G.add_node(f"ip_{ip}", label=ip, node_type="ip",
                       color=NODE_COLORS["ip"], shape=NODE_SHAPES["ip"])

        if user and user not in users:
            users.add(user)
            G.add_node(f"user_{user}", label=user, node_type="user",
                       color=NODE_COLORS["user"], shape=NODE_SHAPES["user"])

        if process and process not in processes and len(processes) < 50:
            processes.add(process)
            proc_label = process.split("/")[-1][:30] if "/" in process else process[:30]
            G.add_node(f"proc_{process}", label=proc_label, node_type="process",
                       color=NODE_COLORS["process"], shape=NODE_SHAPES["process"])

        # Add edges based on action type
        edge_color = SEVERITY_COLORS.get(severity, "#95a5a6")
        edge_width = 2 if not is_suspicious else (4 if severity in ("high", "critical") else 3)

        if ip and user:
            edge_id = f"e_{i}_ip_user"
            G.add_edge(f"ip_{ip}", f"user_{user}",
                       key=edge_id, label=action, action=action,
                       severity=severity, color=edge_color, width=edge_width,
                       event_index=i, suspicious=bool(is_suspicious))

        if user and process:
            edge_id = f"e_{i}_user_proc"
            G.add_edge(f"user_{user}", f"proc_{process}",
                       key=edge_id, label=action, action=action,
                       severity=severity, color=edge_color, width=edge_width,
                       event_index=i, suspicious=bool(is_suspicious))

        if ip and process and not user:
            edge_id = f"e_{i}_ip_proc"
            G.add_edge(f"ip_{ip}", f"proc_{process}",
                       key=edge_id, label=action, action=action,
                       severity=severity, color=edge_color, width=edge_width,
                       event_index=i, suspicious=bool(is_suspicious))

    return _to_cytoscape_json(G)


def _to_cytoscape_json(G: nx.DiGraph) -> Dict:
    """Convert NetworkX graph to Cytoscape.js JSON format."""
    elements = {"nodes": [], "edges": []}

    for node_id, data in G.nodes(data=True):
        elements["nodes"].append({
            "data": {
                "id": node_id,
                "label": data.get("label", node_id),
                "type": data.get("node_type", "unknown"),
                "color": data.get("color", "#95a5a6"),
                "shape": data.get("shape", "ellipse"),
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
                "severity": data.get("severity", "low"),
                "color": data.get("color", "#95a5a6"),
                "width": data.get("width", 2),
                "event_index": data.get("event_index", -1),
                "suspicious": data.get("suspicious", False),
            }
        })

    # Graph metrics
    metrics = {
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
        "density": round(nx.density(G), 4) if G.number_of_nodes() > 1 else 0,
        "unique_users": len([n for n, d in G.nodes(data=True) if d.get("node_type") == "user"]),
        "unique_ips": len([n for n, d in G.nodes(data=True) if d.get("node_type") == "ip"]),
        "unique_processes": len([n for n, d in G.nodes(data=True) if d.get("node_type") == "process"]),
    }

    return {"elements": elements, "metrics": metrics}
