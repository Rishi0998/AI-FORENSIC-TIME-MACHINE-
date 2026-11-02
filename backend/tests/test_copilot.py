"""
Unit tests for Forensic AI Copilot evidence retrieval and chat reasoning.
"""
import pytest
from services.copilot import _extract_ioc_inventory, _retrieve_relevant_events, _generate_suggested_followups, chat_with_evidence

SAMPLE_EVENTS = [
    {
        "id": 101,
        "timestamp": "2026-11-01 10:15:00",
        "action": "failed_logon",
        "user": "sec_admin",
        "ip_address": "185.220.101.5",
        "process": "svchost.exe",
        "severity": "high",
        "is_suspicious": True,
        "detection_rule": "brute_force",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "raw_log": "EventID 4625 user sec_admin failed authentication"
    },
    {
        "id": 102,
        "timestamp": "2026-11-01 10:16:30",
        "action": "powershell_download",
        "user": "sec_admin",
        "ip_address": "185.220.101.5",
        "process": "powershell.exe",
        "severity": "critical",
        "is_suspicious": True,
        "detection_rule": "suspicious_script_execution",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "raw_log": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command Invoke-WebRequest"
    }
]

def test_extract_ioc_inventory():
    iocs = _extract_ioc_inventory(SAMPLE_EVENTS)
    assert "185.220.101.5" in iocs["ips"]
    assert "sec_admin" in iocs["users"]
    assert "powershell.exe" in iocs["processes"]
    assert iocs["suspicious_count"] == 2
    assert iocs["total_count"] == 2

def test_retrieve_relevant_events():
    matched = _retrieve_relevant_events(SAMPLE_EVENTS, "powershell download", top_k=5)
    assert len(matched) > 0
    # PowerShell event should be included
    processes = [e["process"] for e in matched]
    assert "powershell.exe" in processes

def test_generate_suggested_followups():
    iocs = _extract_ioc_inventory(SAMPLE_EVENTS)
    followups = _generate_suggested_followups("What are the malicious IPs?", iocs)
    assert len(followups) == 3
    assert any("IP" in f or "PowerShell" in f for f in followups)

def test_chat_with_evidence_execution():
    result = chat_with_evidence(
        session_id="test-session",
        message="What user account was targeted in the brute force?",
        history=[],
        events=SAMPLE_EVENTS,
        session_info={"risk_score": 90, "risk_level": "critical"}
    )
    assert "reply" in result
    assert len(result["reply"]) > 20
    assert result["model_used"] in ("gemini-3.5-flash-lite", "gemini-3.5-flash", "local-evidence-engine")
    assert len(result["suggested_followups"]) > 0

