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

    explanation = None
    model_used = "rule-based"

    # 1. Try Gemini (Google AI)
    if AI_MODEL in ("gemini", "auto") and GEMINI_API_KEY:
        explanation = _call_gemini(context)
        if explanation:
            model_used = "gemini"

    # 2. Try OpenAI
    if not explanation and AI_MODEL in ("openai", "auto") and OPENAI_API_KEY:
        explanation = _call_openai(context)
        if explanation:
            model_used = "openai"

    # 3. Try Ollama (local)
    if not explanation and AI_MODEL in ("ollama", "auto"):
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


def _call_gemini(context: str) -> Optional[str]:
    """Call Google Gemini API for explanation generation using new google-genai SDK."""
    try:
        from google import genai

        client = genai.Client(api_key=GEMINI_API_KEY)

        # Try models in order of preference
        models_to_try = ["gemini-2.0-flash-lite", "gemini-2.0-flash", "gemini-1.5-flash"]

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
                    print(f"✅ Gemini ({model_name}) response received ({len(response.text)} chars)")
                    return response.text

            except Exception as model_err:
                err_str = str(model_err)
                if "429" in err_str or "quota" in err_str.lower():
                    print(f"⚠️ Gemini {model_name} quota exceeded, trying next model...")
                    continue
                elif "404" in err_str or "not found" in err_str.lower():
                    print(f"⚠️ Gemini model {model_name} not available, trying next...")
                    continue
                else:
                    print(f"⚠️ Gemini {model_name} error: {model_err}")
                    continue

    except ImportError:
        print("⚠️ google-genai package not installed. Run: pip install google-genai")
    except Exception as e:
        print(f"⚠️ Gemini API error: {e}")

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
        print(f"⚠️ OpenAI API error: {e}")
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
