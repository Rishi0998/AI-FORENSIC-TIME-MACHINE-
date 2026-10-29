import { useState, useEffect } from 'react';
import { explainEvent } from '../api';
import { playCyberClick, playTargetLock, playThreatAlert } from '../cyberAudio';

export default function LogExplanationCard({ event, globalIndex, copiedId, copyLog }) {
  const [activeTab, setActiveTab] = useState('analysis'); // 'analysis' | 'ai' | 'raw'
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);
  const [copiedArtifact, setCopiedArtifact] = useState(null);

  // Initial fast rule-based fetch
  useEffect(() => {
    let isMounted = true;
    setLoading(true);

    explainEvent(event, false)
      .then((data) => {
        if (isMounted) {
          setExplanation(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        console.warn('Backend explanation fetch failed, using client-side fallback:', err);
        if (isMounted) {
          // Instant client-side fallback
          setExplanation(buildClientFallback(event));
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [event]);

  // Request Deep Gemini AI report
  const handleRunAiAnalysis = async (e) => {
    if (e) e.stopPropagation();
    playTargetLock();
    setActiveTab('ai');
    setAiLoading(true);

    try {
      const data = await explainEvent(event, true);
      setExplanation((prev) => ({
        ...(prev || {}),
        ...data,
      }));
    } catch (err) {
      console.error('Failed to run AI deep dive:', err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleCopyArtifact = (e, text) => {
    e.stopPropagation();
    playCyberClick();
    navigator.clipboard?.writeText(text);
    setCopiedArtifact(text);
    setTimeout(() => setCopiedArtifact(null), 1500);
  };

  const sev = (event?.severity || 'low').toLowerCase();
  const sevColor =
    sev === 'critical' ? '#ff0055' : sev === 'high' ? '#ff5e00' : sev === 'medium' ? '#ffbb00' : '#00f2fe';

  // Fast client fallback if server is unreachable
  function buildClientFallback(ev) {
    const raw = ev.raw_log || '';
    let eid = 'N/A';
    const m = raw.match(/EventID[=:\s]+(\d+)/i);
    if (m) eid = m[1];

    return {
      event_id: eid,
      event_name: `${ev.action || 'System'} Telemetry Record`,
      subsystem: ev.process || 'Windows OS Subsystem',
      action: ev.action,
      timestamp: ev.timestamp,
      severity: (ev.severity || 'low').toUpperCase(),
      is_suspicious: Boolean(ev.is_suspicious),
      user: ev.user || 'SYSTEM',
      process: ev.process || 'N/A',
      ip_address: ev.ip_address || 'N/A',
      detection_rule: ev.detection_rule || 'Routine Baseline',
      summary: `System recorded '${ev.action}' event at ${ev.timestamp}.`,
      technical_mechanics:
        'The host operating system telemetry layer generated this record as part of audit and event instrumentation.',
      threat_perspective:
        'No direct weaponization signatures matched. Routine baseline activity unless followed by anomalous privilege elevation.',
      mitre_details: {
        technique: ev.mitre_technique || 'N/A',
        tactic: ev.mitre_tactic || 'N/A',
        description: 'Host telemetry observation.',
      },
      artifacts_to_check: [
        'Windows Event Viewer -> System / Application / Security logs',
        'Correlated parent-child process tree via Sysmon or EDR',
      ],
      investigation_steps: [
        'Verify if user security context matches expected baseline.',
        'Check timestamp correlation with adjacent network or process bursts.',
      ],
      ai_explanation: null,
      model_used: 'client-fallback',
      raw_log: raw,
    };
  }

  // Render markdown text cleanly
  const renderMarkdown = (text) => {
    if (!text) return null;
    return text.split('\n').map((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('### ')) {
        return (
          <h4
            key={idx}
            style={{
              fontFamily: 'var(--font-heading)',
              color: '#00f2fe',
              fontSize: '0.95rem',
              letterSpacing: '0.06em',
              margin: '16px 0 6px 0',
              borderBottom: '1px solid rgba(0, 242, 255, 0.2)',
              paddingBottom: 4,
            }}
          >
            {trimmed.replace('### ', '')}
          </h4>
        );
      }
      if (trimmed.startsWith('## ')) {
        return (
          <h3
            key={idx}
            style={{
              fontFamily: 'var(--font-heading)',
              color: '#fff',
              fontSize: '1.08rem',
              letterSpacing: '0.08em',
              margin: '20px 0 8px 0',
              borderBottom: '1px solid rgba(0, 242, 255, 0.35)',
              paddingBottom: 5,
            }}
          >
            {trimmed.replace('## ', '')}
          </h3>
        );
      }
      if (trimmed.startsWith('# ')) {
        return (
          <h2
            key={idx}
            style={{
              fontFamily: 'var(--font-heading)',
              color: '#00f2fe',
              fontSize: '1.2rem',
              letterSpacing: '0.1em',
              margin: '22px 0 10px 0',
            }}
          >
            {trimmed.replace('# ', '')}
          </h2>
        );
      }
      if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
        return (
          <div
            key={idx}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
              margin: '4px 0',
              fontSize: '0.78rem',
              color: '#cbd5e1',
              fontFamily: 'var(--font-mono)',
              lineHeight: 1.5,
            }}
          >
            <span style={{ color: '#00f2fe', minWidth: 10 }}>&bull;</span>
            <span>{trimmed.substring(2)}</span>
          </div>
        );
      }
      if (/^\d+\.\s/.test(trimmed)) {
        const num = trimmed.match(/^(\d+\.)/)[0];
        const content = trimmed.replace(/^(\d+\.\s)/, '');
        return (
          <div
            key={idx}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
              margin: '4px 0',
              fontSize: '0.78rem',
              color: '#e2e8f0',
              fontFamily: 'var(--font-mono)',
              lineHeight: 1.5,
            }}
          >
            <span style={{ color: '#ffbb00', fontWeight: 700, minWidth: 20 }}>{num}</span>
            <span>{content}</span>
          </div>
        );
      }
      if (!trimmed) {
        return <div key={idx} style={{ height: 6 }} />;
      }
      return (
        <p
          key={idx}
          style={{
            margin: '4px 0',
            fontSize: '0.78rem',
            color: '#94a3b8',
            fontFamily: 'var(--font-mono)',
            lineHeight: 1.6,
          }}
        >
          {trimmed}
        </p>
      );
    });
  };

  const exp = explanation || buildClientFallback(event);

  return (
    <div
      onClick={(e) => e.stopPropagation()}
      style={{
        marginTop: 10,
        background: 'rgba(2, 6, 18, 0.98)',
        border: `1px solid ${sevColor}55`,
        boxShadow: `0 8px 32px rgba(0,0,0,0.8), inset 0 0 16px ${sevColor}15`,
        borderRadius: 4,
        overflow: 'hidden',
        animation: 'fadeIn 0.25s ease',
      }}
    >
      {/* ── Top Navigation Bar ────────────────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 10,
          padding: '10px 16px',
          background: 'rgba(4, 11, 28, 0.95)',
          borderBottom: '1px solid rgba(0, 242, 255, 0.18)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="pulse-dot" style={{ background: sevColor }} />
          <span
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: '0.82rem',
              letterSpacing: '0.1em',
              color: '#fff',
              fontWeight: 700,
            }}
          >
            [ 0xDISASSEMBLY // EVENT_ID: {exp.event_id} ]
          </span>
          <span
            style={{
              background: `${sevColor}22`,
              border: `1px solid ${sevColor}66`,
              color: sevColor,
              padding: '1px 6px',
              borderRadius: 2,
              fontFamily: 'var(--font-mono)',
              fontSize: '0.62rem',
              fontWeight: 700,
            }}
          >
            {exp.severity}
          </span>
        </div>

        {/* Tab Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <button
            onClick={() => {
              playCyberClick();
              setActiveTab('analysis');
            }}
            style={{
              background: activeTab === 'analysis' ? 'rgba(0, 242, 255, 0.2)' : 'rgba(255,255,255,0.03)',
              border: `1px solid ${activeTab === 'analysis' ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.1)'}`,
              color: activeTab === 'analysis' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              padding: '4px 10px',
              borderRadius: 2,
              fontFamily: 'var(--font-heading)',
              fontSize: '0.74rem',
              letterSpacing: '0.06em',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}
          >
            <span>🔍 FORENSIC ANALYSIS</span>
          </button>

          <button
            onClick={() => {
              playCyberClick();
              if (!exp.ai_explanation) {
                handleRunAiAnalysis();
              } else {
                setActiveTab('ai');
              }
            }}
            style={{
              background:
                activeTab === 'ai'
                  ? 'rgba(168, 85, 247, 0.25)'
                  : exp.ai_explanation
                  ? 'rgba(168, 85, 247, 0.1)'
                  : 'rgba(255,255,255,0.03)',
              border: `1px solid ${
                activeTab === 'ai' ? 'var(--accent-purple)' : exp.ai_explanation ? '#a855f766' : 'rgba(255,255,255,0.1)'
              }`,
              color: activeTab === 'ai' || exp.ai_explanation ? '#c084fc' : 'var(--text-secondary)',
              padding: '4px 10px',
              borderRadius: 2,
              fontFamily: 'var(--font-heading)',
              fontSize: '0.74rem',
              letterSpacing: '0.06em',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}
          >
            <span>⚡ AI NEURAL COPILOT</span>
            {exp.ai_explanation && (
              <span style={{ fontSize: '0.58rem', background: '#a855f7', color: '#fff', padding: '0 4px', borderRadius: 2 }}>
                READY
              </span>
            )}
          </button>

          <button
            onClick={() => {
              playCyberClick();
              setActiveTab('raw');
            }}
            style={{
              background: activeTab === 'raw' ? 'rgba(0, 242, 255, 0.2)' : 'rgba(255,255,255,0.03)',
              border: `1px solid ${activeTab === 'raw' ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.1)'}`,
              color: activeTab === 'raw' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              padding: '4px 10px',
              borderRadius: 2,
              fontFamily: 'var(--font-heading)',
              fontSize: '0.74rem',
              letterSpacing: '0.06em',
              cursor: 'pointer',
            }}
          >
            <span>📄 RAW BUFFER</span>
          </button>

          <button
            onClick={(e) => copyLog(event.raw_log || JSON.stringify(event, null, 2), globalIndex)}
            className={`cyber-copy-btn ${copiedId === globalIndex ? 'copied' : ''}`}
            style={{ padding: '4px 10px', fontSize: '0.7rem' }}
          >
            {copiedId === globalIndex ? '✓ COPIED' : '📋 COPY RAW'}
          </button>
        </div>
      </div>

      {/* ── Content View ─────────────────────────────────────────────────── */}
      <div style={{ padding: '16px 18px' }}>
        {/* TAB 1: FORENSIC ANALYSIS */}
        {activeTab === 'analysis' && (
          <div>
            {/* Event Name & Headline Banner */}
            <div
              style={{
                background: 'rgba(0, 242, 255, 0.04)',
                border: '1px solid rgba(0, 242, 255, 0.15)',
                borderRadius: 3,
                padding: '12px 16px',
                marginBottom: 14,
              }}
            >
              <div
                style={{
                  fontFamily: 'var(--font-heading)',
                  fontSize: '1.05rem',
                  letterSpacing: '0.06em',
                  color: '#fff',
                  fontWeight: 700,
                  marginBottom: 6,
                }}
              >
                {exp.event_name}
              </div>

              {/* Forensic Badges Ribbon */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
                <span
                  style={{
                    background: 'rgba(0, 242, 255, 0.1)',
                    border: '1px solid rgba(0, 242, 255, 0.3)',
                    color: '#00f2fe',
                    padding: '2px 8px',
                    borderRadius: 2,
                    fontSize: '0.68rem',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  EVENT ID: {exp.event_id}
                </span>

                <span
                  style={{
                    background: 'rgba(168, 85, 247, 0.1)',
                    border: '1px solid rgba(168, 85, 247, 0.3)',
                    color: '#c084fc',
                    padding: '2px 8px',
                    borderRadius: 2,
                    fontSize: '0.68rem',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  SUBSYSTEM: {exp.subsystem}
                </span>

                <span
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid rgba(255, 255, 255, 0.15)',
                    color: '#e2e8f0',
                    padding: '2px 8px',
                    borderRadius: 2,
                    fontSize: '0.68rem',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  USER: {exp.user}
                </span>

                {exp.process && exp.process !== 'N/A' && (
                  <span
                    style={{
                      background: 'rgba(0, 255, 136, 0.08)',
                      border: '1px solid rgba(0, 255, 136, 0.3)',
                      color: '#00ff88',
                      padding: '2px 8px',
                      borderRadius: 2,
                      fontSize: '0.68rem',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    PROC: {exp.process}
                  </span>
                )}

                {exp.ip_address && exp.ip_address !== 'N/A' && (
                  <span
                    style={{
                      background: 'rgba(0, 242, 255, 0.08)',
                      border: '1px solid rgba(0, 242, 255, 0.3)',
                      color: '#00f2fe',
                      padding: '2px 8px',
                      borderRadius: 2,
                      fontSize: '0.68rem',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    IP: {exp.ip_address}
                  </span>
                )}
              </div>
            </div>

            {/* Plain English Summary Box */}
            <div
              style={{
                background: 'rgba(255, 187, 0, 0.06)',
                borderLeft: '3px solid #ffbb00',
                padding: '10px 14px',
                marginBottom: 16,
                borderRadius: '0 3px 3px 0',
              }}
            >
              <div
                style={{
                  fontSize: '0.66rem',
                  fontFamily: 'var(--font-heading)',
                  letterSpacing: '0.1em',
                  color: '#ffbb00',
                  fontWeight: 700,
                  marginBottom: 3,
                }}
              >
                [ WHAT HAPPENED // PLAIN-ENGLISH SUMMARY ]
              </div>
              <div
                style={{
                  fontSize: '0.82rem',
                  color: '#f8fafc',
                  fontFamily: 'var(--font-mono)',
                  lineHeight: 1.5,
                }}
              >
                {exp.summary}
              </div>
            </div>

            {/* 2-Column Forensic Breakdown */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                gap: 14,
                marginBottom: 16,
              }}
            >
              {/* Left Column: Subsystem Mechanics & Threat Analysis */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {/* OS Mechanics */}
                <div
                  style={{
                    background: 'rgba(5, 12, 32, 0.8)',
                    border: '1px solid rgba(0, 242, 255, 0.15)',
                    padding: '12px 14px',
                    borderRadius: 3,
                  }}
                >
                  <div
                    style={{
                      fontFamily: 'var(--font-heading)',
                      color: '#00f2fe',
                      fontSize: '0.78rem',
                      letterSpacing: '0.08em',
                      fontWeight: 700,
                      marginBottom: 6,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span>⚙️</span>
                    <span>SUBSYSTEM & OS KERNEL MECHANICS</span>
                  </div>
                  <div
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.74rem',
                      color: '#94a3b8',
                      lineHeight: 1.55,
                    }}
                  >
                    {exp.technical_mechanics}
                  </div>
                </div>

                {/* Threat & Weaponization Perspective */}
                <div
                  style={{
                    background: 'rgba(5, 12, 32, 0.8)',
                    border: '1px solid rgba(255, 94, 0, 0.25)',
                    padding: '12px 14px',
                    borderRadius: 3,
                  }}
                >
                  <div
                    style={{
                      fontFamily: 'var(--font-heading)',
                      color: '#ff5e00',
                      fontSize: '0.78rem',
                      letterSpacing: '0.08em',
                      fontWeight: 700,
                      marginBottom: 6,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span>🛡️</span>
                    <span>THREAT & ADVERSARY WEAPONIZATION PERSPECTIVE</span>
                  </div>
                  <div
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.74rem',
                      color: '#cbd5e1',
                      lineHeight: 1.55,
                    }}
                  >
                    {exp.threat_perspective}
                  </div>
                </div>

                {/* MITRE ATT&CK Mapping */}
                {exp.mitre_details && exp.mitre_details.technique !== 'N/A' && (
                  <div
                    style={{
                      background: 'rgba(168, 85, 247, 0.06)',
                      border: '1px solid rgba(168, 85, 247, 0.25)',
                      padding: '10px 14px',
                      borderRadius: 3,
                    }}
                  >
                    <div
                      style={{
                        fontFamily: 'var(--font-heading)',
                        color: '#c084fc',
                        fontSize: '0.74rem',
                        letterSpacing: '0.08em',
                        fontWeight: 700,
                        marginBottom: 6,
                      }}
                    >
                      MITRE ATT&CK MAPPING
                    </div>
                    <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                      <span
                        style={{
                          background: 'rgba(168, 85, 247, 0.2)',
                          color: '#e9d5ff',
                          padding: '2px 6px',
                          borderRadius: 2,
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.66rem',
                          fontWeight: 700,
                        }}
                      >
                        {exp.mitre_details.technique}
                      </span>
                      <span
                        style={{
                          background: 'rgba(255, 255, 255, 0.05)',
                          color: '#94a3b8',
                          padding: '2px 6px',
                          borderRadius: 2,
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.66rem',
                        }}
                      >
                        TACTIC: {exp.mitre_details.tactic}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: '0.72rem',
                        fontFamily: 'var(--font-mono)',
                        color: '#a855f7',
                      }}
                    >
                      {exp.mitre_details.description}
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: SOC Playbook & Artifacts */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {/* SOC Checklist */}
                <div
                  style={{
                    background: 'rgba(5, 12, 32, 0.8)',
                    border: '1px solid rgba(0, 255, 136, 0.2)',
                    padding: '12px 14px',
                    borderRadius: 3,
                  }}
                >
                  <div
                    style={{
                      fontFamily: 'var(--font-heading)',
                      color: '#00ff88',
                      fontSize: '0.78rem',
                      letterSpacing: '0.08em',
                      fontWeight: 700,
                      marginBottom: 8,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span>📋</span>
                    <span>FORENSIC INVESTIGATION PLAYBOOK (SOC ACTIONS)</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {(exp.investigation_steps || []).map((step, sIdx) => (
                      <div
                        key={sIdx}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: 8,
                          fontSize: '0.74rem',
                          fontFamily: 'var(--font-mono)',
                          color: '#e2e8f0',
                          lineHeight: 1.45,
                        }}
                      >
                        <span
                          style={{
                            color: '#00ff88',
                            fontWeight: 700,
                            minWidth: 16,
                            textAlign: 'right',
                          }}
                        >
                          {sIdx + 1}.
                        </span>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Key Artifacts to Check */}
                <div
                  style={{
                    background: 'rgba(5, 12, 32, 0.8)',
                    border: '1px solid rgba(0, 242, 255, 0.15)',
                    padding: '12px 14px',
                    borderRadius: 3,
                  }}
                >
                  <div
                    style={{
                      fontFamily: 'var(--font-heading)',
                      color: '#00f2fe',
                      fontSize: '0.78rem',
                      letterSpacing: '0.08em',
                      fontWeight: 700,
                      marginBottom: 8,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span>📁</span>
                    <span>KEY FORENSIC ARTIFACTS & PATHS TO CORRELATE</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {(exp.artifacts_to_check || []).map((art, aIdx) => (
                      <div
                        key={aIdx}
                        onClick={(e) => handleCopyArtifact(e, art)}
                        style={{
                          background: 'rgba(0, 242, 255, 0.05)',
                          border: '1px solid rgba(0, 242, 255, 0.18)',
                          padding: '6px 10px',
                          borderRadius: 2,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: 8,
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                        }}
                        title="Click to copy path"
                      >
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.7rem',
                            color: '#cbd5e1',
                            wordBreak: 'break-all',
                          }}
                        >
                          {art}
                        </span>
                        <span
                          style={{
                            fontSize: '0.62rem',
                            fontFamily: 'var(--font-mono)',
                            color: copiedArtifact === art ? '#00ff88' : '#00f2fe',
                            minWidth: 50,
                            textAlign: 'right',
                          }}
                        >
                          {copiedArtifact === art ? '✓ COPIED' : 'COPY'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Launch AI Deep Dive Prompt Banner */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 12,
                padding: '12px 16px',
                background: 'linear-gradient(90deg, rgba(168, 85, 247, 0.15), rgba(0, 242, 255, 0.1))',
                border: '1px solid rgba(168, 85, 247, 0.35)',
                borderRadius: 3,
              }}
            >
              <div>
                <div
                  style={{
                    fontFamily: 'var(--font-heading)',
                    fontSize: '0.88rem',
                    letterSpacing: '0.06em',
                    color: '#fff',
                    fontWeight: 700,
                  }}
                >
                  ⚡ NEED DEEPER AUTONOMOUS INVESTIGATION?
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.72rem',
                    color: '#c084fc',
                    marginTop: 2,
                  }}
                >
                  Generate a complete AI incident report with Google Gemini 3.5 Flash for root-cause and adversary tradecraft.
                </div>
              </div>

              <button
                onClick={handleRunAiAnalysis}
                style={{
                  background: 'linear-gradient(135deg, #a855f7, #6366f1)',
                  border: 'none',
                  color: '#fff',
                  padding: '8px 16px',
                  borderRadius: 2,
                  fontFamily: 'var(--font-heading)',
                  fontSize: '0.78rem',
                  letterSpacing: '0.08em',
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 0 15px rgba(168, 85, 247, 0.4)',
                  transition: 'transform 0.15s ease',
                }}
              >
                {exp.ai_explanation ? 'VIEW GEMINI REPORT ▶' : '⚡ RUN GEMINI AI INVESTIGATION'}
              </button>
            </div>
          </div>
        )}

        {/* TAB 2: AI NEURAL COPILOT */}
        {activeTab === 'ai' && (
          <div>
            {aiLoading && (
              <div
                style={{
                  padding: '40px 20px',
                  textAlign: 'center',
                  background: 'rgba(5, 12, 32, 0.6)',
                  borderRadius: 3,
                }}
              >
                <div className="spinner" style={{ margin: '0 auto 16px' }} />
                <div
                  style={{
                    fontFamily: 'var(--font-heading)',
                    color: '#c084fc',
                    letterSpacing: '0.12em',
                    fontSize: '0.95rem',
                  }}
                >
                  QUERYING GEMINI NEURAL REASONING CORE...
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    color: '#64748b',
                    fontSize: '0.72rem',
                    marginTop: 6,
                  }}
                >
                  Analyzing telemetry buffer, cross-referencing MITRE ATT&CK vectors and adversary tradecraft...
                </div>
              </div>
            )}

            {!aiLoading && exp.ai_explanation && (
              <div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: 14,
                    borderBottom: '1px solid rgba(168, 85, 247, 0.25)',
                    paddingBottom: 8,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span
                      style={{
                        background: 'rgba(168, 85, 247, 0.2)',
                        border: '1px solid #a855f7',
                        color: '#e9d5ff',
                        padding: '2px 8px',
                        borderRadius: 2,
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.66rem',
                        fontWeight: 700,
                      }}
                    >
                      AI ENGINE: GEMINI 3.5 FLASH
                    </span>
                    <span style={{ fontSize: '0.7rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                      [ AUTONOMOUS DFIR REPORT ]
                    </span>
                  </div>

                  <button
                    onClick={handleRunAiAnalysis}
                    style={{
                      background: 'rgba(255,255,255,0.05)',
                      border: '1px solid rgba(255,255,255,0.15)',
                      color: '#cbd5e1',
                      padding: '3px 8px',
                      borderRadius: 2,
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.66rem',
                      cursor: 'pointer',
                    }}
                  >
                    ↻ RE-ANALYZE
                  </button>
                </div>

                <div
                  style={{
                    background: 'rgba(3, 8, 22, 0.95)',
                    border: '1px solid rgba(168, 85, 247, 0.25)',
                    borderRadius: 3,
                    padding: '16px 20px',
                    maxHeight: '480px',
                    overflowY: 'auto',
                  }}
                >
                  {renderMarkdown(exp.ai_explanation)}
                </div>
              </div>
            )}

            {!aiLoading && !exp.ai_explanation && (
              <div
                style={{
                  padding: '36px 24px',
                  textAlign: 'center',
                  background: 'rgba(5, 12, 32, 0.6)',
                  border: '1px dashed rgba(168, 85, 247, 0.35)',
                  borderRadius: 3,
                }}
              >
                <div style={{ fontSize: '2rem', marginBottom: 10 }}>🤖</div>
                <div
                  style={{
                    fontFamily: 'var(--font-heading)',
                    fontSize: '1.05rem',
                    letterSpacing: '0.08em',
                    color: '#fff',
                    marginBottom: 6,
                  }}
                >
                  AUTONOMOUS GEMINI DFIR INVESTIGATION
                </div>
                <p
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem',
                    color: '#94a3b8',
                    maxWidth: 500,
                    margin: '0 auto 18px',
                    lineHeight: 1.5,
                  }}
                >
                  Ask Google Gemini 3.5 Flash to generate a specialized incident response briefing, analyzing root-cause mechanics, potential evasions, and concrete triage steps.
                </p>
                <button
                  onClick={handleRunAiAnalysis}
                  style={{
                    background: 'linear-gradient(135deg, #a855f7, #6366f1)',
                    border: 'none',
                    color: '#fff',
                    padding: '8px 20px',
                    borderRadius: 2,
                    fontFamily: 'var(--font-heading)',
                    fontSize: '0.82rem',
                    letterSpacing: '0.08em',
                    fontWeight: 700,
                    cursor: 'pointer',
                    boxShadow: '0 0 18px rgba(168, 85, 247, 0.4)',
                  }}
                >
                  ⚡ INITIALIZE GEMINI AI INVESTIGATION
                </button>
              </div>
            )}
          </div>
        )}

        {/* TAB 3: RAW BUFFER */}
        {activeTab === 'raw' && (
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 8,
              }}
            >
              <span
                style={{
                  fontSize: '0.68rem',
                  color: 'var(--accent-cyan)',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                DECODED RAW TELEMETRY PAYLOAD
              </span>
              <button
                onClick={(e) => copyLog(event.raw_log || JSON.stringify(event, null, 2), globalIndex)}
                className={`cyber-copy-btn ${copiedId === globalIndex ? 'copied' : ''}`}
              >
                {copiedId === globalIndex ? '✓ BUFFER COPIED' : '📋 COPY RAW PAYLOAD'}
              </button>
            </div>

            <pre
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.74rem',
                color: '#94a3b8',
                background: 'rgba(2, 4, 12, 0.9)',
                border: '1px solid rgba(0, 242, 255, 0.2)',
                borderRadius: 2,
                padding: '12px 14px',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                margin: '0 0 14px 0',
                lineHeight: 1.55,
                maxHeight: 260,
              }}
            >
              {event.raw_log || JSON.stringify(event, null, 2)}
            </pre>

            {/* Parsed JSON Metadata */}
            <div
              style={{
                background: 'rgba(4, 9, 24, 0.8)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: 2,
                padding: '10px 14px',
              }}
            >
              <div
                style={{
                  fontSize: '0.65rem',
                  fontFamily: 'var(--font-heading)',
                  color: '#64748b',
                  letterSpacing: '0.08em',
                  marginBottom: 6,
                }}
              >
                PARSED EVENT OBJECT SCHEMA
              </div>
              <pre
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.68rem',
                  color: '#64748b',
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                }}
              >
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

