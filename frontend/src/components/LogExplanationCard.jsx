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

  // Format playbook text with high-tech inline code badges for paths and binaries
  const formatStepContent = (text) => {
    if (!text) return null;
    const parts = text.split(/(`[^`]+`|[A-Za-z]:\\[\w\\.-]+|%[\w]+%|\b[\w-]+\.(?:exe|dll|sys|bat|ps1|sh|json|log|bin)\b)/g);
    return parts.map((part, i) => {
      if (!part) return null;
      if (
        (part.startsWith('`') && part.endsWith('`')) ||
        /^[A-Za-z]:\\/.test(part) ||
        /^%[\w]+%$/.test(part) ||
        /\.(?:exe|dll|sys|bat|ps1|sh|json|log|bin)$/i.test(part)
      ) {
        const clean = part.replace(/^`|`$/g, '');
        return <code key={i} className="forensic-inline-code">{clean}</code>;
      }
      return <span key={i}>{part}</span>;
    });
  };

  // Render markdown text with sleek typography
  const renderMarkdown = (text) => {
    if (!text) return null;
    return text.split('\n').map((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('### ')) {
        return (
          <h4
            key={idx}
            style={{
              fontFamily: 'var(--font-tech)',
              color: '#00f2fe',
              fontSize: '1.05rem',
              fontWeight: 700,
              letterSpacing: '0.06em',
              margin: '18px 0 8px 0',
              borderBottom: '1px solid rgba(0, 242, 255, 0.2)',
              paddingBottom: 4,
              textTransform: 'uppercase',
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
              fontFamily: 'var(--font-tech)',
              color: '#ffffff',
              fontSize: '1.18rem',
              fontWeight: 700,
              letterSpacing: '0.06em',
              margin: '22px 0 10px 0',
              borderBottom: '1px solid rgba(0, 242, 255, 0.35)',
              paddingBottom: 6,
              textTransform: 'uppercase',
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
              fontFamily: 'var(--font-tech)',
              color: '#00f2fe',
              fontSize: '1.32rem',
              fontWeight: 700,
              letterSpacing: '0.08em',
              margin: '24px 0 12px 0',
              textTransform: 'uppercase',
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
              gap: 10,
              margin: '6px 0',
              fontSize: '0.84rem',
              color: '#e2e8f0',
              fontFamily: 'var(--font-sans)',
              lineHeight: 1.6,
            }}
          >
            <span style={{ color: '#00f2fe', fontWeight: 700, minWidth: 10 }}>&bull;</span>
            <span>{formatStepContent(trimmed.substring(2))}</span>
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
              gap: 10,
              margin: '6px 0',
              fontSize: '0.84rem',
              color: '#e2e8f0',
              fontFamily: 'var(--font-sans)',
              lineHeight: 1.6,
            }}
          >
            <span style={{ color: '#00ff88', fontWeight: 700, minWidth: 22, fontFamily: 'var(--font-tech)', fontSize: '0.92rem' }}>
              {num}
            </span>
            <span>{formatStepContent(content)}</span>
          </div>
        );
      }
      if (!trimmed) {
        return <div key={idx} style={{ height: 8 }} />;
      }
      return (
        <p
          key={idx}
          style={{
            margin: '6px 0',
            fontSize: '0.85rem',
            color: '#cbd5e1',
            fontFamily: 'var(--font-sans)',
            lineHeight: 1.65,
            letterSpacing: '0.01em',
          }}
        >
          {formatStepContent(trimmed)}
        </p>
      );
    });
  };

  const exp = explanation || buildClientFallback(event);

  return (
    <div
      className="forensic-disassembly-card"
      onClick={(e) => e.stopPropagation()}
      style={{
        border: `1px solid ${sevColor}55`,
        boxShadow: `0 12px 36px rgba(0,0,0,0.85), inset 0 0 18px ${sevColor}15`,
      }}
    >
      {/* ── Top Navigation Bar ────────────────────────────────────────────── */}
      <div className="forensic-top-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="pulse-dot" style={{ background: sevColor }} />
          <span className="forensic-tag-id">
            [ 0xDISASSEMBLY // EVENT_ID: {exp.event_id} ]
          </span>
          <span
            style={{
              background: `${sevColor}22`,
              border: `1px solid ${sevColor}66`,
              color: sevColor,
              padding: '2px 8px',
              borderRadius: 3,
              fontFamily: 'var(--font-tech)',
              fontSize: '0.72rem',
              fontWeight: 700,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
            }}
          >
            {exp.severity}
          </span>
        </div>

        {/* Tab Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={() => {
              playCyberClick();
              setActiveTab('analysis');
            }}
            className={`forensic-tab-btn ${activeTab === 'analysis' ? 'active' : ''}`}
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
            className={`forensic-tab-btn ai-tab ${activeTab === 'ai' ? 'active' : ''}`}
          >
            <span>⚡ AI NEURAL COPILOT</span>
            {exp.ai_explanation && (
              <span style={{ fontSize: '0.62rem', background: '#a855f7', color: '#fff', padding: '1px 5px', borderRadius: 2, fontWeight: 700 }}>
                READY
              </span>
            )}
          </button>

          <button
            onClick={() => {
              playCyberClick();
              setActiveTab('raw');
            }}
            className={`forensic-tab-btn ${activeTab === 'raw' ? 'active' : ''}`}
          >
            <span>📄 RAW BUFFER</span>
          </button>

          <button
            onClick={(e) => copyLog(event.raw_log || JSON.stringify(event, null, 2), globalIndex)}
            className={`cyber-copy-btn ${copiedId === globalIndex ? 'copied' : ''}`}
            style={{ padding: '5px 12px', fontSize: '0.75rem', fontFamily: 'var(--font-tech)', fontWeight: 700, letterSpacing: '0.06em' }}
          >
            {copiedId === globalIndex ? '✓ COPIED' : '📋 COPY RAW'}
          </button>
        </div>
      </div>

      {/* ── Content View ─────────────────────────────────────────────────── */}
      <div style={{ padding: '18px 20px' }}>
        {/* TAB 1: FORENSIC ANALYSIS */}
        {activeTab === 'analysis' && (
          <div>
            {/* Event Name & Headline Banner */}
            <div className="forensic-headline-banner">
              <div className="forensic-headline-title">
                {exp.event_name}
              </div>

              {/* Forensic Badges Ribbon */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span className="forensic-badge-tag">
                  <span className="badge-label" style={{ color: 'var(--accent-cyan)' }}>EVENT ID:</span>
                  <span className="badge-val">{exp.event_id}</span>
                </span>

                <span className="forensic-badge-tag">
                  <span className="badge-label" style={{ color: '#c084fc' }}>SUBSYSTEM:</span>
                  <span className="badge-val" style={{ color: '#e9d5ff' }}>{exp.subsystem}</span>
                </span>

                <span className="forensic-badge-tag">
                  <span className="badge-label" style={{ color: '#94a3b8' }}>USER:</span>
                  <span className="badge-val">{exp.user}</span>
                </span>

                {exp.process && exp.process !== 'N/A' && (
                  <span className="forensic-badge-tag">
                    <span className="badge-label" style={{ color: '#00ff88' }}>PROC:</span>
                    <span className="badge-val" style={{ color: '#00ff88' }}>{exp.process}</span>
                  </span>
                )}

                {exp.ip_address && exp.ip_address !== 'N/A' && (
                  <span className="forensic-badge-tag">
                    <span className="badge-label" style={{ color: 'var(--accent-cyan)' }}>IP:</span>
                    <span className="badge-val" style={{ color: 'var(--accent-cyan)' }}>{exp.ip_address}</span>
                  </span>
                )}
              </div>
            </div>

            {/* Plain English Summary Box */}
            <div className="forensic-summary-box">
              <div className="forensic-summary-tag">
                <span>⚡</span>
                <span>[ WHAT HAPPENED // PLAIN-ENGLISH SUMMARY ]</span>
              </div>
              <div className="forensic-summary-prose">
                {formatStepContent(exp.summary)}
              </div>
            </div>

            {/* 2-Column Forensic Breakdown */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
                gap: 16,
                marginBottom: 18,
              }}
            >
              {/* Left Column: Subsystem Mechanics & Threat Analysis */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* OS Mechanics */}
                <div className="forensic-panel">
                  <div className="forensic-section-header" style={{ color: '#00f2fe' }}>
                    <span>⚙️</span>
                    <span>SUBSYSTEM & OS KERNEL MECHANICS</span>
                  </div>
                  <div className="forensic-prose">
                    {formatStepContent(exp.technical_mechanics)}
                  </div>
                </div>

                {/* Threat & Weaponization Perspective */}
                <div className="forensic-panel forensic-panel-threat">
                  <div className="forensic-section-header" style={{ color: '#ff5e00' }}>
                    <span>🛡️</span>
                    <span>THREAT & ADVERSARY WEAPONIZATION PERSPECTIVE</span>
                  </div>
                  <div className="forensic-prose">
                    {formatStepContent(exp.threat_perspective)}
                  </div>
                </div>

                {/* MITRE ATT&CK Mapping */}
                {exp.mitre_details && exp.mitre_details.technique !== 'N/A' && (
                  <div
                    className="forensic-panel"
                    style={{
                      background: 'rgba(168, 85, 247, 0.08)',
                      borderColor: 'rgba(168, 85, 247, 0.3)',
                    }}
                  >
                    <div className="forensic-section-header" style={{ color: '#c084fc' }}>
                      <span>🎯</span>
                      <span>MITRE ATT&CK MAPPING</span>
                    </div>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
                      <span
                        style={{
                          background: 'rgba(168, 85, 247, 0.22)',
                          border: '1px solid rgba(168, 85, 247, 0.45)',
                          color: '#f3e8ff',
                          padding: '3px 8px',
                          borderRadius: 3,
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                        }}
                      >
                        {exp.mitre_details.technique}
                      </span>
                      <span
                        style={{
                          background: 'rgba(255, 255, 255, 0.06)',
                          border: '1px solid rgba(255, 255, 255, 0.14)',
                          color: '#cbd5e1',
                          padding: '3px 8px',
                          borderRadius: 3,
                          fontFamily: 'var(--font-tech)',
                          fontSize: '0.74rem',
                          fontWeight: 600,
                          letterSpacing: '0.04em',
                          textTransform: 'uppercase',
                        }}
                      >
                        TACTIC: {exp.mitre_details.tactic}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: '0.82rem',
                        fontFamily: 'var(--font-sans)',
                        color: '#d8b4fe',
                        lineHeight: 1.55,
                      }}
                    >
                      {exp.mitre_details.description}
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: SOC Playbook & Artifacts */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* SOC Checklist */}
                <div className="forensic-panel forensic-panel-playbook">
                  <div className="forensic-section-header" style={{ color: '#00ff88' }}>
                    <span>📋</span>
                    <span>FORENSIC INVESTIGATION PLAYBOOK (SOC ACTIONS)</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {(exp.investigation_steps || []).map((step, sIdx) => (
                      <div key={sIdx} className="forensic-playbook-item">
                        <span className="forensic-step-num">
                          {sIdx + 1}.
                        </span>
                        <span className="forensic-step-text">
                          {formatStepContent(step)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Key Artifacts to Check */}
                <div className="forensic-panel">
                  <div className="forensic-section-header" style={{ color: '#00f2fe' }}>
                    <span>📁</span>
                    <span>KEY FORENSIC ARTIFACTS & PATHS TO CORRELATE</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {(exp.artifacts_to_check || []).map((art, aIdx) => (
                      <div
                        key={aIdx}
                        className="forensic-artifact-row"
                        onClick={(e) => handleCopyArtifact(e, art)}
                        title="Click to copy path to clipboard"
                      >
                        <span className="forensic-artifact-path">
                          {art}
                        </span>
                        <span className="forensic-artifact-copy" style={{ color: copiedArtifact === art ? '#00ff88' : '#00f2fe' }}>
                          {copiedArtifact === art ? '✓ COPIED' : 'COPY'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Launch AI Deep Dive Prompt Banner */}
            <div className="forensic-ai-banner-box">
              <div>
                <div
                  style={{
                    fontFamily: 'var(--font-tech)',
                    fontSize: '1.05rem',
                    letterSpacing: '0.06em',
                    color: '#ffffff',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                  }}
                >
                  ⚡ NEED DEEPER AUTONOMOUS INVESTIGATION?
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-sans)',
                    fontSize: '0.84rem',
                    color: '#e2e8f0',
                    marginTop: 3,
                    lineHeight: 1.5,
                  }}
                >
                  Generate a complete AI incident report with Google Gemini 3.5 Flash for root-cause and adversary tradecraft.
                </div>
              </div>

              <button
                onClick={handleRunAiAnalysis}
                className="forensic-ai-btn"
              >
                <span>{exp.ai_explanation ? 'VIEW GEMINI REPORT ▶' : '⚡ RUN GEMINI AI INVESTIGATION'}</span>
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
                  padding: '44px 20px',
                  textAlign: 'center',
                  background: 'rgba(5, 12, 32, 0.6)',
                  borderRadius: 4,
                  border: '1px solid rgba(168, 85, 247, 0.25)',
                }}
              >
                <div className="spinner" style={{ margin: '0 auto 16px' }} />
                <div
                  style={{
                    fontFamily: 'var(--font-tech)',
                    color: '#c084fc',
                    letterSpacing: '0.08em',
                    fontSize: '1.15rem',
                    fontWeight: 700,
                  }}
                >
                  QUERYING GEMINI NEURAL REASONING CORE...
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-sans)',
                    color: '#94a3b8',
                    fontSize: '0.84rem',
                    marginTop: 8,
                    lineHeight: 1.5,
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
                    paddingBottom: 10,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span
                      style={{
                        background: 'rgba(168, 85, 247, 0.2)',
                        border: '1px solid #a855f7',
                        color: '#f3e8ff',
                        padding: '3px 10px',
                        borderRadius: 3,
                        fontFamily: 'var(--font-tech)',
                        fontSize: '0.78rem',
                        fontWeight: 700,
                        letterSpacing: '0.06em',
                      }}
                    >
                      AI ENGINE: GEMINI 3.5 FLASH
                    </span>
                    <span style={{ fontSize: '0.76rem', color: '#94a3b8', fontFamily: 'var(--font-tech)', fontWeight: 600, letterSpacing: '0.04em' }}>
                      [ AUTONOMOUS DFIR REPORT ]
                    </span>
                  </div>

                  <button
                    onClick={handleRunAiAnalysis}
                    style={{
                      background: 'rgba(255,255,255,0.06)',
                      border: '1px solid rgba(255,255,255,0.18)',
                      color: '#f8fafc',
                      padding: '4px 12px',
                      borderRadius: 3,
                      fontFamily: 'var(--font-tech)',
                      fontSize: '0.76rem',
                      fontWeight: 700,
                      letterSpacing: '0.06em',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    ↻ RE-ANALYZE
                  </button>
                </div>

                <div
                  style={{
                    background: 'rgba(3, 8, 22, 0.95)',
                    border: '1px solid rgba(168, 85, 247, 0.25)',
                    borderRadius: 4,
                    padding: '20px 24px',
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
                  padding: '44px 24px',
                  textAlign: 'center',
                  background: 'rgba(5, 12, 32, 0.6)',
                  border: '1px dashed rgba(168, 85, 247, 0.35)',
                  borderRadius: 4,
                }}
              >
                <div style={{ fontSize: '2.4rem', marginBottom: 12 }}>🤖</div>
                <div
                  style={{
                    fontFamily: 'var(--font-tech)',
                    fontSize: '1.25rem',
                    letterSpacing: '0.06em',
                    color: '#ffffff',
                    fontWeight: 700,
                    marginBottom: 8,
                  }}
                >
                  AUTONOMOUS GEMINI DFIR INVESTIGATION
                </div>
                <p
                  style={{
                    fontFamily: 'var(--font-sans)',
                    fontSize: '0.86rem',
                    color: '#cbd5e1',
                    maxWidth: 540,
                    margin: '0 auto 20px',
                    lineHeight: 1.6,
                  }}
                >
                  Ask Google Gemini 3.5 Flash to generate a specialized incident response briefing, analyzing root-cause mechanics, potential evasions, and concrete triage steps.
                </p>
                <button
                  onClick={handleRunAiAnalysis}
                  className="forensic-ai-btn"
                  style={{ margin: '0 auto' }}
                >
                  <span>⚡ INITIALIZE GEMINI AI INVESTIGATION</span>
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
                marginBottom: 10,
              }}
            >
              <span
                style={{
                  fontSize: '0.76rem',
                  color: 'var(--accent-cyan)',
                  fontFamily: 'var(--font-tech)',
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                }}
              >
                DECODED RAW TELEMETRY PAYLOAD
              </span>
              <button
                onClick={(e) => copyLog(event.raw_log || JSON.stringify(event, null, 2), globalIndex)}
                className={`cyber-copy-btn ${copiedId === globalIndex ? 'copied' : ''}`}
                style={{ fontFamily: 'var(--font-tech)', fontSize: '0.76rem', fontWeight: 700, letterSpacing: '0.06em' }}
              >
                {copiedId === globalIndex ? '✓ BUFFER COPIED' : '📋 COPY RAW PAYLOAD'}
              </button>
            </div>

            <pre
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.78rem',
                color: '#cbd5e1',
                background: 'rgba(2, 4, 12, 0.95)',
                border: '1px solid rgba(0, 242, 255, 0.2)',
                borderRadius: 3,
                padding: '14px 16px',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                margin: '0 0 16px 0',
                lineHeight: 1.6,
                maxHeight: 280,
              }}
            >
              {event.raw_log || JSON.stringify(event, null, 2)}
            </pre>

            {/* Parsed JSON Metadata */}
            <div
              style={{
                background: 'rgba(4, 9, 24, 0.8)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: 3,
                padding: '12px 16px',
              }}
            >
              <div
                style={{
                  fontSize: '0.72rem',
                  fontFamily: 'var(--font-tech)',
                  color: '#94a3b8',
                  letterSpacing: '0.08em',
                  fontWeight: 700,
                  marginBottom: 8,
                  textTransform: 'uppercase',
                }}
              >
                PARSED EVENT OBJECT SCHEMA
              </div>
              <pre
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.72rem',
                  color: '#94a3b8',
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  lineHeight: 1.5,
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
