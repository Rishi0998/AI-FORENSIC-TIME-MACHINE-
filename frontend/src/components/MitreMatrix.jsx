import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { getMitreMatrix } from '../api';
import { playCyberClick, playTargetLock, playThreatAlert, playWarpEffect } from '../cyberAudio';
import CyberGlitchText from './CyberGlitchText';

export default function MitreMatrix({ sessionId }) {
  const [matrixData, setMatrixData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState('all'); // 'all' | 'detected' | 'critical'
  const [copiedSigma, setCopiedSigma] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [isDemoMode, setIsDemoMode] = useState(false);
  const navigate = useNavigate();

  const fetchMatrix = (forceDemo = false) => {
    setLoading(true);
    getMitreMatrix(sessionId, forceDemo)
      .then((data) => {
        setMatrixData(data);
        setIsDemoMode(data?.summary?.is_demo || forceDemo);
        setLoading(false);
        // Pre-select first detected technique if available
        if (data?.tactics) {
          for (const tac of data.tactics) {
            const detected = tac.techniques.find((t) => t.is_detected);
            if (detected) {
              setSelectedTechnique({ ...detected, tacticName: tac.name, tacticId: tac.id });
              break;
            }
          }
        }
      })
      .catch((err) => {
        console.error('Failed to fetch MITRE matrix:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchMatrix(false);
  }, [sessionId]);

  const handleLoadDemo = () => {
    playWarpEffect();
    fetchMatrix(true);
  };

  const handleCopySigma = (yaml) => {
    playCyberClick();
    navigator.clipboard?.writeText(yaml);
    setCopiedSigma(true);
    setTimeout(() => setCopiedSigma(false), 1600);
  };

  const handleExportBlueprint = () => {
    if (!matrixData) return;
    playCyberClick();
    const blob = new Blob([JSON.stringify(matrixData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mitre_attack_matrix_${sessionId || 'demo'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 1600);
  };

  // Filter tactics and techniques according to search & filter mode
  const filteredTactics = useMemo(() => {
    if (!matrixData?.tactics) return [];
    const query = searchQuery.toLowerCase().trim();

    return matrixData.tactics.map((tactic) => {
      const filteredTechs = tactic.techniques.filter((t) => {
        // Search filter
        const matchesSearch =
          !query ||
          t.id.toLowerCase().includes(query) ||
          t.name.toLowerCase().includes(query) ||
          (t.sub && t.sub.toLowerCase().includes(query)) ||
          (t.description && t.description.toLowerCase().includes(query));

        if (!matchesSearch) return false;

        // View filter mode
        if (filterMode === 'detected') return t.is_detected;
        if (filterMode === 'critical') return t.is_detected && (t.severity === 'critical' || t.severity === 'high');
        return true;
      });

      return {
        ...tactic,
        techniques: filteredTechs,
      };
    });
  }, [matrixData, searchQuery, filterMode]);

  const summary = matrixData?.summary || {
    total_tactics: 14,
    covered_tactics: 0,
    coverage_percentage: 0,
    total_techniques_detected: 0,
    critical_techniques: 0,
    high_techniques: 0,
    medium_techniques: 0,
    low_techniques: 0,
  };

  const getSeverityGlow = (sev, isDetected) => {
    if (!isDetected) return 'rgba(255, 255, 255, 0.04)';
    if (sev === 'critical') return 'rgba(255, 0, 85, 0.25)';
    if (sev === 'high') return 'rgba(255, 94, 0, 0.25)';
    if (sev === 'medium') return 'rgba(255, 187, 0, 0.2)';
    return 'rgba(0, 242, 254, 0.18)';
  };

  const getSeverityBorder = (sev, isDetected) => {
    if (!isDetected) return 'rgba(255, 255, 255, 0.08)';
    if (sev === 'critical') return '#ff0055';
    if (sev === 'high') return '#ff5e00';
    if (sev === 'medium') return '#ffbb00';
    return '#00f2fe';
  };

  const getSeverityBadgeColor = (sev) => {
    if (sev === 'critical') return { bg: 'rgba(255,0,85,0.2)', border: '#ff0055', text: '#ff0055' };
    if (sev === 'high') return { bg: 'rgba(255,94,0,0.2)', border: '#ff5e00', text: '#ff5e00' };
    if (sev === 'medium') return { bg: 'rgba(255,187,0,0.2)', border: '#ffbb00', text: '#ffbb00' };
    return { bg: 'rgba(0,242,254,0.15)', border: '#00f2fe', text: '#00f2fe' };
  };

  if (loading) {
    return (
      <div className="card fade-in" style={{ padding: '60px 24px', textAlign: 'center', border: '1px solid rgba(0,242,254,0.3)' }}>
        <div className="loading-state">
          <div className="spinner" style={{ width: 44, height: 44, borderColor: 'rgba(0,242,255,0.2)', borderTopColor: 'var(--accent-cyan)' }}></div>
          <div className="loading-text" style={{ fontFamily: 'var(--font-heading)', color: 'var(--accent-cyan)', letterSpacing: '0.12em', marginTop: 14 }}>
            CORRELATING ENTERPRISE MITRE ATT&CK MATRIX...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in">
      {/* ── 1. Top Tactical Metrics Banner ───────────────────────────────── */}
      <div
        className="card"
        style={{
          border: '1px solid rgba(0, 242, 254, 0.25)',
          background: 'linear-gradient(135deg, rgba(2, 6, 20, 0.95), rgba(4, 12, 32, 0.92))',
          padding: '16px 20px',
          marginBottom: 16,
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <div className="chart-scanline" />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 14, marginBottom: 16 }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--accent-cyan)', letterSpacing: '0.14em', marginBottom: 3 }}>
              [ 0xTACTICAL_FRAMEWORK // MITRE ATT&CK ENTERPRISE HEATMAP ]
            </div>
            <div style={{ fontFamily: 'var(--font-heading)', fontSize: '1.25rem', color: '#fff', letterSpacing: '0.08em', fontWeight: 700 }}>
              <CyberGlitchText text="MITRE ATT&CK® ENTERPRISE MATRIX" />
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              DYNAMIC KILL CHAIN MATRIX &bull; ADVERSARY TTP RADAR &bull; CORRELATED AGAINST AUDIT TELEMETRY
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {isDemoMode && (
              <span
                style={{
                  background: 'rgba(255, 0, 85, 0.15)',
                  border: '1px solid #ff0055',
                  color: '#ff0055',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.68rem',
                  padding: '3px 8px',
                  borderRadius: 2,
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                }}
              >
                ● APT WEAPONIZED DEMO ACTIVE
              </span>
            )}
            <button className="btn btn-sm btn-outline" onClick={handleLoadDemo} title="Load 16-stage APT29/BlackCat attack kill chain">
              <span>⚡ LOAD APT DEMO SCENARIO</span>
            </button>
            <button className="btn btn-sm btn-outline" onClick={handleExportBlueprint}>
              <span>{copiedJson ? '✓ EXPORTED' : '📥 EXPORT MATRIX JSON'}</span>
            </button>
          </div>
        </div>

        {/* Tactical Metric Cards */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: 12,
            marginTop: 8,
          }}
        >
          {/* Card 1: Coverage */}
          <div
            style={{
              background: 'rgba(5, 12, 32, 0.7)',
              border: '1px solid rgba(0, 242, 255, 0.2)',
              borderRadius: 3,
              padding: '10px 14px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.66rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              <span>KILL CHAIN COVERAGE</span>
              <span style={{ color: 'var(--accent-cyan)' }}>{summary.coverage_percentage}%</span>
            </div>
            <div style={{ fontSize: '1.35rem', fontFamily: 'var(--font-heading)', color: '#00f2fe', fontWeight: 700, margin: '2px 0 6px' }}>
              {summary.covered_tactics} / {summary.total_tactics} TACTICS
            </div>
            <div style={{ width: '100%', height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, overflow: 'hidden' }}>
              <div
                style={{
                  width: `${summary.coverage_percentage}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #00f2fe, #ff0055)',
                  boxShadow: '0 0 8px rgba(0,242,254,0.6)',
                  transition: 'width 0.4s ease',
                }}
              />
            </div>
          </div>

          {/* Card 2: Techniques Detected */}
          <div
            style={{
              background: 'rgba(5, 12, 32, 0.7)',
              border: '1px solid rgba(168, 85, 247, 0.25)',
              borderRadius: 3,
              padding: '10px 14px',
            }}
          >
            <div style={{ fontSize: '0.66rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              ACTIVE TECHNIQUES OBSERVED
            </div>
            <div style={{ fontSize: '1.35rem', fontFamily: 'var(--font-heading)', color: '#c084fc', fontWeight: 700, margin: '2px 0' }}>
              {summary.total_techniques_detected} TECHNIQUES
            </div>
            <div style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              Mapped from {summary.total_events_analyzed} incident events
            </div>
          </div>

          {/* Card 3: Threat Severity Breakdown */}
          <div
            style={{
              background: 'rgba(5, 12, 32, 0.7)',
              border: '1px solid rgba(255, 0, 85, 0.25)',
              borderRadius: 3,
              padding: '10px 14px',
            }}
          >
            <div style={{ fontSize: '0.66rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              HIGH-VOLTAGE THREAT RADAR
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '4px 0' }}>
              <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#ff0055', fontWeight: 700 }}>
                {summary.critical_techniques} CRITICAL
              </span>
              <span style={{ color: 'var(--border-secondary)' }}>&bull;</span>
              <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#ff5e00', fontWeight: 700 }}>
                {summary.high_techniques} HIGH
              </span>
              <span style={{ color: 'var(--border-secondary)' }}>&bull;</span>
              <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#ffbb00' }}>
                {summary.medium_techniques} MED
              </span>
            </div>
            <div style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              {summary.critical_techniques + summary.high_techniques > 0 ? '⚠️ Weaponized intrusion signatures active' : '✓ Normal operational baseline'}
            </div>
          </div>
        </div>
      </div>

      {/* ── 2. Matrix Console & Filter Controls ──────────────────────────── */}
      <div className="timeline-terminal-console" style={{ marginBottom: 16 }}>
        <div className="terminal-prompt-bar">
          <div className="terminal-prompt-label">
            <span className="pulse-dot" style={{ background: 'var(--accent-cyan)' }} />
            <span>MITRE://NAVIGATOR&gt;</span>
          </div>

          <div className="terminal-input-wrapper">
            <input
              type="text"
              className="terminal-search-input"
              placeholder="SEARCH BY MITRE ID (T1059), TECHNIQUE NAME, OR KEYWORD..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                className="terminal-clear-btn"
                onClick={() => {
                  playCyberClick();
                  setSearchQuery('');
                }}
              >
                ✕ CLEAR
              </button>
            )}
          </div>

          {/* Filter Pills */}
          <div className="filter-group-cyber">
            <button
              className={`filter-btn-cyber ${filterMode === 'all' ? 'active' : ''}`}
              onClick={() => {
                playCyberClick();
                setFilterMode('all');
              }}
            >
              <span>ALL TECHNIQUES</span>
            </button>
            <button
              className={`filter-btn-cyber ${filterMode === 'detected' ? 'active' : ''}`}
              onClick={() => {
                playCyberClick();
                setFilterMode('detected');
              }}
            >
              <span>DETECTED ONLY</span>
              <span className="filter-count-badge" style={{ color: 'var(--accent-cyan)' }}>
                {summary.total_techniques_detected}
              </span>
            </button>
            <button
              className={`filter-btn-cyber danger ${filterMode === 'critical' ? 'active' : ''}`}
              onClick={() => {
                playThreatAlert();
                setFilterMode('critical');
              }}
            >
              <span>CRITICAL / HIGH</span>
              <span className="filter-count-badge" style={{ color: '#ff0055' }}>
                {summary.critical_techniques + summary.high_techniques}
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* ── 3. The 14-Column MITRE Matrix Board (Horizontal Scroll) ────────── */}
      <div
        className="card"
        style={{
          border: '1px solid rgba(0, 242, 254, 0.22)',
          padding: 0,
          overflow: 'hidden',
          marginBottom: 16,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 18px',
            borderBottom: '1px solid rgba(0, 242, 254, 0.12)',
            background: 'rgba(3, 8, 24, 0.95)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontFamily: 'var(--font-heading)', color: '#fff', fontSize: '0.9rem', letterSpacing: '0.06em', fontWeight: 700 }}>
              ENTERPRISE ATT&CK TACTICAL SPECTRUM
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
              (14 KILL CHAIN PHASES)
            </span>
          </div>

          {/* Visual Legend */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: '#ff0055' }}>
              <span style={{ width: 8, height: 8, background: '#ff0055', borderRadius: 1 }} />
              CRITICAL
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: '#ff5e00' }}>
              <span style={{ width: 8, height: 8, background: '#ff5e00', borderRadius: 1 }} />
              HIGH
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: '#ffbb00' }}>
              <span style={{ width: 8, height: 8, background: '#ffbb00', borderRadius: 1 }} />
              MEDIUM
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: '#00f2fe' }}>
              <span style={{ width: 8, height: 8, background: '#00f2fe', borderRadius: 1 }} />
              LOW
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              <span style={{ width: 8, height: 8, background: 'rgba(255,255,255,0.15)', borderRadius: 1 }} />
              STANDBY
            </div>
          </div>
        </div>

        {/* Horizontal Columns Container */}
        <div
          style={{
            display: 'flex',
            overflowX: 'auto',
            padding: '14px 16px',
            gap: 12,
            background: 'rgba(1, 4, 14, 0.98)',
            minHeight: 420,
          }}
        >
          {filteredTactics.map((tac) => {
            const hasMatches = tac.techniques.length > 0;
            return (
              <div
                key={tac.id}
                style={{
                  minWidth: 210,
                  maxWidth: 230,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                {/* Column Header */}
                <div
                  style={{
                    background: tac.has_detections ? 'rgba(0, 242, 255, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                    border: `1px solid ${tac.has_detections ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.1)'}`,
                    borderRadius: 3,
                    padding: '8px 10px',
                    boxShadow: tac.has_detections ? '0 0 12px rgba(0, 242, 255, 0.2)' : 'none',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: tac.has_detections ? 'var(--accent-cyan)' : 'var(--text-muted)' }}>
                      {tac.id}
                    </span>
                    <span
                      style={{
                        background: tac.has_detections ? 'rgba(0, 242, 255, 0.25)' : 'rgba(255, 255, 255, 0.06)',
                        color: tac.has_detections ? '#fff' : 'var(--text-muted)',
                        padding: '1px 5px',
                        borderRadius: 2,
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.58rem',
                        fontWeight: 700,
                      }}
                    >
                      {tac.detected_techniques} / {tac.total_techniques}
                    </span>
                  </div>
                  <div
                    style={{
                      fontFamily: 'var(--font-heading)',
                      fontSize: '0.8rem',
                      letterSpacing: '0.04em',
                      color: tac.has_detections ? '#fff' : 'var(--text-secondary)',
                      fontWeight: 700,
                      marginTop: 2,
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                    title={tac.name}
                  >
                    {tac.name}
                  </div>
                </div>

                {/* Column Technique Cards */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {!hasMatches && (
                    <div
                      style={{
                        padding: 14,
                        textAlign: 'center',
                        fontSize: '0.68rem',
                        color: 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)',
                        border: '1px dashed rgba(255,255,255,0.06)',
                        borderRadius: 2,
                      }}
                    >
                      NO MATCHING TECHNIQUES
                    </div>
                  )}

                  {tac.techniques.map((t) => {
                    const isSelected = selectedTechnique?.id === t.id && selectedTechnique?.tacticId === tac.id;
                    const glowBg = getSeverityGlow(t.severity, t.is_detected);
                    const borderColor = getSeverityBorder(t.severity, t.is_detected);

                    return (
                      <div
                        key={t.id}
                        onClick={() => {
                          playTargetLock();
                          setSelectedTechnique({ ...t, tacticName: tac.name, tacticId: tac.id });
                        }}
                        style={{
                          background: isSelected ? 'rgba(0, 242, 255, 0.2)' : glowBg,
                          border: `1px solid ${isSelected ? '#00f2fe' : borderColor}`,
                          borderRadius: 3,
                          padding: '8px 10px',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                          transform: isSelected ? 'scale(1.02)' : 'none',
                          boxShadow: isSelected
                            ? '0 0 16px rgba(0, 242, 255, 0.5)'
                            : t.is_detected && t.severity === 'critical'
                            ? '0 0 12px rgba(255, 0, 85, 0.35)'
                            : 'none',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.62rem',
                              fontWeight: 700,
                              color: t.is_detected ? (t.severity === 'critical' ? '#ff0055' : t.severity === 'high' ? '#ff5e00' : '#00f2fe') : '#64748b',
                            }}
                          >
                            {t.id}
                          </span>

                          {t.is_detected && (
                            <span
                              style={{
                                background: t.severity === 'critical' ? 'rgba(255,0,85,0.3)' : 'rgba(0,242,254,0.2)',
                                color: t.severity === 'critical' ? '#ff0055' : 'var(--accent-cyan)',
                                padding: '1px 4px',
                                borderRadius: 2,
                                fontSize: '0.55rem',
                                fontFamily: 'var(--font-mono)',
                                fontWeight: 700,
                              }}
                            >
                              {t.event_count} PKT
                            </span>
                          )}
                        </div>

                        <div
                          style={{
                            fontFamily: 'var(--font-heading)',
                            fontSize: '0.74rem',
                            color: t.is_detected ? '#fff' : 'var(--text-secondary)',
                            fontWeight: 600,
                            lineHeight: 1.25,
                            marginBottom: 2,
                          }}
                        >
                          {t.name}
                        </div>

                        {t.sub && (
                          <div
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.58rem',
                              color: t.is_detected ? 'rgba(255,255,255,0.7)' : 'var(--text-muted)',
                              whiteSpace: 'nowrap',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                            }}
                            title={t.sub}
                          >
                            {t.sub}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── 4. Deep Tactical Inspection Drawer (Selected Technique) ───────── */}
      {selectedTechnique && (
        <div
          className="card fade-in"
          style={{
            border: `1px solid ${getSeverityBorder(selectedTechnique.severity, selectedTechnique.is_detected)}`,
            background: 'rgba(3, 8, 22, 0.98)',
            boxShadow: '0 8px 32px rgba(0,0,0,0.85)',
            padding: '18px 22px',
          }}
        >
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 14, borderBottom: '1px solid rgba(0, 242, 254, 0.15)', paddingBottom: 10 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span
                  style={{
                    background: 'rgba(0, 242, 255, 0.15)',
                    border: '1px solid #00f2fe',
                    color: '#00f2fe',
                    padding: '2px 8px',
                    borderRadius: 2,
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.72rem',
                    fontWeight: 700,
                  }}
                >
                  {selectedTechnique.id}
                </span>

                <span
                  style={{
                    background: 'rgba(168, 85, 247, 0.15)',
                    border: '1px solid #a855f7',
                    color: '#c084fc',
                    padding: '2px 8px',
                    borderRadius: 2,
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.72rem',
                  }}
                >
                  TACTIC: {selectedTechnique.tacticName} ({selectedTechnique.tacticId})
                </span>

                {selectedTechnique.is_detected && (
                  <span
                    style={{
                      background: getSeverityBadgeColor(selectedTechnique.severity).bg,
                      border: `1px solid ${getSeverityBadgeColor(selectedTechnique.severity).border}`,
                      color: getSeverityBadgeColor(selectedTechnique.severity).text,
                      padding: '2px 8px',
                      borderRadius: 2,
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                    }}
                  >
                    STATUS: {selectedTechnique.severity.toUpperCase()} DETECTED ({selectedTechnique.event_count} EVENTS)
                  </span>
                )}
              </div>

              <h2 style={{ fontFamily: 'var(--font-heading)', color: '#fff', fontSize: '1.2rem', letterSpacing: '0.06em', margin: 0, fontWeight: 700 }}>
                {selectedTechnique.name} {selectedTechnique.sub && `// ${selectedTechnique.sub}`}
              </h2>
            </div>

            {/* Quick Action Navigation Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <button
                className="btn btn-sm btn-primary"
                onClick={() => {
                  playCyberClick();
                  navigate('/app/timeline');
                }}
                title="Filter timeline by this technique"
              >
                <span>🔍 ISOLATE IN TIMELINE</span>
              </button>

              <button
                className="btn btn-sm btn-outline"
                onClick={() => {
                  playCyberClick();
                  navigate('/app/graph');
                }}
                title="Highlight correlated nodes on topological attack graph"
              >
                <span>🕸️ LOCATE ON ATTACK GRAPH</span>
              </button>

              <a
                href={selectedTechnique.url}
                target="_blank"
                rel="noreferrer"
                className="btn btn-sm btn-ghost"
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}
              >
                MITRE DOCS ↗
              </a>
            </div>
          </div>

          {/* Description & Tradecraft Mechanics */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontFamily: 'var(--font-heading)', color: 'var(--accent-cyan)', fontSize: '0.78rem', letterSpacing: '0.08em', fontWeight: 700, marginBottom: 4 }}>
              [ ADVERSARY TRADECRAFT & MECHANICS ]
            </div>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#cbd5e1', lineHeight: 1.6, margin: 0 }}>
              {selectedTechnique.description}
            </p>
          </div>

          {/* Correlated Event Logs Sample */}
          {selectedTechnique.events_sample && selectedTechnique.events_sample.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: 'var(--font-heading)', color: '#ffbb00', fontSize: '0.78rem', letterSpacing: '0.08em', fontWeight: 700, marginBottom: 6 }}>
                [ MATCHING AUDIT TELEMETRY ({selectedTechnique.events_sample.length} SAMPLES) ]
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
                {selectedTechnique.events_sample.map((ev, evIdx) => (
                  <div
                    key={evIdx}
                    style={{
                      background: 'rgba(5, 12, 32, 0.8)',
                      border: '1px solid rgba(0, 242, 255, 0.12)',
                      padding: '6px 10px',
                      borderRadius: 2,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      fontSize: '0.7rem',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    <span style={{ color: 'var(--accent-cyan)', minWidth: 64 }}>{ev.timestamp.split('T')[1]?.substring(0, 8) || ev.timestamp}</span>
                    <span style={{ color: '#fff', fontWeight: 600 }}>{ev.action}</span>
                    {ev.user && <span style={{ color: 'var(--text-secondary)' }}>USER:{ev.user}</span>}
                    {ev.process && <span style={{ color: '#00ff88' }}>PROC:{ev.process}</span>}
                    <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 280 }}>
                      {ev.raw_log}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Automated Sigma Defense Rule Synthesizer */}
          {selectedTechnique.sigma_rule && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontFamily: 'var(--font-heading)', color: '#c084fc', fontSize: '0.78rem', letterSpacing: '0.08em', fontWeight: 700 }}>
                  [ AUTO-SYNTHESIZED SIGMA DETECTION RULE // SIEM ASSET ]
                </span>
                <button
                  onClick={() => handleCopySigma(selectedTechnique.sigma_rule)}
                  className={`cyber-copy-btn ${copiedSigma ? 'copied' : ''}`}
                >
                  {copiedSigma ? '✓ SIGMA RULE COPIED' : '📋 COPY SIGMA YAML'}
                </button>
              </div>

              <pre
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.72rem',
                  color: '#94a3b8',
                  background: 'rgba(1, 4, 12, 0.95)',
                  border: '1px solid rgba(168, 85, 247, 0.3)',
                  borderRadius: 2,
                  padding: '12px 14px',
                  margin: 0,
                  overflowX: 'auto',
                  lineHeight: 1.5,
                  maxHeight: 200,
                }}
              >
                {selectedTechnique.sigma_rule}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

