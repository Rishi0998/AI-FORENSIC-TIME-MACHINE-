import { useState, useEffect } from 'react';
import { getAnalysis } from '../api';
import { playCyberClick, playRadarPing } from '../cyberAudio';

export default function Analysis({ sessionId }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    getAnalysis(sessionId).then(data => {
      setAnalysis(data);
      setLoading(false);
      if (data.risk_score >= 70) {
        playRadarPing();
      }
    }).catch(() => setLoading(false));
  }, [sessionId]);

  if (loading) {
    return (
      <div className="card fade-in" style={{ padding: '60px 24px', textAlign: 'center' }}>
        <div className="loading-state">
          <div className="spinner" style={{ width: 44, height: 44, borderColor: 'rgba(0,242,255,0.2)', borderTopColor: 'var(--accent-cyan)' }}></div>
          <div className="loading-text" style={{ fontFamily: 'var(--font-heading)', color: 'var(--accent-cyan)', letterSpacing: '0.1em' }}>
            SYNTHESIZING DEEP THREAT INTELLIGENCE MATRIX...
          </div>
        </div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="card fade-in">
        <div className="empty-state">
          <h3 style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', color: 'var(--text-primary)' }}>NO THREAT ANALYSIS ARTIFACTS</h3>
          <p>Ingest log files or stream live host telemetry to generate AI forensic intelligence.</p>
        </div>
      </div>
    );
  }

  const renderExplanation = (text) => {
    if (!text) return null;
    return text.split('\n').map((line, i) => {
      if (line.startsWith('## ')) return (
        <h2 key={i} style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', color: 'var(--accent-cyan)', borderBottom: '1px solid rgba(0,242,255,0.2)', paddingBottom: 6, marginTop: 20, fontSize: '1.05rem' }}>
          {line.replace('## ', '').replace(/[^\w\s\-—().,/:]/g, '')}
        </h2>
      );
      if (line.startsWith('### ')) return (
        <h3 key={i} style={{ fontFamily: 'var(--font-heading)', color: '#fff', marginTop: 14, fontSize: '0.92rem' }}>
          {line.replace('### ', '')}
        </h3>
      );
      if (line.startsWith('**') && line.endsWith('**')) return (
        <p key={i} style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.84rem' }}>
          <strong>{line.replace(/\*\*/g, '')}</strong>
        </p>
      );
      if (line.startsWith('- ')) return (
        <li key={i} style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', marginBottom: 4, lineHeight: 1.5 }}>
          {renderInline(line.substring(2))}
        </li>
      );
      if (line.match(/^\d+\.\s/)) return (
        <li key={i} style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', marginBottom: 4, lineHeight: 1.5 }}>
          {renderInline(line.replace(/^\d+\.\s/, ''))}
        </li>
      );
      if (line.trim() === '') return <div key={i} style={{ height: 8 }} />;
      return (
        <p key={i} style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', lineHeight: 1.6, margin: '6px 0' }}>
          {renderInline(line)}
        </p>
      );
    });
  };

  const renderInline = (text) => {
    const parts = text.split(/(\*\*[^*]+\*\*)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) return <strong key={i} style={{ color: '#fff' }}>{part.replace(/\*\*/g, '')}</strong>;
      return part;
    });
  };

  const riskDescriptions = {
    critical: 'CRITICAL HAZARD — Active adversarial breach or exfiltration confirmed.',
    high: 'ELEVATED THREAT — Multi-stage unauthorized activity detected.',
    medium: 'SURVEILLANCE ADVISORY — Anomalous authentication and system behaviors.',
    low: 'NOMINAL DEFCON — Minimal suspicious anomalies detected.',
  };

  const getDefconTier = (score) => {
    if (score >= 75) return { tier: 'DEFCON 1', color: 'var(--accent-red)' };
    if (score >= 50) return { tier: 'DEFCON 2', color: 'var(--accent-amber)' };
    if (score >= 25) return { tier: 'DEFCON 3', color: '#ffea00' };
    return { tier: 'DEFCON 5', color: 'var(--accent-green)' };
  };

  const defcon = getDefconTier(analysis.risk_score || 0);

  return (
    <div className="fade-in">
      {/* ── Risk Overview HUD ────────────────────────────────────── */}
      <div className="card" style={{ position: 'relative', overflow: 'hidden' }}>
        <div className="card-header" style={{ marginBottom: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: defcon.color, boxShadow: `0 0 10px ${defcon.color}` }}></div>
              <div className="card-title" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.1em', fontSize: '1.05rem', color: '#fff' }}>
                QUANTUM ADVERSARIAL RISK EVALUATION
              </div>
            </div>
            <p style={{ margin: '4px 0 0 20px', fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              HEURISTIC THREAT CORRELATION ACROSS INGESTED ATTACK VECTORS
            </p>
          </div>
          <span className={`badge badge-${analysis.risk_level}`} style={{ fontSize: '0.72rem', letterSpacing: '0.08em' }}>
            {defcon.tier} &bull; {analysis.risk_level?.toUpperCase()}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 28, flexWrap: 'wrap', background: 'rgba(6,11,25,0.7)', padding: '20px 24px', borderRadius: '8px', border: '1px solid rgba(0,242,255,0.15)' }}>
          <div style={{ textAlign: 'center', minWidth: 100 }}>
            <div style={{ 
              fontSize: '3rem', 
              fontWeight: 800, 
              fontFamily: 'var(--font-heading)', 
              color: defcon.color,
              textShadow: `0 0 20px ${defcon.color}`,
              lineHeight: 1
            }}>
              {analysis.risk_score}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginTop: 6 }}>
              THREAT INDEX / 100
            </div>
          </div>

          <div style={{ flex: '1 1 300px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              <span>SEVERITY THRESHOLD</span>
              <span style={{ color: defcon.color }}>{defcon.tier}</span>
            </div>
            <div className="risk-bar" style={{ height: 12, background: 'rgba(255,255,255,0.06)', borderRadius: 6, overflow: 'hidden' }}>
              <div 
                className={`risk-bar-fill ${analysis.risk_level}`} 
                style={{ 
                  width: `${analysis.risk_score}%`, 
                  height: '100%',
                  background: `linear-gradient(90deg, var(--accent-cyan), ${defcon.color})`,
                  boxShadow: `0 0 12px ${defcon.color}`
                }}
              ></div>
            </div>
            <div style={{ marginTop: 8, fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              {riskDescriptions[analysis.risk_level] || ''}
            </div>
          </div>
        </div>
      </div>

      {/* ── Attack Kill Chain Conduits ──────────────────────────── */}
      {analysis.chains?.length > 0 && (
        <div className="card" style={{ position: 'relative' }}>
          <div className="card-header" style={{ marginBottom: 16 }}>
            <div>
              <div className="card-title" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.1em', fontSize: '1rem', color: '#fff' }}>
                MITRE ATT&amp;CK ADVERSARIAL KILL CHAIN
              </div>
              <p style={{ margin: '4px 0 0 0', fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                PROGRESSION SEQUENCE OF ADVERSARIAL TACTICS OBSERVED IN CHRONO BUFFER
              </p>
            </div>
          </div>

          <div className="killchain" style={{ display: 'flex', gap: 12, overflowX: 'auto', paddingBottom: 8, alignItems: 'center' }}>
            {analysis.chains.map((chain, i) => (
              <div key={i} style={{ display: 'contents' }}>
                <div 
                  className="killchain-phase" 
                  style={{
                    background: 'linear-gradient(135deg, rgba(6,11,25,0.9) 0%, rgba(138,43,226,0.1) 100%)',
                    border: '1px solid rgba(0,242,255,0.3)',
                    borderRadius: '8px',
                    padding: '14px 18px',
                    minWidth: 160,
                    textAlign: 'center',
                    boxShadow: '0 0 15px rgba(0,242,255,0.08)',
                    position: 'relative'
                  }}
                >
                  <div className="phase-num" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--accent-cyan)', letterSpacing: '0.08em', marginBottom: 4 }}>
                    PHASE 0{i + 1}
                  </div>
                  <div className="phase-name" style={{ fontFamily: 'var(--font-heading)', color: '#fff', fontSize: '0.85rem', marginBottom: 8 }}>
                    {chain.chain_name}
                  </div>
                  <span className={`badge badge-${chain.severity}`} style={{ fontSize: '0.62rem' }}>
                    {chain.severity?.toUpperCase()}
                  </span>
                  {chain.mitre_tactic && (
                    <div className="mitre-tag" style={{ marginTop: 8, fontSize: '0.62rem' }}>
                      {chain.mitre_tactic}
                    </div>
                  )}
                </div>
                {i < analysis.chains.length - 1 && (
                  <div style={{ color: 'var(--accent-cyan)', fontSize: '1.2rem', padding: '0 4px', userSelect: 'none', animation: 'pulseSlow 2s infinite' }}>
                    &rarr;
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── AI Forensic Synthesis Briefing ─────────────────────── */}
      <div className="card">
        <div className="card-header" style={{ marginBottom: 14 }}>
          <div>
            <div className="card-title" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.1em', fontSize: '1rem', color: '#fff' }}>
              DECLASSIFIED FORENSIC INCIDENT INTELLIGENCE
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              AUTOMATED ROOT-CAUSE DECONSTRUCTION &amp; REMEDIATION DIRECTIVES
            </p>
          </div>
          <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
            ENGINE: {analysis.model_used?.toUpperCase() || 'RULE-BASED CORRELATION'}
          </span>
        </div>

        <div 
          className="report-content" 
          style={{
            background: 'rgba(4,7,17,0.85)',
            border: '1px solid rgba(0,242,255,0.2)',
            borderRadius: '6px',
            padding: '20px 24px',
            fontFamily: 'var(--font-primary)'
          }}
        >
          {renderExplanation(analysis.explanation)}
        </div>
      </div>
    </div>
  );
}
