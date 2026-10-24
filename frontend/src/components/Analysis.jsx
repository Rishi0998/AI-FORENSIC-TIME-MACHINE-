import { useState, useEffect } from 'react';
import { getAnalysis } from '../api';

export default function Analysis({ sessionId }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    getAnalysis(sessionId).then(data => {
      setAnalysis(data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [sessionId]);

  if (loading) {
    return <div className="card"><div className="loading-state"><div className="spinner"></div><div className="loading-text">Generating analysis...</div></div></div>;
  }

  if (!analysis) {
    return <div className="card"><div className="empty-state"><h3>No analysis available</h3></div></div>;
  }

  const renderExplanation = (text) => {
    if (!text) return null;
    return text.split('\n').map((line, i) => {
      if (line.startsWith('## ')) return <h2 key={i}>{line.replace('## ', '').replace(/[^\w\s\-—().,/:]/g, '')}</h2>;
      if (line.startsWith('### ')) return <h3 key={i}>{line.replace('### ', '')}</h3>;
      if (line.startsWith('**') && line.endsWith('**')) return <p key={i}><strong>{line.replace(/\*\*/g, '')}</strong></p>;
      if (line.startsWith('- ')) return <li key={i}>{renderInline(line.substring(2))}</li>;
      if (line.match(/^\d+\.\s/)) return <li key={i}>{renderInline(line.replace(/^\d+\.\s/, ''))}</li>;
      if (line.trim() === '') return <br key={i} />;
      return <p key={i}>{renderInline(line)}</p>;
    });
  };

  const renderInline = (text) => {
    const parts = text.split(/(\*\*[^*]+\*\*)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) return <strong key={i}>{part.replace(/\*\*/g, '')}</strong>;
      return part;
    });
  };

  const riskDescriptions = {
    critical: 'Immediate action required — active attack detected',
    high: 'High risk — significant suspicious activity detected',
    medium: 'Elevated risk — anomalous behavior detected',
    low: 'Low risk — minimal suspicious activity',
  };

  return (
    <div className="fade-in">
      {/* Risk Overview */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Risk Assessment</div>
          <span className={`badge badge-${analysis.risk_level}`}>{analysis.risk_level?.toUpperCase()}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: analysis.risk_score >= 75 ? 'var(--accent-red)' : analysis.risk_score >= 40 ? 'var(--accent-amber)' : 'var(--accent-green)' }}>
              {analysis.risk_score}
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</div>
          </div>
          <div style={{ flex: 1 }}>
            <div className="risk-bar">
              <div className={`risk-bar-fill ${analysis.risk_level}`} style={{ width: `${analysis.risk_score}%` }}></div>
            </div>
            <div style={{ marginTop: 6, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              {riskDescriptions[analysis.risk_level] || ''}
            </div>
          </div>
        </div>
      </div>

      {/* Attack Kill Chain */}
      {analysis.chains?.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Attack Kill Chain</div>
          </div>
          <div className="killchain">
            {analysis.chains.map((chain, i) => (
              <div key={i} style={{ display: 'contents' }}>
                <div className="killchain-phase">
                  <div className="phase-num">Phase {i + 1}</div>
                  <div className="phase-name">{chain.chain_name}</div>
                  <span className={`badge badge-${chain.severity}`}>{chain.severity}</span>
                  {chain.mitre_tactic && <div className="mitre-tag" style={{ marginTop: 6 }}>{chain.mitre_tactic}</div>}
                </div>
                {i < analysis.chains.length - 1 && <div className="killchain-arrow">&rarr;</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Report */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Incident Analysis Report</div>
          <span className="badge badge-info">Engine: {analysis.model_used || 'rule-based'}</span>
        </div>
        <div className="report-content">
          {renderExplanation(analysis.explanation)}
        </div>
      </div>
    </div>
  );
}
