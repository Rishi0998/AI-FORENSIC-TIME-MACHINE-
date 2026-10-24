import { useState, useEffect, useRef } from 'react';
import { getReplay } from '../api';

export default function Replay({ sessionId }) {
  const [steps, setSteps] = useState([]);
  const [currentStep, setCurrentStep] = useState(-1);
  const [loading, setLoading] = useState(true);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1500);
  const intervalRef = useRef(null);
  const stepsRef = useRef(null);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    getReplay(sessionId).then(data => {
      setSteps(data.steps || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => {
    if (playing) {
      intervalRef.current = setInterval(() => {
        setCurrentStep(prev => {
          if (prev >= steps.length - 1) { setPlaying(false); return prev; }
          return prev + 1;
        });
      }, speed);
    }
    return () => clearInterval(intervalRef.current);
  }, [playing, speed, steps.length]);

  useEffect(() => {
    if (currentStep >= 0 && stepsRef.current) {
      const el = stepsRef.current.querySelector('.replay-step.active');
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [currentStep]);

  const handlePlay = () => { if (currentStep >= steps.length - 1) setCurrentStep(-1); setPlaying(true); };
  const handlePause = () => setPlaying(false);
  const handleReset = () => { setPlaying(false); setCurrentStep(-1); };
  const handleNext = () => setCurrentStep(prev => Math.min(prev + 1, steps.length - 1));
  const handlePrev = () => setCurrentStep(prev => Math.max(prev - 1, -1));
  const progress = steps.length > 0 ? ((currentStep + 1) / steps.length) * 100 : 0;

  if (loading) return <div className="card"><div className="loading-state"><div className="spinner"></div><div className="loading-text">Loading replay data...</div></div></div>;
  if (steps.length === 0) return <div className="card"><div className="empty-state"><h3>No suspicious events to replay</h3><p>Upload logs with detectable threats to use forensic replay.</p></div></div>;

  return (
    <div className="fade-in">
      <div className="card">
        <div className="card-header">
          <div className="card-title">Attack Replay</div>
          <span className="card-subtitle">{steps.length} suspicious events</span>
        </div>

        <div className="replay-controls">
          <button className="btn btn-sm btn-outline" onClick={handleReset}>Reset</button>
          <button className="btn btn-sm btn-outline" onClick={handlePrev} disabled={currentStep <= -1}>Prev</button>
          {playing ? (
            <button className="btn btn-sm btn-danger" onClick={handlePause}>Pause</button>
          ) : (
            <button className="btn btn-sm btn-primary" onClick={handlePlay}>Play</button>
          )}
          <button className="btn btn-sm btn-outline" onClick={handleNext} disabled={currentStep >= steps.length - 1}>Next</button>

          <div className="replay-progress">
            <div className="replay-progress-fill" style={{ width: `${progress}%` }}></div>
          </div>

          <div className="replay-counter">{currentStep + 1} / {steps.length}</div>

          <select value={speed} onChange={e => setSpeed(Number(e.target.value))}
            style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)', border: '1px solid var(--border-secondary)', borderRadius: 'var(--radius-sm)', padding: '4px 8px', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
            <option value={3000}>0.5x</option>
            <option value={1500}>1x</option>
            <option value={800}>2x</option>
            <option value={400}>4x</option>
          </select>
        </div>

        <div ref={stepsRef} style={{ maxHeight: 550, overflowY: 'auto' }}>
          {steps.map((step, i) => (
            <div
              key={i}
              className={`event-row ${i === currentStep ? 'active replay-step' : ''} ${i > currentStep ? 'future' : ''} ${step.severity === 'critical' ? 'critical' : 'suspicious'}`}
              onClick={() => { setCurrentStep(i); setPlaying(false); }}
              style={{
                cursor: 'pointer',
                opacity: i > currentStep && currentStep !== -1 ? 0.35 : 1,
                transition: 'opacity 0.2s, background 0.15s',
                background: i === currentStep ? 'var(--accent-blue-dim)' : undefined,
                flexDirection: 'column',
                alignItems: 'stretch',
                padding: '10px 12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--accent-blue)', fontWeight: 700, minWidth: 28 }}>{step.step}</span>
                <span className="event-time">{step.timestamp?.split('T')[1]?.substring(0, 8) || step.timestamp}</span>
                <span className="event-action" style={{ fontWeight: 600 }}>{step.action}</span>
                <span className={`badge badge-${step.severity}`}>{step.severity}</span>
                {step.mitre_technique && <span className="mitre-tag">{step.mitre_technique}</span>}
                {step.user && <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem' }}>{step.user}</span>}
                {step.ip_address && <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>{step.ip_address}</span>}
              </div>
              {i <= currentStep && currentStep !== -1 && (
                <div style={{ marginTop: 6, paddingLeft: 38 }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>{step.description}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)', background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 'var(--radius-sm)', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                    {step.raw_log}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
