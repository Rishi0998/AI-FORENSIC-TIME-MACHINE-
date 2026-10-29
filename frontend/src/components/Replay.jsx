import { useState, useEffect, useRef } from 'react';
import { getReplay } from '../api';
import { playCyberClick, playRadarPing, playWarpEffect } from '../cyberAudio';

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
          if (prev >= steps.length - 1) { 
            setPlaying(false); 
            return prev; 
          }
          const next = prev + 1;
          const nextStep = steps[next];
          if (nextStep && (nextStep.severity === 'critical' || nextStep.severity === 'high')) {
            playRadarPing();
          } else {
            playCyberClick();
          }
          return next;
        });
      }, speed);
    }
    return () => clearInterval(intervalRef.current);
  }, [playing, speed, steps]);

  useEffect(() => {
    if (currentStep >= 0 && stepsRef.current) {
      const el = stepsRef.current.querySelector('.replay-step.active');
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [currentStep]);

  const handlePlay = () => { 
    playWarpEffect();
    if (currentStep >= steps.length - 1) setCurrentStep(-1); 
    setPlaying(true); 
  };
  const handlePause = () => {
    playCyberClick();
    setPlaying(false);
  };
  const handleReset = () => { 
    playCyberClick();
    setPlaying(false); 
    setCurrentStep(-1); 
  };
  const handleNext = () => {
    playCyberClick();
    setCurrentStep(prev => Math.min(prev + 1, steps.length - 1));
  };
  const handlePrev = () => {
    playCyberClick();
    setCurrentStep(prev => Math.max(prev - 1, -1));
  };

  const progress = steps.length > 0 ? ((currentStep + 1) / steps.length) * 100 : 0;
  const activeEvent = currentStep >= 0 ? steps[currentStep] : null;

  if (loading) return (
    <div className="card fade-in" style={{ padding: '60px 24px', textAlign: 'center' }}>
      <div className="loading-state">
        <div className="spinner" style={{ width: 42, height: 42, borderColor: 'rgba(0,242,255,0.2)', borderTopColor: 'var(--accent-cyan)' }}></div>
        <div className="loading-text" style={{ fontFamily: 'var(--font-heading)', color: 'var(--accent-cyan)', letterSpacing: '0.1em' }}>
          SYNCHRONIZING TEMPORAL INCIDENT REPLAY...
        </div>
      </div>
    </div>
  );

  if (steps.length === 0) return (
    <div className="card fade-in">
      <div className="empty-state">
        <h3 style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', color: 'var(--text-primary)' }}>NO SUSPICIOUS EVENT REPLAY BUFFER</h3>
        <p>Upload forensic logs or stream live host telemetry to engage the Chrono Time Machine.</p>
      </div>
    </div>
  );

  return (
    <div className="fade-in">
      {/* ── Chrono Replay Chamber Header & Cockpit ─────────────── */}
      <div className="card" style={{ position: 'relative', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: playing ? 'var(--accent-red)' : 'var(--accent-cyan)', boxShadow: `0 0 10px ${playing ? 'var(--accent-red)' : 'var(--accent-cyan)'}` }}></div>
              <h2 style={{ margin: 0, fontSize: '1.1rem', fontFamily: 'var(--font-heading)', letterSpacing: '0.12em', color: '#fff' }}>
                CHRONO TEMPORAL FORENSIC REPLAY
              </h2>
            </div>
            <p style={{ margin: '4px 0 0 20px', fontSize: '0.76rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              RECONSTRUCTING STEP-BY-STEP ADVERSARIAL TIMELINE &bull; {steps.length} TIME-LOCKED INCIDENT VECTORS
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
              STEP {currentStep + 1} / {steps.length}
            </span>
            <span className={`badge ${playing ? 'badge-critical' : 'badge-medium'}`}>
              {playing ? '▶ REPLAY ACTIVE' : '⏸ PAUSED'}
            </span>
          </div>
        </div>

        {/* Temporal Scrubber Control Deck */}
        <div className="replay-controls" style={{ background: 'rgba(6,11,25,0.7)', border: '1px solid rgba(0,242,255,0.2)', padding: '12px 18px', borderRadius: '8px', marginBottom: 20 }}>
          <button className="btn btn-sm btn-outline" onClick={handleReset} title="Jump to start">
            ⏮ RESET
          </button>
          <button className="btn btn-sm btn-outline" onClick={handlePrev} disabled={currentStep <= -1}>
            ◀ PREV
          </button>

          {playing ? (
            <button className="btn btn-sm btn-danger" onClick={handlePause} style={{ minWidth: 90 }}>
              ⏸ PAUSE
            </button>
          ) : (
            <button className="btn btn-sm btn-primary" onClick={handlePlay} style={{ minWidth: 90 }}>
              ▶ PLAY
            </button>
          )}

          <button className="btn btn-sm btn-outline" onClick={handleNext} disabled={currentStep >= steps.length - 1}>
            NEXT ▶
          </button>

          {/* Interactive Progress Bar */}
          <div 
            className="replay-progress" 
            style={{ flex: 1, height: 8, background: 'rgba(255,255,255,0.06)', borderRadius: 4, cursor: 'pointer', position: 'relative', overflow: 'hidden' }}
            onClick={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              const clickX = e.clientX - rect.left;
              const pct = clickX / rect.width;
              const target = Math.min(Math.floor(pct * steps.length), steps.length - 1);
              setCurrentStep(target);
              playCyberClick();
            }}
          >
            <div 
              className="replay-progress-fill" 
              style={{ 
                width: `${progress}%`, 
                height: '100%', 
                background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-red))',
                boxShadow: '0 0 10px rgba(0,242,255,0.5)',
                transition: 'width 0.15s ease-out'
              }}
            ></div>
          </div>

          <div className="replay-counter" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-cyan)', minWidth: 60, textAlign: 'right' }}>
            {Math.round(progress)}%
          </div>

          <select 
            value={speed} 
            onChange={e => { playCyberClick(); setSpeed(Number(e.target.value)); }}
            style={{ 
              background: 'rgba(4,7,17,0.9)', 
              color: 'var(--accent-cyan)', 
              border: '1px solid rgba(0,242,255,0.3)', 
              borderRadius: '4px', 
              padding: '5px 10px', 
              fontSize: '0.75rem', 
              fontFamily: 'var(--font-mono)',
              outline: 'none',
              cursor: 'pointer'
            }}
          >
            <option value={3000}>0.5x SPD</option>
            <option value={1500}>1.0x SPD</option>
            <option value={800}>2.0x SPD</option>
            <option value={400}>4.0x WARP</option>
          </select>
        </div>

        {/* ── Active Temporal Event Spotlight Hologram ──────────── */}
        {activeEvent ? (
          <div style={{
            background: 'linear-gradient(135deg, rgba(0,242,255,0.08) 0%, rgba(255,0,85,0.08) 100%)',
            border: '1px solid rgba(0,242,255,0.4)',
            borderRadius: '8px',
            padding: '16px 20px',
            marginBottom: 20,
            position: 'relative',
            boxShadow: '0 0 25px rgba(0,242,255,0.1)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10, flexWrap: 'wrap', gap: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                  EVENT #{activeEvent.step}
                </span>
                <span style={{ fontSize: '0.85rem', fontFamily: 'var(--font-heading)', letterSpacing: '0.06em', color: '#fff' }}>
                  {activeEvent.action}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`badge badge-${activeEvent.severity}`}>
                  {activeEvent.severity?.toUpperCase()}
                </span>
                {activeEvent.mitre_technique && (
                  <span className="mitre-tag">
                    {activeEvent.mitre_technique}
                  </span>
                )}
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {activeEvent.timestamp}
                </span>
              </div>
            </div>

            <p style={{ margin: '0 0 10px 0', fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {activeEvent.description}
            </p>

            <div style={{
              background: 'rgba(4,7,17,0.9)',
              border: '1px solid rgba(0,242,255,0.2)',
              borderRadius: '6px',
              padding: '10px 14px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.72rem',
              color: 'var(--accent-cyan)',
              overflowX: 'auto',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all'
            }}>
              <span style={{ color: 'var(--text-muted)', userSelect: 'none' }}>$ FORENSIC_RAW_PAYLOAD &gt; </span>
              {activeEvent.raw_log}
            </div>
          </div>
        ) : (
          <div style={{
            background: 'rgba(6,11,25,0.4)',
            border: '1px dashed rgba(255,255,255,0.1)',
            borderRadius: '8px',
            padding: '16px 20px',
            marginBottom: 20,
            textAlign: 'center',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.78rem'
          }}>
            CLICK "PLAY" OR ANY STEP BELOW TO ENGAGE TIME MACHINE SCRUBBER
          </div>
        )}

        {/* ── Scrollable Incident Step Log ──────────────────────── */}
        <div ref={stepsRef} style={{ maxHeight: 480, overflowY: 'auto', paddingRight: 4 }}>
          {steps.map((step, i) => (
            <div
              key={i}
              className={`event-row ${i === currentStep ? 'active replay-step' : ''} ${i > currentStep && currentStep !== -1 ? 'future' : ''} ${step.severity === 'critical' ? 'critical' : 'suspicious'}`}
              onClick={() => { playCyberClick(); setCurrentStep(i); setPlaying(false); }}
              style={{
                cursor: 'pointer',
                opacity: i > currentStep && currentStep !== -1 ? 0.35 : 1,
                transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                background: i === currentStep ? 'rgba(0,242,255,0.12)' : 'rgba(6,11,25,0.6)',
                borderLeft: i === currentStep ? '3px solid var(--accent-cyan)' : '3px solid transparent',
                borderRadius: '6px',
                marginBottom: 6,
                padding: '10px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: 6
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: i === currentStep ? 'var(--accent-cyan)' : 'var(--text-muted)', fontWeight: 700, minWidth: 32 }}>
                  #{step.step}
                </span>
                <span className="event-time" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  {step.timestamp?.split('T')[1]?.substring(0, 8) || step.timestamp}
                </span>
                <span style={{ fontWeight: 600, color: '#fff', fontSize: '0.8rem', fontFamily: 'var(--font-primary)' }}>
                  {step.action}
                </span>
                <span className={`badge badge-${step.severity}`} style={{ fontSize: '0.62rem' }}>
                  {step.severity}
                </span>
                {step.mitre_technique && <span className="mitre-tag" style={{ fontSize: '0.62rem' }}>{step.mitre_technique}</span>}
                {step.user && <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>USER:{step.user}</span>}
                {step.ip_address && <span style={{ color: 'var(--accent-cyan)', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>IP:{step.ip_address}</span>}
              </div>

              {i <= currentStep && currentStep !== -1 && (
                <div style={{ marginTop: 4, paddingLeft: 38 }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                    {step.description}
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)', background: 'rgba(4,7,17,0.8)', padding: '6px 10px', borderRadius: '4px', overflowX: 'auto', whiteSpace: 'nowrap' }}>
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
