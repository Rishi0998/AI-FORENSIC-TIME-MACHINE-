import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { uploadLogs, extractLocalChannel } from '../api';
import { playCyberClick, playWarpEffect, playThreatAlert } from '../cyberAudio';
import CyberGlitchText from './CyberGlitchText';
import CyberReactor from './CyberReactor';

export default function Upload({ onAnalysisComplete, loading, setLoading }) {
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState(null);
  const [winChannels, setWinChannels] = useState([]);
  const [extracting, setExtracting] = useState(null);
  const [showExtract, setShowExtract] = useState(true);
  const fileInput = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Fetch available Windows log channels
    api.get('/extract-local-logs')
      .then(res => {
        setWinChannels(res.data.channels || []);
      })
      .catch(() => {});
  }, []);

  const handleFile = async (file) => {
    playWarpEffect();
    setLoading(true);
    setError(null);
    try {
      const result = await uploadLogs(file);
      onAnalysisComplete(result);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze logs');
      playThreatAlert();
    } finally {
      setLoading(false);
    }
  };

  const handleExtractWindows = async (channelId) => {
    playCyberClick();
    const channel = winChannels.find(c => c.id === channelId);
    if (!channel || !channel.available) {
      playThreatAlert();
      setError(
        channel?.needs_admin
          ? `"${channel?.name || channelId}" requires Administrator privileges. Run the backend as Admin to access Security logs.`
          : `"${channel?.name || channelId}" is not available or has no events.`
      );
      return;
    }
    setExtracting(channelId);
    setError(null);
    setLoading(true);
    playWarpEffect();
    try {
      const result = await extractLocalChannel(channelId);
      onAnalysisComplete(result);
    } catch (err) {
      playThreatAlert();
      const detail = err.response?.data?.detail || '';
      if (detail.includes('not available') || detail.includes('Empty')) {
        setError(`Could not extract logs from "${channel.name}". The channel may be empty or require Administrator privileges.`);
      } else {
        setError(detail || 'Failed to extract Windows logs. Ensure the backend is running.');
      }
    } finally {
      setExtracting(null);
      setLoading(false);
    }
  };

  const onDrop = (e) => { 
    e.preventDefault(); 
    setDragOver(false); 
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); 
  };

  if (loading) {
    return (
      <div 
        className="card fade-in" 
        style={{ 
          textAlign: 'center', 
          padding: '70px 24px', 
          border: '1px solid var(--accent-cyan)', 
          background: 'radial-gradient(circle at center, rgba(0,242,255,0.12) 0%, rgba(4,7,17,0.98) 100%)',
          boxShadow: '0 0 40px rgba(0,242,255,0.25)',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '2px',
          background: 'linear-gradient(90deg, transparent, var(--accent-cyan), var(--accent-magenta), transparent)',
          animation: 'radarScan 2s linear infinite'
        }}></div>

        <div className="loading-state">
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 20 }}>
            <CyberReactor size={74} isCritical={false} />
          </div>
          <div className="loading-text" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.14em', color: 'var(--accent-cyan)', fontSize: '1.15rem', marginTop: 10 }}>
            <CyberGlitchText 
              text={extracting
                ? `HARVESTING TELEMETRY // ${winChannels.find(c => c.id === extracting)?.name || extracting}`
                : 'QUANTUM CHRONO ENGINE // PARSING TIMELINE TOPOLOGY'} 
            />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 10 }}>
            CHRONO-CORE ENGAGED &bull; CORRELATING MITRE ATT&CK MATRIX &bull; NEURAL RECONSTRUCTION ACTIVE
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in">
      {/* ── Holographic Ingestion Pod ────────────────────────────── */}
      <div
        className={`upload-zone ${dragOver ? 'dragover' : ''}`}
        onDrop={onDrop}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onClick={() => { playCyberClick(); fileInput.current?.click(); }}
        style={{
          border: dragOver ? '2px solid var(--accent-magenta)' : '1px solid rgba(0,242,255,0.4)',
          background: dragOver 
            ? 'radial-gradient(circle at center, rgba(247,37,133,0.18) 0%, rgba(6,11,25,0.95) 100%)'
            : 'radial-gradient(circle at center, rgba(0,242,255,0.06) 0%, rgba(4,8,20,0.92) 100%)',
          backdropFilter: 'blur(16px)',
          position: 'relative',
          padding: '50px 30px',
          overflow: 'hidden',
          cursor: 'pointer',
          boxShadow: dragOver ? '0 0 45px rgba(247,37,133,0.4)' : '0 10px 35px rgba(0,0,0,0.7), 0 0 25px rgba(0,242,255,0.12)',
          transition: 'all 0.25s ease'
        }}
      >
        {/* Corner HUD Bracket Reticles */}
        <div style={{ position: 'absolute', top: 10, left: 14, fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--accent-cyan)', letterSpacing: '0.1em', opacity: 0.8 }}>
          [ INGEST // 0xPORT_01 ]
        </div>
        <div style={{ position: 'absolute', top: 10, right: 14, fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--accent-cyan)', letterSpacing: '0.1em', opacity: 0.8 }}>
          [ PROTOCOL // EVTX_SYSLOG_PCAP ]
        </div>
        <div style={{ position: 'absolute', bottom: 10, left: 14, fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
          [ SHA-256 // HEURISTICS_READY ]
        </div>
        <div style={{ position: 'absolute', bottom: 10, right: 14, fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--accent-green)', letterSpacing: '0.1em' }}>
          [ STATUS // STANDBY_ARMED ]
        </div>

        {/* Animated Laser Scanline */}
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '2px',
          background: 'linear-gradient(90deg, transparent, var(--accent-cyan), var(--accent-magenta), transparent)',
          animation: 'radarScan 3.5s linear infinite',
          boxShadow: '0 0 10px var(--accent-cyan)'
        }}></div>

        {/* Central Quantum Reactor Core */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 20 }}>
          <CyberReactor size={70} isCritical={dragOver} />
        </div>

        <h3 style={{ 
          fontFamily: 'var(--font-heading)', 
          letterSpacing: '0.12em', 
          color: '#fff', 
          fontSize: '1.25rem', 
          marginBottom: 8,
          textShadow: '0 0 15px rgba(0,242,255,0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 10
        }}>
          <CyberGlitchText text="QUANTUM FORENSIC LOG INGESTION CHAMBER" />
        </h3>

        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', maxWidth: 620, margin: '0 auto 18px', lineHeight: 1.5 }}>
          Drag & drop raw event logs, sysmon traces, auth.log, or network telemetry to reconstruct the multi-stage attack graph and chronological incident narrative.
        </p>

        {/* Animated Spectrum Equalizer Deck */}
        <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'center', gap: 4, height: 20, opacity: 0.75 }}>
          {[12, 18, 8, 24, 16, 28, 14, 22, 10, 26, 15, 20, 9, 25].map((h, i) => (
            <div 
              key={i} 
              style={{
                width: 3,
                height: `${h}px`,
                background: i % 2 === 0 ? 'var(--accent-cyan)' : 'var(--accent-magenta)',
                borderRadius: '1px',
                animation: `equalizerBounce 1s infinite ${i * 0.08}s`
              }}
            />
          ))}
        </div>

        <input ref={fileInput} type="file" accept=".log,.txt,.csv" style={{ display: 'none' }} onChange={(e) => e.target.files[0] && handleFile(e.target.files[0])} />
      </div>

      {/* ── Real Telemetry Source Actions ───────────── */}
      <div style={{ marginTop: 18, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ 
          fontFamily: 'var(--font-mono)', 
          fontSize: '0.72rem', 
          color: 'var(--text-muted)', 
          display: 'flex', 
          alignItems: 'center', 
          gap: 6,
          letterSpacing: '0.08em'
        }}>
          <span style={{ color: 'var(--accent-cyan)' }}>📡</span>
          <span>AUTHENTIC FORENSIC CHANNELS:</span>
        </div>

        <button
          onClick={(e) => { e.stopPropagation(); playCyberClick(); fileInput.current?.click(); }}
          style={{
            background: 'rgba(6, 12, 28, 0.85)',
            border: '1px solid var(--accent-cyan)',
            borderRadius: '4px',
            padding: '7px 16px',
            color: '#fff',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            fontFamily: 'var(--font-mono)',
            fontSize: '0.72rem',
            fontWeight: 600,
            letterSpacing: '0.06em',
            boxShadow: '0 0 10px rgba(0,242,255,0.15)',
            transition: 'all 0.15s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'translateY(-2px)';
            e.currentTarget.style.boxShadow = '0 0 18px rgba(0,242,255,0.4)';
            e.currentTarget.style.background = 'rgba(0,242,255,0.15)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'translateY(0)';
            e.currentTarget.style.boxShadow = '0 0 10px rgba(0,242,255,0.15)';
            e.currentTarget.style.background = 'rgba(6, 12, 28, 0.85)';
          }}
        >
          <span style={{ color: 'var(--accent-cyan)' }}>📁</span>
          <span>BROWSE LOG FILE (.LOG / .TXT / .CSV / .EVTX)</span>
        </button>

        <button
          onClick={(e) => { e.stopPropagation(); playCyberClick(); navigate('/app/monitor'); }}
          style={{
            background: 'rgba(6, 12, 28, 0.85)',
            border: '1px solid var(--accent-green)',
            borderRadius: '4px',
            padding: '7px 16px',
            color: '#fff',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            fontFamily: 'var(--font-mono)',
            fontSize: '0.72rem',
            fontWeight: 600,
            letterSpacing: '0.06em',
            boxShadow: '0 0 10px rgba(5,255,161,0.15)',
            transition: 'all 0.15s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'translateY(-2px)';
            e.currentTarget.style.boxShadow = '0 0 18px rgba(5,255,161,0.4)';
            e.currentTarget.style.background = 'rgba(5,255,161,0.15)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'translateY(0)';
            e.currentTarget.style.boxShadow = '0 0 10px rgba(5,255,161,0.15)';
            e.currentTarget.style.background = 'rgba(6, 12, 28, 0.85)';
          }}
        >
          <span style={{ color: 'var(--accent-green)' }}>⚡</span>
          <span>LAUNCH LIVE OS MONITOR STREAM</span>
        </button>
      </div>

      {error && (
        <div style={{ marginTop: 18, padding: '14px 18px', background: 'rgba(255,0,85,0.14)', borderRadius: 'var(--radius-md)', color: 'var(--accent-red)', fontSize: '0.85rem', border: '1px solid rgba(255,0,85,0.5)', display: 'flex', alignItems: 'center', gap: 12, fontFamily: 'var(--font-mono)', boxShadow: '0 0 20px rgba(255,0,85,0.2)' }}>
          <span style={{ fontSize: '1.2rem' }}>⚠</span>
          <span>{error}</span>
        </div>
      )}

      {/* ── Extract System Logs Banner ────────────────────────────── */}
      <div
        className="extract-system-banner"
        onClick={() => { playCyberClick(); setShowExtract(!showExtract); }}
        style={{ 
          marginTop: 28, 
          background: 'linear-gradient(90deg, rgba(8,16,38,0.92) 0%, rgba(14,24,54,0.92) 100%)',
          border: '1px solid rgba(0,242,255,0.3)',
          clipPath: 'polygon(0 0, calc(100% - 14px) 0, 100% 14px, 100% 100%, 0 100%)',
          padding: '16px 20px',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ 
            width: 40, 
            height: 40, 
            borderRadius: '6px', 
            background: 'rgba(0,242,255,0.12)', 
            border: '1px solid rgba(0,242,255,0.3)', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            color: 'var(--accent-cyan)',
            boxShadow: '0 0 12px rgba(0,242,255,0.2)'
          }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
          </div>
          <div>
            <h3 style={{ margin: 0, fontFamily: 'var(--font-heading)', fontSize: '0.95rem', letterSpacing: '0.08em', color: '#fff' }}>
              LOCAL HARDWARE SENSOR ARRAY // HOST LOG HARVESTER
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Directly tap the Windows Kernel event architecture to harvest live forensic artifacts from this machine.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ 
            padding: '4px 10px', 
            background: 'rgba(5,255,161,0.12)', 
            border: '1px solid rgba(5,255,161,0.35)', 
            borderRadius: '4px', 
            color: 'var(--accent-green)', 
            fontFamily: 'var(--font-mono)', 
            fontSize: '0.7rem',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', boxShadow: '0 0 8px var(--accent-green)' }}></span>
            6 SENSORS ARMED
          </span>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
            style={{ transition: 'transform 0.25s', transform: showExtract ? 'rotate(180deg)' : 'rotate(0deg)' }}>
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </div>
      </div>

      {/* ── Live Windows Channels Grid ────────────────────────────── */}
      {showExtract && (
        <div className="extract-channels-panel fade-in" style={{ marginTop: 14 }}>
          {winChannels.length === 0 ? (
            <div className="extract-empty" style={{ padding: '30px', textAlign: 'center', background: 'rgba(6,10,24,0.6)', border: '1px solid rgba(0,242,255,0.15)', borderRadius: '6px' }}>
              <div className="spinner" style={{ width: 24, height: 24, borderWidth: 2, marginBottom: 10 }}></div>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Scanning local event channels...</p>
            </div>
          ) : (
            <div className="extract-grid">
              {winChannels.map((ch, idx) => (
                <div
                  key={ch.id}
                  className={`extract-card-cyber ${!ch.available ? 'disabled' : ''} ${extracting === ch.id ? 'extracting' : ''}`}
                  onClick={() => !extracting ? handleExtractWindows(ch.id) : null}
                  style={{ cursor: extracting ? 'wait' : 'pointer' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        [ CH-0{idx + 1} ]
                      </span>
                      <h4 style={{ margin: 0, fontSize: '0.86rem', fontWeight: 700, color: '#fff' }}>
                        {ch.name}
                      </h4>
                    </div>
                    {ch.available ? (
                      <span style={{ padding: '2px 6px', background: 'rgba(5,255,161,0.12)', color: 'var(--accent-green)', border: '1px solid rgba(5,255,161,0.3)', borderRadius: '3px', fontSize: '0.62rem', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        ONLINE
                      </span>
                    ) : ch.needs_admin ? (
                      <span style={{ padding: '2px 6px', background: 'rgba(245,158,11,0.15)', color: 'var(--accent-amber)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: '3px', fontSize: '0.62rem', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        🔒 ADMIN
                      </span>
                    ) : (
                      <span style={{ padding: '2px 6px', background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)', borderRadius: '3px', fontSize: '0.62rem', fontFamily: 'var(--font-mono)' }}>
                        EMPTY
                      </span>
                    )}
                  </div>

                  <p style={{ margin: '0 0 10px 0', fontSize: '0.74rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                    {ch.description}
                  </p>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 8, borderTop: '1px solid rgba(0,242,255,0.12)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-muted)' }}>
                      {ch.channel}
                    </span>

                    {ch.event_count > 0 ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div className="pulse-wave-mini">
                          <span></span><span></span><span></span><span></span>
                        </div>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--accent-cyan)', fontWeight: 700, textShadow: '0 0 8px rgba(0,242,255,0.4)' }}>
                          {ch.event_count.toLocaleString()} EVENTS
                        </span>
                      </div>
                    ) : (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                        STANDBY
                      </span>
                    )}
                  </div>

                  {extracting === ch.id && (
                    <div style={{
                      position: 'absolute',
                      inset: 0,
                      background: 'rgba(4,7,18,0.92)',
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 8,
                      zIndex: 10
                    }}>
                      <CyberReactor size={32} />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--accent-cyan)', letterSpacing: '0.08em' }}>
                        EXTRACTING REAL LOGS...
                      </span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

