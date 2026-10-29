import { useState, useEffect, useRef } from 'react';
import { playCyberClick, playGlitchSound } from '../cyberAudio';
import CyberGlitchText from './CyberGlitchText';

export default function CyberDiagnosticsHUD({ sessionId, sessionInfo }) {
  const [collapsed, setCollapsed] = useState(false);
  const [coreLoads, setCoreLoads] = useState([74, 58, 89, 63]);
  const [hashes, setHashes] = useState([
    '0x7F2A9B...4E10',
    '0x3C81FA...9D22',
    '0xEA4490...1B88',
    '0x992B11...FE40'
  ]);
  const [packetRate, setPacketRate] = useState(48290);
  const [phaseOffset, setPhaseOffset] = useState(0);
  const animRef = useRef(null);

  // Dynamic CPU load & rolling cryptographic hashes animation
  useEffect(() => {
    const interval = setInterval(() => {
      setCoreLoads([
        Math.floor(65 + Math.random() * 30),
        Math.floor(45 + Math.random() * 45),
        Math.floor(70 + Math.random() * 28),
        Math.floor(50 + Math.random() * 40),
      ]);

      const randomHex = () =>
        '0x' + Array.from({ length: 6 }, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase() +
        '...' +
        Array.from({ length: 4 }, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase();

      setHashes([randomHex(), randomHex(), randomHex(), randomHex()]);
      setPacketRate(prev => Math.floor(47000 + Math.random() * 3000));
    }, 1800);

    return () => clearInterval(interval);
  }, []);

  // Oscilloscope wave phase animation loop
  useEffect(() => {
    let phase = 0;
    const animateWave = () => {
      phase += 0.08;
      setPhaseOffset(phase);
      animRef.current = requestAnimationFrame(animateWave);
    };
    animRef.current = requestAnimationFrame(animateWave);
    return () => cancelAnimationFrame(animRef.current);
  }, []);

  const handleToggle = () => {
    playGlitchSound();
    playCyberClick();
    setCollapsed(!collapsed);
  };

  // Generate SVG waveform points
  const width = 280;
  const height = 50;
  const midY = height / 2;
  const points = [];
  for (let x = 0; x <= width; x += 4) {
    const t = (x / width) * 4 * Math.PI + phaseOffset;
    const y = midY + Math.sin(t) * 14 + Math.sin(t * 2.5) * 6;
    points.push(`${x},${y.toFixed(1)}`);
  }
  const pathD = `M 0,${midY} ` + points.map(p => `L ${p}`).join(' ') + ` L ${width},${midY}`;

  const isCritical = sessionInfo?.risk_level === 'critical';
  const isHigh = sessionInfo?.risk_level === 'high';
  const threatClass = isCritical ? 'badge-critical' : isHigh ? 'badge-high' : 'badge-low';

  return (
    <div className={`cyber-diagnostics-hud ${collapsed ? 'collapsed' : ''}`}>
      {/* Top HUD Trim Header */}
      <div className="hud-deck-header" onClick={handleToggle}>
        <div className="hud-deck-title">
          <span className="hud-deck-icon">◈</span>
          <span className="hud-deck-tag">SYS-DIAGNOSTICS // TACTICAL TELEMETRY DECK</span>
          <span className="hud-deck-coords">LOC: 37.7749°N, 122.4194°W &bull; CHRONO-CORE 0x7F</span>
        </div>

        <div className="hud-deck-controls">
          <div className="hud-deck-metric">
            <span className="metric-tag">THREAT MATRIX:</span>
            <span className={`badge ${threatClass}`} style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
              {sessionInfo?.risk_level ? sessionInfo.risk_level.toUpperCase() : 'STANDBY'}
            </span>
          </div>

          <div className="hud-deck-metric">
            <span className="metric-tag">PKTS/SEC:</span>
            <span className="metric-val">{packetRate.toLocaleString()}</span>
          </div>

          <button className="hud-collapse-btn" onClick={(e) => { e.stopPropagation(); handleToggle(); }}>
            {collapsed ? '▲ EXPAND TACTICAL HUD' : '▼ MINIMIZE HUD'}
          </button>
        </div>
      </div>

      {/* Expandable Diagnostics Telemetry Grid */}
      {!collapsed && (
        <div className="hud-deck-body">
          {/* Deck Module 1: Oscilloscope Live Frequency Monitor */}
          <div className="hud-module">
            <div className="hud-module-header">
              <span className="module-title">// 01. QUANTUM FREQUENCY MONITOR</span>
              <span className="module-status">LIVE SINE 142.8 MHz</span>
            </div>
            <div className="waveform-container">
              <svg viewBox={`0 0 ${width} ${height}`} className="waveform-svg">
                <defs>
                  <linearGradient id="waveGlow" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#00f2fe" stopOpacity="0.8" />
                    <stop offset="50%" stopColor="#9d4edd" stopOpacity="1" />
                    <stop offset="100%" stopColor="#ff0055" stopOpacity="0.9" />
                  </linearGradient>
                </defs>
                {/* Grid Guidelines */}
                <line x1="0" y1="12" x2={width} y2="12" stroke="rgba(0,242,254,0.12)" strokeDasharray="3,3" />
                <line x1="0" y1={midY} x2={width} y2={midY} stroke="rgba(0,242,254,0.2)" strokeDasharray="2,2" />
                <line x1="0" y1="38" x2={width} y2="38" stroke="rgba(0,242,254,0.12)" strokeDasharray="3,3" />
                {/* Oscilloscope Wave */}
                <path d={pathD} fill="none" stroke="url(#waveGlow)" strokeWidth="2" strokeLinecap="round" />
              </svg>
              <div className="waveform-meta">
                <span>JITTER: 1.2ps</span>
                <span>SAMPLING: 96kHz</span>
                <span>DRIFT: ±0.002ms</span>
              </div>
            </div>
          </div>

          {/* Deck Module 2: Quad-Core Neural Processing Units */}
          <div className="hud-module">
            <div className="hud-module-header">
              <span className="module-title">// 02. NEURAL FORENSIC ENGINE</span>
              <span className="module-status">4x CLUSTER CORES</span>
            </div>
            <div className="core-grid">
              {[
                { label: 'INGEST', val: coreLoads[0], color: 'var(--accent-cyan)' },
                { label: 'PARSER', val: coreLoads[1], color: 'var(--accent-purple)' },
                { label: 'MITRE', val: coreLoads[2], color: 'var(--accent-red)' },
                { label: 'SCRUB', val: coreLoads[3], color: 'var(--accent-green)' },
              ].map((core, i) => (
                <div key={i} className="core-row">
                  <div className="core-info">
                    <span className="core-name">C-0{i + 1} [{core.label}]</span>
                    <span className="core-val" style={{ color: core.color }}>{core.val}%</span>
                  </div>
                  <div className="core-bar-track">
                    <div 
                      className="core-bar-fill" 
                      style={{ 
                        width: `${core.val}%`, 
                        background: `linear-gradient(90deg, transparent, ${core.color})`,
                        boxShadow: `0 0 8px ${core.color}`
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Deck Module 3: Rolling Decryption Cipher Stream */}
          <div className="hud-module">
            <div className="hud-module-header">
              <span className="module-title">// 03. LIVE CRYPTOGRAPHIC CIPHER</span>
              <span className="module-status">AES-256-GCM ACTIVE</span>
            </div>
            <div className="cipher-stream">
              {hashes.map((h, i) => (
                <div key={i} className="cipher-row">
                  <span className="cipher-dot">›</span>
                  <span className="cipher-hash">{h}</span>
                  <span className="cipher-status">
                    {i === 0 ? 'INTERCEPT' : i === 1 ? 'VERIFIED' : i === 2 ? 'DECRYPTED' : 'HASH-MATCH'}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Deck Module 4: Tactical Threat Status & Rapid Operations */}
          <div className="hud-module">
            <div className="hud-module-header">
              <span className="module-title">// 04. THREAT SECTOR STATUS</span>
              <span className="module-status">{sessionId ? 'LIVE SESSION' : 'AWAITING TELEMETRY'}</span>
            </div>
            <div className="threat-summary-box">
              {sessionId ? (
                <>
                  <div className="threat-sum-row">
                    <span>SESSION IDENTIFIER:</span>
                    <span style={{ color: 'var(--accent-cyan)' }}>{sessionId}</span>
                  </div>
                  <div className="threat-sum-row">
                    <span>CRITICAL IOCs:</span>
                    <span style={{ color: 'var(--accent-red)' }}>{sessionInfo?.suspicious_events || 0}</span>
                  </div>
                  <div className="threat-sum-row">
                    <span>CALCULATED THREAT:</span>
                    <span style={{ color: isCritical ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
                      {sessionInfo?.risk_score || 0} / 100 ({sessionInfo?.risk_level?.toUpperCase() || 'INFO'})
                    </span>
                  </div>
                  <div className="threat-radar-indicator">
                    <span className="beacon-pulse"></span>
                    <span>ALL SENSORS LOCKED &bull; ZERO-DAY DETECTION READY</span>
                  </div>
                </>
              ) : (
                <div className="hud-idle-state">
                  <span className="hud-idle-radar">◎</span>
                  <div>
                    <div style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>CHRONO FORENSICS STANDBY</div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                      Ingest forensic logs or monitor live telemetry to launch deep forensic reconstruction.
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
