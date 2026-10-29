import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useNavigate, useLocation } from 'react-router-dom';
import Upload from './components/Upload';
import Timeline from './components/Timeline';
import Graph from './components/Graph';
import Replay from './components/Replay';
import Analysis from './components/Analysis';
import LiveMonitor from './components/LiveMonitor';
import ReportExport from './components/ReportExport';
import Settings from './components/Settings';
import LandingPage from './components/LandingPage';
import CyberBackground from './components/CyberBackground';
import CyberDiagnosticsHUD from './components/CyberDiagnosticsHUD';
import CyberTicker from './components/CyberTicker';
import CyberGlitchText from './components/CyberGlitchText';
import { isSoundEnabled, toggleSound, playCyberClick } from './cyberAudio';
import './index.css';

/* ── Professional SOC Topbar ─────────────────────────────────────────────── */
function Topbar({ title, sessionId, sessionInfo, onNewSession }) {
  const navigate = useNavigate();
  const [timeStr, setTimeStr] = useState('');
  const [soundOn, setSoundOn] = useState(isSoundEnabled());

  useEffect(() => {
    const updateTime = () => {
      const d = new Date();
      const zulu = d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      setTimeStr(zulu);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleSoundToggle = () => {
    const nextState = toggleSound();
    setSoundOn(nextState);
  };

  const riskLevel = sessionInfo?.risk_level || 'low';
  const riskBadgeClass = riskLevel === 'critical' ? 'badge-critical'
    : riskLevel === 'high' ? 'badge-high'
    : riskLevel === 'medium' ? 'badge-medium'
    : 'badge-low';

  const isCritical = riskLevel === 'critical' || (sessionInfo?.risk_score && sessionInfo.risk_score >= 70);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <h2 className="topbar-title" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.06em', fontSize: '1rem' }}>
          {title}
        </h2>
        <div className="topbar-divider"></div>
        <div className="topbar-clock">
          <span className="pulse-dot"></span>
          <span>{timeStr}</span>
        </div>

        {/* DEFCON Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '2px 8px',
          background: isCritical ? 'rgba(255,0,85,0.18)' : 'rgba(0,242,254,0.12)',
          border: `1px solid ${isCritical ? 'var(--accent-red)' : 'rgba(0,242,254,0.35)'}`,
          borderRadius: '4px',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.68rem',
          fontWeight: 700,
          color: isCritical ? 'var(--accent-red)' : 'var(--accent-cyan)',
          letterSpacing: '0.06em'
        }}>
          <span style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: isCritical ? 'var(--accent-red)' : 'var(--accent-cyan)',
            boxShadow: `0 0 8px ${isCritical ? 'var(--accent-red)' : 'var(--accent-cyan)'}`,
            animation: 'pulseSlow 1.5s infinite'
          }}></span>
          <span>{isCritical ? 'DEFCON 1 // BREACH' : 'DEFCON 5 // STANDBY'}</span>
        </div>

        {sessionId && (
          <span className={`badge ${riskBadgeClass}`}>
            {riskLevel.toUpperCase()} THREAT &bull; SCORE {sessionInfo?.risk_score ?? 0}
          </span>
        )}
      </div>

      <div className="topbar-actions">
        {/* Audio Synthesizer SFX Toggle */}
        <button 
          className="btn btn-outline btn-sm" 
          onClick={handleSoundToggle}
          title="Toggle Cyber Synthesizer Sound FX"
          style={{
            borderColor: soundOn ? 'var(--accent-cyan)' : 'var(--border-secondary)',
            color: soundOn ? 'var(--accent-cyan)' : 'var(--text-muted)',
            boxShadow: soundOn ? '0 0 10px rgba(0,242,255,0.2)' : 'none',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.72rem'
          }}
        >
          <span>{soundOn ? '🔊 SFX ON' : '🔈 SFX OFF'}</span>
        </button>

        {sessionId ? (
          <button className="btn btn-outline btn-sm" onClick={() => { playCyberClick(); onNewSession(); }}>
            <IconUpload />
            <span>New Investigation</span>
          </button>
        ) : (
          <button className="btn btn-primary btn-sm" onClick={() => { playCyberClick(); navigate('/app'); }}>
            <IconUpload />
            <span>Ingest Logs</span>
          </button>
        )}
        <button className="btn btn-ghost btn-sm" onClick={() => { playCyberClick(); navigate('/'); }}>
          Portal Overview &rarr;
        </button>
      </div>
    </header>
  );
}

/* ── Enterprise SOC Sidebar ──────────────────────────────────────────────── */
function Sidebar({ sessionId, sessionInfo }) {
  const navigate = useNavigate();

  return (
    <aside className="sidebar">
      <div className="sidebar-brand" onClick={() => { playCyberClick(); navigate('/'); }} role="button" tabIndex={0}>
        <div className="brand-logo-icon" style={{ boxShadow: '0 0 15px rgba(0,242,255,0.4)', borderColor: 'var(--accent-cyan)' }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <circle cx="12" cy="11" r="3"/>
            <path d="M12 8v3l2 2"/>
          </svg>
        </div>
        <div className="sidebar-brand-text">
          <h1 style={{ fontFamily: 'var(--font-heading)', fontSize: '0.95rem', letterSpacing: '0.06em' }}>
            <CyberGlitchText text="Chronos Forensics" triggerOnHover={true} />
          </h1>
          <span style={{ color: 'var(--accent-cyan)', letterSpacing: '0.12em', fontWeight: 700 }}>
            QUANTUM SOC // V4.2
          </span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-title">Telemetry Ingestion</div>
          <NavLink to="/app" end className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconUpload /></span>
            Log Ingestion
          </NavLink>
          <NavLink to="/app/monitor" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconRadar /></span>
            Live Event Monitor
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Investigation Grid</div>
          <NavLink to="/app/timeline" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconTimeline /></span>
            Event Timeline
          </NavLink>
          <NavLink to="/app/graph" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconGraph /></span>
            Attack Vector Graph
          </NavLink>
          <NavLink to="/app/replay" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconReplay /></span>
            Forensic Replay
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Threat Intelligence</div>
          <NavLink to="/app/analysis" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconAnalysis /></span>
            AI Kill Chain Analysis
          </NavLink>
          <NavLink to="/app/report" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconReport /></span>
            Forensic Report Export
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">System Settings</div>
          <NavLink to="/app/settings" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} onClick={playCyberClick}>
            <span className="nav-icon"><IconSettings /></span>
            AI Engine &amp; Rules
          </NavLink>
        </div>
      </nav>

      <div className="sidebar-footer">
        {sessionId ? (
          <div className="sidebar-session-card">
            <div className="session-id-row">
              <span className="session-tag">SESSION ID</span>
              <span className="session-val">{sessionId.substring(0, 16)}...</span>
            </div>
            <div className="session-counts">
              <span>{sessionInfo?.total_events || 0} events</span>
              <span>&bull;</span>
              <span style={{ color: sessionInfo?.suspicious_events > 0 ? 'var(--accent-red)' : 'var(--text-muted)' }}>
                {sessionInfo?.suspicious_events || 0} IOCs
              </span>
            </div>
          </div>
        ) : (
          <div className="sidebar-idle-card">
            <span>READY FOR INGESTION</span>
          </div>
        )}
        <div className="telemetry-status">
          <span className="pulse-dot"></span>
          <span>SOC Engine Operational</span>
        </div>
      </div>
    </aside>
  );
}

/* ── Crazy Cybernetic Tactical HUD Session Stats ────────────────────────────── */
function SessionStats({ sessionInfo }) {
  if (!sessionInfo) return null;
  const [copied, setCopied] = useState(false);

  const copySessionId = () => {
    if (sessionInfo.session_id) {
      playCyberClick();
      navigator.clipboard?.writeText(sessionInfo.session_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    }
  };

  const riskScore = sessionInfo.risk_score || 0;
  const numActiveCells = Math.min(10, Math.max(riskScore > 0 ? 1 : 0, Math.round((riskScore / 100) * 10)));
  const threatLevel = riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low';
  const hasThreats = (sessionInfo.suspicious_events || 0) > 0;

  return (
    <div className="stats-grid-cyber fade-in">
      {/* 1. Active Investigation ID */}
      <div className="stat-card-cyber">
        <div>
          <div className="stat-corner-tag">[ 0xSEC_ID // INVESTIGATION ]</div>
          <div className="stat-header-cyber">
            <span className="stat-title-cyber">
              <span className="pulse-dot" style={{ background: 'var(--accent-cyan)', boxShadow: '0 0 8px var(--accent-cyan)' }}></span>
              ACTIVE INVESTIGATION
            </span>
            <button 
              className={`cyber-copy-btn ${copied ? 'copied' : ''}`} 
              onClick={copySessionId} 
              title="Copy Investigation Hex ID to Clipboard"
            >
              {copied ? '✓ COPIED' : '📋 0xCOPY'}
            </button>
          </div>
          <div className="stat-value-cyber cyan" style={{ fontSize: '1.25rem', wordBreak: 'break-all' }}>
            0x{sessionInfo.session_id?.substring(0, 10) || '00000000'}
          </div>
        </div>
        <div className="stat-footer-cyber">
          <span>NODE: CHRONOS-ALPHA</span>
          <span style={{ color: 'var(--accent-cyan)' }}>ENCRYPTED</span>
        </div>
      </div>

      {/* 2. Ingested Events */}
      <div className="stat-card-cyber">
        <div>
          <div className="stat-corner-tag">[ TELEMETRY_STREAM ]</div>
          <div className="stat-header-cyber">
            <span className="stat-title-cyber">INGESTED EVENTS</span>
            <span className="stat-pill-cyber success">NORMALIZED</span>
          </div>
          <div className="stat-value-cyber" style={{ color: '#00f2fe' }}>
            {sessionInfo.total_events?.toLocaleString() || 0}
          </div>
        </div>
        <div className="stat-footer-cyber">
          <div className="pulse-wave-mini">
            <span></span><span></span><span></span><span></span>
          </div>
          <span>DRIFT: 0.00% // LIVE</span>
        </div>
      </div>

      {/* 3. Suspicious IOCs */}
      <div className={`stat-card-cyber ${hasThreats ? 'threat-alert' : ''}`}>
        <div>
          <div className="stat-corner-tag" style={{ color: hasThreats ? '#ff0055' : 'var(--accent-cyan)' }}>
            [ {hasThreats ? '⚠ IOC_ALERT' : 'PERIMETER_MONITOR'} ]
          </div>
          <div className="stat-header-cyber">
            <span className="stat-title-cyber" style={{ color: hasThreats ? '#ff0055' : '#fff' }}>
              SUSPICIOUS IOCS
            </span>
            <span className={`stat-pill-cyber ${hasThreats ? 'danger' : 'success'}`}>
              {hasThreats ? 'THREATS' : 'CLEAR'}
            </span>
          </div>
          <div className={`stat-value-cyber ${hasThreats ? 'danger' : 'cyan'}`}>
            {sessionInfo.suspicious_events || 0}
          </div>
        </div>
        <div className="stat-footer-cyber">
          <span style={{ color: hasThreats ? '#ff0055' : 'var(--text-muted)' }}>
            {hasThreats ? '🚨 ANOMALY LOCATED' : 'PERIMETER SECURE'}
          </span>
          <span>{hasThreats ? 'FLAGGED' : '0 VULNS'}</span>
        </div>
      </div>

      {/* 4. MITRE Attack Phases */}
      <div className="stat-card-cyber tactic-alert">
        <div>
          <div className="stat-corner-tag" style={{ color: '#ffaa00' }}>[ MITRE_ATT&CK ]</div>
          <div className="stat-header-cyber">
            <span className="stat-title-cyber">MITRE ATTACK PHASES</span>
            <span className="stat-pill-cyber warning">TACTICS</span>
          </div>
          <div className="stat-value-cyber warning">
            {sessionInfo.attack_phases || 0}
          </div>
        </div>
        <div className="stat-footer-cyber">
          <span style={{ color: '#ffaa00' }}>KILL-CHAIN ACTIVE</span>
          <span>ATT&CK v14</span>
        </div>
      </div>

      {/* 5. Threat Risk Score & 10-Segment LED Energy Cell Meter */}
      <div className={`stat-card-cyber ${threatLevel === 'critical' ? 'threat-alert' : ''}`}>
        <div>
          <div className="stat-corner-tag">[ DEFCON_MATRIX ]</div>
          <div className="stat-header-cyber">
            <span className="stat-title-cyber">THREAT RISK SCORE</span>
            <span className={`stat-pill-cyber ${threatLevel === 'critical' ? 'danger' : threatLevel === 'high' ? 'danger' : threatLevel === 'medium' ? 'warning' : ''}`}>
              {sessionInfo.risk_level?.toUpperCase() || 'LOW'}
            </span>
          </div>
          <div className={`stat-value-cyber ${threatLevel === 'critical' || threatLevel === 'high' ? 'danger' : threatLevel === 'medium' ? 'warning' : 'cyan'}`}>
            {riskScore} <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: 500 }}>/ 100</span>
          </div>
          {/* Segmented LED Energy Gauge */}
          <div className="hud-energy-gauge">
            {[...Array(10)].map((_, idx) => (
              <div 
                key={idx} 
                className={`hud-cell ${idx < numActiveCells ? `active-${threatLevel}` : ''}`} 
              />
            ))}
          </div>
        </div>
        <div className="stat-footer-cyber">
          <span>DEFCON {threatLevel === 'critical' ? '1' : threatLevel === 'high' ? '2' : threatLevel === 'medium' ? '3' : '5'}</span>
          <span>SCORE {riskScore}%</span>
        </div>
      </div>
    </div>
  );
}

const PAGE_TITLES = {
  '/app': 'Telemetry Log Ingestion',
  '/app/monitor': 'Live Event Monitor',
  '/app/timeline': 'Event Reconstruction Timeline',
  '/app/graph': 'Attack Vector Graph',
  '/app/replay': 'Forensic Replay Scrubber',
  '/app/analysis': 'AI Neural Incident Analysis',
  '/app/report': 'Forensic Report Export',
  '/app/settings': 'AI Engine Configuration',
};

function DashboardLayout({ sessionId, sessionInfo, onAnalysisComplete, onNewSession, loading, setLoading }) {
  const location = useLocation();
  const title = PAGE_TITLES[location.pathname] || 'Forensic Workspace';
  const showStats = sessionId && sessionInfo && !['/app/monitor', '/app', '/app/settings'].includes(location.pathname);
  const defconLevel = sessionId && sessionInfo?.risk_score >= 70 ? 'DEFCON 1' : 'DEFCON 5';

  return (
    <div className="app-layout" style={{ position: 'relative', minHeight: '100vh', paddingBottom: 28 }}>
      {/* Live Interactive Cyber Matrix Background */}
      <CyberBackground />

      <Sidebar sessionId={sessionId} sessionInfo={sessionInfo} />
      
      <div className="main-area" style={{ position: 'relative', zIndex: 1 }}>
        <Topbar 
          title={title} 
          sessionId={sessionId} 
          sessionInfo={sessionInfo}
          onNewSession={onNewSession} 
        />
        <main className="page-content" style={{ position: 'relative', zIndex: 1 }}>
          {showStats && <SessionStats sessionInfo={sessionInfo} />}
          <Routes>
            <Route path="/" element={<Upload onAnalysisComplete={onAnalysisComplete} loading={loading} setLoading={setLoading} />} />
            <Route path="/monitor" element={<LiveMonitor onAnalysisComplete={onAnalysisComplete} />} />
            <Route path="/timeline" element={sessionId ? <Timeline sessionId={sessionId} /> : <NoSession />} />
            <Route path="/graph" element={sessionId ? <Graph sessionId={sessionId} /> : <NoSession />} />
            <Route path="/replay" element={sessionId ? <Replay sessionId={sessionId} /> : <NoSession />} />
            <Route path="/analysis" element={sessionId ? <Analysis sessionId={sessionId} /> : <NoSession />} />
            <Route path="/report" element={sessionId ? <ReportExport sessionId={sessionId} sessionInfo={sessionInfo} /> : <NoSession />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>

      {/* Floating Tactical Telemetry & Oscilloscope Deck */}
      <CyberDiagnosticsHUD sessionId={sessionId} sessionInfo={sessionInfo} />

      {/* Live Threat Telemetry Ticker at the bottom edge */}
      <CyberTicker sessionInfo={sessionInfo} defconLevel={defconLevel} />
    </div>
  );
}

function AppContent() {
  const [sessionId, setSessionId] = useState(null);
  const [sessionInfo, setSessionInfo] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleAnalysisComplete = (result) => {
    setSessionId(result.session_id);
    setSessionInfo(result);
    navigate('/app/timeline');
  };

  const handleNewSession = () => {
    setSessionId(null);
    setSessionInfo(null);
    navigate('/app');
  };

  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/app/*" element={
        <DashboardLayout 
          sessionId={sessionId} 
          sessionInfo={sessionInfo} 
          onAnalysisComplete={handleAnalysisComplete}
          onNewSession={handleNewSession}
          loading={loading}
          setLoading={setLoading}
        />
      } />
    </Routes>
  );
}

function NoSession() {
  const navigate = useNavigate();

  return (
    <div className="card fade-in" style={{ textAlign: 'center', padding: '56px 24px' }}>
      <div className="empty-state">
        <div className="empty-icon">
          <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="1.5">
            <rect x="3" y="3" width="18" height="18" rx="2"/>
            <path d="M3 9h18"/>
            <path d="M9 21V9"/>
          </svg>
        </div>
        <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fff', marginTop: 14 }}>
          No Active Investigation Selected
        </h3>
        <p style={{ maxWidth: 480, margin: '10px auto 22px', color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: 1.5 }}>
          Launch the live event monitor to capture events in real time, or ingest system log files to begin automated breach timeline reconstruction.
        </p>
        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', marginTop: 16 }}>
          <button className="btn btn-primary" onClick={() => navigate('/app/monitor')}>
            <IconRadar />
            <span>Launch Live Monitor</span>
          </button>
          <button className="btn btn-outline" onClick={() => navigate('/app')}>
            <IconUpload />
            <span>Ingest System Logs</span>
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

/* ── Clean SVG Icons ─────────────────────────────────────────────────────── */
function IconUpload() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  );
}

function IconRadar() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><path d="M12 2a15 15 0 0 1 4 10"/><circle cx="12" cy="12" r="2"/>
    </svg>
  );
}

function IconTimeline() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/>
    </svg>
  );
}

function IconGraph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><circle cx="18" cy="6" r="3"/><line x1="8.6" y1="7.4" x2="15.4" y2="16.6"/><line x1="15.4" y1="7.4" x2="8.6" y2="16.6"/>
    </svg>
  );
}

function IconReplay() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  );
}

function IconAnalysis() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>
    </svg>
  );
}

function IconReport() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
    </svg>
  );
}

function IconSettings() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  );
}
