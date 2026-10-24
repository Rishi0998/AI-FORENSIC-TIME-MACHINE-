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
import './index.css';

/* ── Dashboard Sidebar ─────────────────────────────────────────────────── */
function Sidebar({ sessionId, sessionInfo }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h1>Digital Forensics<br/>Time Machine</h1>
        <span>AI-Powered Analysis</span>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-title">Ingestion</div>
          <NavLink to="/app" end className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconUpload /></span>
            Log Upload
          </NavLink>
          <NavLink to="/app/monitor" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconRadar /></span>
            Live Monitor
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Investigation</div>
          <NavLink to="/app/timeline" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconTimeline /></span>
            Event Timeline
          </NavLink>
          <NavLink to="/app/graph" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconGraph /></span>
            Attack Graph
          </NavLink>
          <NavLink to="/app/replay" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconReplay /></span>
            Forensic Replay
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Reporting</div>
          <NavLink to="/app/analysis" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconAnalysis /></span>
            AI Analysis
          </NavLink>
          <NavLink to="/app/report" className={({ isActive }) => `nav-link ${!sessionId ? 'disabled' : ''} ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconReport /></span>
            Export Report
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">System</div>
          <NavLink to="/app/settings" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <span className="nav-icon"><IconSettings /></span>
            Settings
          </NavLink>
        </div>
      </nav>

      {sessionId && sessionInfo && (
        <div className="sidebar-footer">
          Session: {sessionId}<br/>
          {sessionInfo.total_events} events &middot; {sessionInfo.suspicious_events} threats
        </div>
      )}
    </aside>
  );
}

function Topbar({ title, sessionId, onNewSession }) {
  const navigate = useNavigate();
  return (
    <div className="topbar">
      <div className="topbar-title">{title}</div>
      <div className="topbar-actions">
        {sessionId && (
          <button className="btn btn-outline btn-sm" onClick={onNewSession}>
            New Analysis
          </button>
        )}
        <button className="btn btn-ghost btn-sm" onClick={() => navigate('/')}>
          Exit to Home
        </button>
      </div>
    </div>
  );
}

function SessionStats({ sessionInfo }) {
  if (!sessionInfo) return null;
  return (
    <div className="stats-grid fade-in">
      <div className="stat-card">
        <div className="stat-label">Session ID</div>
        <div className="stat-value info">{sessionInfo.session_id || '—'}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Total Events</div>
        <div className="stat-value">{sessionInfo.total_events}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Threats Detected</div>
        <div className="stat-value danger">{sessionInfo.suspicious_events}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Attack Phases</div>
        <div className="stat-value warning">{sessionInfo.attack_phases}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Risk Score</div>
        <div className="stat-value danger">{sessionInfo.risk_score}</div>
        <div className="risk-bar">
          <div className={`risk-bar-fill ${sessionInfo.risk_level}`} style={{ width: `${sessionInfo.risk_score}%` }}></div>
        </div>
      </div>
    </div>
  );
}

const PAGE_TITLES = {
  '/app': 'Log Ingestion',
  '/app/monitor': 'Real-Time Monitor',
  '/app/timeline': 'Event Timeline',
  '/app/graph': 'Attack Graph',
  '/app/replay': 'Forensic Replay',
  '/app/analysis': 'AI Analysis Report',
  '/app/report': 'Export Report',
  '/app/settings': 'Settings',
};

function DashboardLayout({ sessionId, sessionInfo, onAnalysisComplete, onNewSession, loading, setLoading }) {
  const location = useLocation();
  const title = PAGE_TITLES[location.pathname] || 'Forensics';
  const showStats = sessionId && sessionInfo && !['/app/monitor', '/app', '/app/settings'].includes(location.pathname);

  return (
    <div className="app-layout">
      <Sidebar sessionId={sessionId} sessionInfo={sessionInfo} />
      <div className="main-area">
        <Topbar title={title} sessionId={sessionId} onNewSession={onNewSession} />
        <div className="page-content">
          {showStats && <SessionStats sessionInfo={sessionInfo} />}
          <Routes>
            <Route path="/" element={<Upload onAnalysisComplete={onAnalysisComplete} loading={loading} setLoading={setLoading} />} />
            <Route path="/monitor" element={<LiveMonitor onAnalysisComplete={onAnalysisComplete} />} />
            <Route path="/timeline" element={sessionId ? <Timeline sessionId={sessionId} /> : <NoSession onAnalysisComplete={onAnalysisComplete} setLoading={setLoading} />} />
            <Route path="/graph" element={sessionId ? <Graph sessionId={sessionId} /> : <NoSession onAnalysisComplete={onAnalysisComplete} setLoading={setLoading} />} />
            <Route path="/replay" element={sessionId ? <Replay sessionId={sessionId} /> : <NoSession onAnalysisComplete={onAnalysisComplete} setLoading={setLoading} />} />
            <Route path="/analysis" element={sessionId ? <Analysis sessionId={sessionId} /> : <NoSession onAnalysisComplete={onAnalysisComplete} setLoading={setLoading} />} />
            <Route path="/report" element={sessionId ? <ReportExport sessionId={sessionId} sessionInfo={sessionInfo} /> : <NoSession onAnalysisComplete={onAnalysisComplete} setLoading={setLoading} />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </div>
      </div>
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

function NoSession({ onAnalysisComplete, setLoading }) {
  const navigate = useNavigate();

  return (
    <div className="empty-state fade-in">
      <div className="empty-icon">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/></svg>
      </div>
      <h3>No Active Forensic Session</h3>
      <p>Start the real-time live monitor to stream events as they happen, or ingest log files from your machine.</p>
      <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', marginTop: 16 }}>
        <button className="btn btn-primary" onClick={() => navigate('/app/monitor')}>
          ⚡ Start Live Monitor
        </button>
        <button className="btn btn-outline" onClick={() => navigate('/app')}>
          📁 Ingest System Logs
        </button>
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


/* ── SVG Icons ─────────────────────────────────────────────────────────── */
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
