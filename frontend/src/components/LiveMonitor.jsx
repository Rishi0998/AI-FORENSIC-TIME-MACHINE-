import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { analyzeLiveStream } from '../api';

const getWsUrl = () => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  if (import.meta.env.VITE_API_BASE) {
    return import.meta.env.VITE_API_BASE.replace(/^http/, 'ws') + '/ws/monitor';
  }
  return `${protocol}//${window.location.host}/api/ws/monitor`;
};

const WS_URL = getWsUrl();

export default function LiveMonitor({ onAnalysisComplete }) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({ total_events: 0, suspicious_events: 0 });
  const [statusText, setStatusText] = useState('Connecting to live system stream...');
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [autoScroll, setAutoScroll] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const wsRef = useRef(null);
  const feedEndRef = useRef(null);
  const reconnectRef = useRef(null);
  const navigate = useNavigate();

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    setStatusText('Connecting...');
    setError(null);

    try {
      const ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setConnected(true);
        setStatusText('Live streaming host system events');
        setError(null);
      };

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.type === 'event' && data.event) {
            const evt = data.event;
            const normalizedEvent = {
              timestamp: evt.timestamp || new Date().toISOString(),
              action: evt.action || evt.source_type || 'system_event',
              user: evt.user || null,
              ip_address: evt.ip_address || null,
              process: evt.process || null,
              severity: evt.severity || 'low',
              is_suspicious: evt.is_suspicious || false,
              detection_rule: evt.detection_rule || null,
              mitre_technique: evt.mitre_technique || null,
              raw_log: evt.raw_log || '',
            };
            setEvents(prev => {
              const next = [...prev, normalizedEvent];
              return next.length > 500 ? next.slice(-500) : next;
            });
            if (data.stats) setStats(data.stats);
          } else if (data.type === 'status') {
            setStatusText(data.message || 'Connected');
          } else if (data.type === 'heartbeat' && data.stats) {
            setStats(data.stats);
          } else if (data.type === 'error') {
            setError(data.message);
          }
        } catch (err) {
          console.warn('WS parse error:', err);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        setStatusText('Disconnected');
        reconnectRef.current = setTimeout(connect, 4000);
      };

      ws.onerror = () => {
        setError('WebSocket connection error. Ensure backend server is active on port 8000.');
        setConnected(false);
      };

      wsRef.current = ws;
    } catch (err) {
      setError(`Connection error: ${err.message}`);
    }
  }, []);

  const disconnect = () => {
    clearTimeout(reconnectRef.current);
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    setConnected(false);
    setStatusText('Disconnected');
  };

  // Connect automatically on mount
  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [connect]);

  useEffect(() => {
    if (autoScroll && feedEndRef.current) feedEndRef.current.scrollIntoView({ behavior: 'smooth' });
  }, [events, autoScroll]);

  const handleAnalyzeStream = async () => {
    if (events.length === 0) return;
    setAnalyzing(true);
    setError(null);
    try {
      const result = await analyzeLiveStream(events);
      if (onAnalysisComplete) {
        onAnalysisComplete(result);
      } else {
        navigate('/app/timeline');
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze live stream');
    } finally {
      setAnalyzing(false);
    }
  };

  const filtered = filter === 'suspicious' ? events.filter(e => e.is_suspicious) : events;
  const suspiciousCount = events.filter(e => e.is_suspicious).length;
  const threatRate = events.length > 0 ? Math.round((suspiciousCount / events.length) * 100) : 0;

  const getTimeStr = (ts) => {
    if (!ts) return '--:--:--';
    const parts = ts.split('T');
    if (parts.length > 1) return parts[1].substring(0, 8);
    const tparts = ts.split(' ');
    if (tparts.length > 1) return tparts[1].substring(0, 8);
    return ts.substring(0, 8);
  };

  return (
    <div className="fade-in">
      {/* Controls & Action Bar */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <span className={`status-dot ${connected ? 'online' : 'offline'}`}></span>
            Real-Time System Monitor
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              className="btn btn-primary btn-sm"
              disabled={events.length === 0 || analyzing}
              onClick={handleAnalyzeStream}
              style={{ fontWeight: 600, background: 'linear-gradient(135deg, #00f2ff, #7928ca)' }}
            >
              {analyzing ? 'Analyzing Stream...' : `⚡ Analyze in Time Machine (${events.length})`}
            </button>
            {!connected ? (
              <button className="btn btn-outline btn-sm" onClick={connect}>Connect</button>
            ) : (
              <button className="btn btn-danger btn-sm" onClick={disconnect}>Pause</button>
            )}
            {events.length > 0 && <button className="btn btn-ghost btn-sm" onClick={() => setEvents([])}>Clear</button>}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
          <div className="monitor-status">{statusText}</div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div className="filter-group">
              <button className={`filter-btn ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>All ({events.length})</button>
              <button className={`filter-btn danger ${filter === 'suspicious' ? 'active' : ''}`} onClick={() => setFilter('suspicious')}>Threats ({suspiciousCount})</button>
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.7rem', color: 'var(--text-muted)', cursor: 'pointer' }}>
              <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
              Auto-scroll
            </label>
          </div>
        </div>

        {error && (
          <div style={{ marginTop: 10, padding: '8px 12px', background: 'var(--accent-red-dim)', borderRadius: 'var(--radius-sm)', color: 'var(--accent-red)', fontSize: '0.78rem' }}>
            {error}
          </div>
        )}
      </div>

      {/* Real-time stats */}
      <div className="stats-grid">
        <div className="stat-card"><div className="stat-label">Total Live Events</div><div className="stat-value">{stats.total_events || events.length}</div></div>
        <div className="stat-card"><div className="stat-label">Detected Threats</div><div className="stat-value danger">{suspiciousCount}</div></div>
        <div className="stat-card"><div className="stat-label">Active Buffer</div><div className="stat-value">{events.length}</div></div>
        <div className="stat-card"><div className="stat-label">Threat Percentage</div><div className={`stat-value ${threatRate > 10 ? 'danger' : ''}`}>{threatRate}%</div></div>
      </div>

      {/* Live Event Stream */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Live Host Event Stream</div>
          <span className="card-subtitle">{filtered.length} captured</span>
        </div>

        <div className="live-feed" style={{ maxHeight: '480px' }}>
          {!connected && events.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 2a15 15 0 0 1 4 10"/><circle cx="12" cy="12" r="2"/></svg>
              </div>
              <h3>Monitor Disconnected</h3>
              <p>Click "Connect" to stream live events from the operating system.</p>
            </div>
          )}

          {connected && events.length === 0 && (
            <div className="loading-state" style={{ padding: 32 }}>
              <div className="spinner"></div>
              <div className="loading-text">Listening for live host system events...</div>
            </div>
          )}

          {filtered.map((event, i) => (
            <div
              key={i}
              className={`live-event ${event.is_suspicious ? 'threat' : ''}`}
              style={{ animation: i === filtered.length - 1 ? 'slideIn 0.2s ease' : 'none' }}
            >
              <span style={{ color: 'var(--text-muted)', minWidth: 68, fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                {getTimeStr(event.timestamp)}
              </span>
              <span style={{
                color: event.is_suspicious ? 'var(--accent-red)' : 'var(--text-primary)',
                fontWeight: event.is_suspicious ? 600 : 400,
                minWidth: 150,
                fontSize: '0.76rem',
              }}>
                {event.action}
              </span>
              {event.is_suspicious && event.severity && (
                <span className={`badge badge-${event.severity}`}>{event.severity}</span>
              )}
              {event.user && (
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem' }}>
                  {event.user}
                </span>
              )}
              {event.ip_address && (
                <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
                  {event.ip_address}
                </span>
              )}
              {event.process && (
                <span style={{ color: 'var(--text-muted)', fontSize: '0.68rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={event.process}>
                  [{event.process}]
                </span>
              )}
              {event.mitre_technique && <span className="mitre-tag">{event.mitre_technique}</span>}
            </div>
          ))}
          <div ref={feedEndRef} />
        </div>
      </div>
    </div>
  );
}
