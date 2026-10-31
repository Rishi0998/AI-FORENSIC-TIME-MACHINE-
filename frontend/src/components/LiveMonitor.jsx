import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { analyzeLiveStream } from '../api';
import { playCyberClick, playThreatAlert, playWarpEffect } from '../cyberAudio';
import LogExplanationCard from './LogExplanationCard';

const getWsUrl = () => {
  if (import.meta.env.VITE_API_BASE) {
    return import.meta.env.VITE_API_BASE.replace(/^http/, 'ws') + '/ws/monitor';
  }
  if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
    return `ws://127.0.0.1:8000/api/ws/monitor`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
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
  const [hoveredBlip, setHoveredBlip] = useState(null);
  const [coalesceDuplicates, setCoalesceDuplicates] = useState(true);
  const [expandedLiveIndex, setExpandedLiveIndex] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const wsRef = useRef(null);
  const feedEndRef = useRef(null);
  const reconnectRef = useRef(null);
  const navigate = useNavigate();

  const connect = useCallback(() => {
    // Prevent duplicate connections if already open or connecting
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }
    clearTimeout(reconnectRef.current);

    if (wsRef.current) {
      const old = wsRef.current;
      wsRef.current = null;
      old.onopen = null;
      old.onmessage = null;
      old.onerror = null;
      old.onclose = null;
      old.close();
    }

    setStatusText('INITIATING TELEMETRY LINK...');
    setError(null);

    try {
      const ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        if (wsRef.current !== ws) return;
        setConnected(true);
        setStatusText('LIVE STREAMING HOST SYSTEM EVENTS // CHRONO-RADAR ACTIVE');
        setError(null);
      };

      ws.onmessage = (e) => {
        if (wsRef.current !== ws) return;
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
              message: evt.message || null,
              event_id: evt.event_id || null,
              record_id: evt.record_id || null,
              severity: evt.severity || 'low',
              is_suspicious: evt.is_suspicious || false,
              detection_rule: evt.detection_rule || null,
              mitre_technique: evt.mitre_technique || null,
              raw_log: evt.raw_log || '',
            };

            if (normalizedEvent.is_suspicious) {
              playThreatAlert();
            }

            setEvents(prev => {
              const next = [...prev, normalizedEvent];
              return next.length > 500 ? next.slice(-500) : next;
            });
            if (data.stats) setStats(data.stats);
          } else if (data.type === 'status') {
            setStatusText(data.message || 'Connected to Host Monitor');
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
        if (wsRef.current === ws) {
          wsRef.current = null;
          setConnected(false);
          setStatusText('TELEMETRY DISCONNECTED // RETRYING');
          clearTimeout(reconnectRef.current);
          reconnectRef.current = setTimeout(connect, 3500);
        }
      };

      ws.onerror = () => {
        if (wsRef.current === ws) {
          setError('WebSocket telemetry error. Verify backend server is active on port 8000.');
          setConnected(false);
        }
      };

      wsRef.current = ws;
    } catch (err) {
      setError(`Connection error: ${err.message}`);
    }
  }, []);

  const disconnect = () => {
    clearTimeout(reconnectRef.current);
    if (wsRef.current) {
      const ws = wsRef.current;
      wsRef.current = null;
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      ws.close();
    }
    setConnected(false);
    setStatusText('TELEMETRY PAUSED');
  };

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectRef.current);
      if (wsRef.current) {
        const ws = wsRef.current;
        wsRef.current = null;
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
      }
    };
  }, [connect]);

  useEffect(() => {
    if (autoScroll && feedEndRef.current) feedEndRef.current.scrollIntoView({ behavior: 'smooth' });
  }, [events, autoScroll]);

  const handleAnalyzeStream = async () => {
    if (events.length === 0) return;
    playWarpEffect();
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

  // Intelligently coalesce consecutive burst duplicates into single row with repeat counter
  const displayedEvents = useMemo(() => {
    if (!coalesceDuplicates) return filtered;
    const coalesced = [];
    for (const evt of filtered) {
      if (coalesced.length > 0) {
        const prev = coalesced[coalesced.length - 1];
        const isSameAction = prev.action === evt.action;
        const isSameProcess = prev.process === evt.process;
        const isSameUser = (prev.user || '') === (evt.user || '');
        const isSameEventId = (prev.event_id || '') === (evt.event_id || '');
        const isSameRule = (prev.detection_rule || '') === (evt.detection_rule || '');

        if (isSameAction && isSameProcess && isSameUser && isSameEventId && isSameRule) {
          prev.repeats = (prev.repeats || 1) + 1;
          prev.last_timestamp = evt.timestamp;
          continue;
        }
      }
      coalesced.push({ ...evt, repeats: 1 });
    }
    return coalesced;
  }, [filtered, coalesceDuplicates]);

  const getTimeStr = (ts) => {
    if (!ts) return '--:--:--';
    const parts = ts.split('T');
    if (parts.length > 1) return parts[1].substring(0, 8);
    const tparts = ts.split(' ');
    if (tparts.length > 1) return tparts[1].substring(0, 8);
    return ts.substring(0, 8);
  };

  // Convert recent stream events into stable polar radar coordinates
  const radarBlips = useMemo(() => {
    const recent = events.slice(-24);
    return recent.map((evt, idx) => {
      const str = `${evt.action || ''}_${evt.process || ''}_${evt.user || ''}_${idx}`;
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = (hash << 5) - hash + str.charCodeAt(i);
        hash |= 0;
      }
      const angle = ((Math.abs(hash) % 360) * Math.PI) / 180;
      const r = evt.is_suspicious 
        ? 22 + (Math.abs(hash >> 3) % 18) 
        : 14 + (Math.abs(hash >> 4) % 25);
      const x = Math.min(88, Math.max(12, 50 + r * Math.cos(angle)));
      const y = Math.min(88, Math.max(12, 50 + r * Math.sin(angle)));
      return {
        id: `${idx}_${evt.timestamp}_${evt.action}`,
        x,
        y,
        isThreat: !!evt.is_suspicious,
        severity: evt.severity || 'low',
        action: evt.action,
        process: evt.process,
        user: evt.user,
        rule: evt.detection_rule || evt.mitre_technique || evt.action,
        time: getTimeStr(evt.timestamp),
      };
    });
  }, [events]);

  const getTooltipStyle = (blip) => {
    if (!blip) return {};
    const isTop = blip.y < 45;
    const vStyle = isTop 
      ? { top: `calc(${blip.y}% + 14px)` } 
      : { bottom: `calc(${100 - blip.y}% + 14px)` };

    let hStyle = {};
    if (blip.x > 68) {
      hStyle = { right: `calc(${100 - blip.x}% - 14px)` };
    } else if (blip.x < 32) {
      hStyle = { left: `calc(${blip.x}% - 14px)` };
    } else {
      hStyle = { left: `${blip.x}%`, transform: 'translateX(-50%)' };
    }

    return {
      ...vStyle,
      ...hStyle,
    };
  };

  return (
    <div className="fade-in">
      {/* Top Holographic Radar + Telemetry Dashboard */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <span className={`status-dot ${connected ? 'online' : 'offline'}`}></span>
            CHRONO RADAR // LIVE HOST SURVEILLANCE
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary"
              disabled={events.length === 0 || analyzing}
              onClick={handleAnalyzeStream}
            >
              {analyzing ? 'WARP ANALYZING...' : `⚡ WARP TO TIME MACHINE (${events.length})`}
            </button>
            {!connected ? (
              <button className="btn btn-outline btn-sm" onClick={() => { playCyberClick(); connect(); }}>CONNECT</button>
            ) : (
              <button className="btn btn-danger btn-sm" onClick={() => { playCyberClick(); disconnect(); }}>PAUSE</button>
            )}
            {events.length > 0 && (
              <button className="btn btn-ghost btn-sm" onClick={() => { playCyberClick(); setEvents([]); }}>CLEAR</button>
            )}
          </div>
        </div>

        {/* Radar Screen + Live Diagnostics HUD */}
        <div className="radar-screen-container">
          <div className="radar-column">
            <div className="radar-frame">
              <div className="radar-screen">
                <div className="radar-ring r1"></div>
                <div className="radar-ring r2"></div>
                <div className="radar-ring r3"></div>
                <div className="radar-crosshair-x"></div>
                <div className="radar-crosshair-y"></div>
                <div className="radar-crosshair-diag1"></div>
                <div className="radar-crosshair-diag2"></div>
                <div className="radar-center-dot" title="Host Sensor Origin"></div>

                <span className="radar-cardinal n">N 000°</span>
                <span className="radar-cardinal e">E 090°</span>
                <span className="radar-cardinal s">S 180°</span>
                <span className="radar-cardinal w">W 270°</span>

                {connected && <div className="radar-sweep-beam"></div>}

                {/* Target Blips */}
                {connected && radarBlips.map((blip) => (
                  <div
                    key={blip.id}
                    className={`radar-blip ${blip.isThreat ? 'threat' : 'telemetry'} ${hoveredBlip?.id === blip.id ? 'active-target' : ''}`}
                    style={{ left: `${blip.x}%`, top: `${blip.y}%` }}
                    onMouseEnter={() => setHoveredBlip(blip)}
                    onMouseLeave={() => setHoveredBlip(null)}
                    onClick={() => {
                      playCyberClick();
                      if (blip.isThreat) setFilter('suspicious');
                    }}
                  />
                ))}
              </div>

              {/* Floating Smart HUD Tooltip: Unclipped outside circular screen */}
              {connected && hoveredBlip && (
                <div
                  className={`radar-floating-hud ${hoveredBlip.isThreat ? 'threat-hud' : ''}`}
                  style={getTooltipStyle(hoveredBlip)}
                >
                  <div className="hud-header">
                    <span className="hud-icon">{hoveredBlip.isThreat ? '🚨' : '⚡'}</span>
                    <span className="hud-title">{hoveredBlip.isThreat ? 'TARGET IOC DETECTED' : 'SYSTEM TELEMETRY'}</span>
                    <span className={`hud-badge ${hoveredBlip.isThreat ? 'badge-danger' : 'badge-cyan'}`}>
                      {hoveredBlip.severity?.toUpperCase()}
                    </span>
                  </div>
                  <div className="hud-body">
                    <div className="hud-action" title={hoveredBlip.action || hoveredBlip.rule}>
                      {hoveredBlip.rule || hoveredBlip.action}
                    </div>
                    {hoveredBlip.process && (
                      <div className="hud-row">
                        <span className="hud-label">PROCESS:</span>
                        <span className="hud-val">{hoveredBlip.process}</span>
                      </div>
                    )}
                    {hoveredBlip.user && (
                      <div className="hud-row">
                        <span className="hud-label">USER:</span>
                        <span className="hud-val">{hoveredBlip.user}</span>
                      </div>
                    )}
                    <div className="hud-row">
                      <span className="hud-label">TIME:</span>
                      <span className="hud-val">{hoveredBlip.time}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Radar Status Bar outside circular screen */}
            <div className="radar-status-bar">
              <span className={`radar-indicator-dot ${connected ? 'active' : ''}`}></span>
              <span className="radar-status-label">
                {connected ? `SCANNING 360° // ${radarBlips.filter(b => b.isThreat).length} IOC` : 'RADAR SYSTEM OFFLINE'}
              </span>
            </div>
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span className="badge badge-info" style={{ letterSpacing: '0.1em' }}>LIVE FEED</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--accent-cyan)' }}>
                  {statusText}
                </span>
              </div>
              {hoveredBlip && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px',
                  background: hoveredBlip.isThreat ? 'rgba(255,42,109,0.12)' : 'rgba(0,242,255,0.08)',
                  border: `1px solid ${hoveredBlip.isThreat ? 'rgba(255,42,109,0.4)' : 'rgba(0,242,255,0.3)'}`,
                  borderRadius: 6, marginBottom: 10, fontFamily: 'var(--font-mono)', fontSize: '0.74rem',
                  animation: 'hudFadeIn 0.15s ease-out'
                }}>
                  <span style={{ color: hoveredBlip.isThreat ? '#ff2a6d' : 'var(--accent-cyan)', fontWeight: 700 }}>
                    {hoveredBlip.isThreat ? '🚨 TARGET LOCK:' : '⚡ SENSOR ACQUIRED:'}
                  </span>
                  <span style={{ color: '#fff' }}>{hoveredBlip.rule || hoveredBlip.action}</span>
                  {hoveredBlip.process && <span style={{ color: 'var(--text-muted)' }}>({hoveredBlip.process})</span>}
                  <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.68rem' }}>{hoveredBlip.time}</span>
                </div>
              )}
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Streaming live Windows security and system telemetry directly from the host operating system.
                Autonomous heuristics scan each incoming packet against 20+ MITRE ATT&CK signatures in real time.
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10, marginTop: 14 }}>
              <div className="filter-group-cyber">
                <button
                  className={`filter-btn-cyber ${filter === 'all' ? 'active' : ''}`}
                  onClick={() => { playCyberClick(); setFilter('all'); }}
                >
                  <span>ALL TELEMETRY</span>
                  <span className="filter-count-badge">{events.length}</span>
                </button>
                <button
                  className={`filter-btn-cyber danger ${filter === 'suspicious' ? 'active' : ''}`}
                  onClick={() => { playThreatAlert(); setFilter('suspicious'); }}
                >
                  <span>IOC DETECTIONS</span>
                  <span className="filter-count-badge" style={{ color: suspiciousCount > 0 ? '#ff0055' : undefined }}>
                    {suspiciousCount}
                  </span>
                </button>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.74rem', color: 'var(--text-secondary)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
                  <input type="checkbox" checked={coalesceDuplicates} onChange={(e) => setCoalesceDuplicates(e.target.checked)} />
                  COALESCE REPEATS
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.74rem', color: 'var(--text-secondary)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
                  <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
                  AUTO-SCROLL
                </label>
              </div>
            </div>
          </div>
        </div>

        {error && (
          <div style={{ marginTop: 12, padding: '10px 14px', background: 'var(--accent-red-dim)', border: '1px solid var(--accent-red)', borderRadius: 'var(--radius-sm)', color: 'var(--accent-red)', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            [ERROR] {error}
          </div>
        )}
      </div>

      {/* Real-time stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">
            <span>TOTAL TELEMETRY</span>
            <span style={{ color: 'var(--accent-cyan)' }}>[PKT]</span>
          </div>
          <div className="stat-value info">{stats.total_events || events.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <span>IOC DETECTIONS</span>
            <span style={{ color: 'var(--accent-red)' }}>[ALERT]</span>
          </div>
          <div className="stat-value danger">{suspiciousCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <span>BUFFER CAPACITY</span>
            <span>[FIFO]</span>
          </div>
          <div className="stat-value">{events.length}/500</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <span>THREAT DENSITY</span>
            <span>[RATIO]</span>
          </div>
          <div className={`stat-value ${threatRate > 10 ? 'danger' : 'info'}`}>{threatRate}%</div>
        </div>
      </div>

      {/* Live Event Stream */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">LIVE TELEMETRY STREAM</div>
          <span className="card-subtitle">{displayedEvents.length} PACKETS DISPLAYED {coalesceDuplicates && `(${events.length} TOTAL)`}</span>
        </div>

        <div className="live-feed" style={{ maxHeight: '480px' }}>
          {!connected && events.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="1.5">
                  <circle cx="12" cy="12" r="10"/><path d="M12 2a15 15 0 0 1 4 10"/><circle cx="12" cy="12" r="2"/>
                </svg>
              </div>
              <h3 style={{ fontFamily: 'var(--font-display)', color: '#fff' }}>TELEMETRY STREAM OFFLINE</h3>
              <p>Click "CONNECT" above to establish live link with host event channels.</p>
            </div>
          )}

          {connected && events.length === 0 && (
            <div className="loading-state" style={{ padding: 40 }}>
              <div className="spinner"></div>
              <div className="loading-text" style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                LISTENING FOR REAL-TIME HOST SYSTEM TELEMETRY...
              </div>
            </div>
          )}

          {displayedEvents.map((event, i) => {
            const isExpanded = expandedLiveIndex === i;
            return (
              <div
                key={i}
                className={`live-event ${event.is_suspicious ? 'threat' : ''} ${isExpanded ? 'expanded' : ''}`}
                style={{ 
                  animation: i === displayedEvents.length - 1 ? 'fadeIn 0.2s ease' : 'none',
                  flexDirection: isExpanded ? 'column' : 'row',
                  alignItems: isExpanded ? 'stretch' : 'center',
                  cursor: 'pointer'
                }}
                onClick={() => {
                  playCyberClick();
                  setExpandedLiveIndex(isExpanded ? null : i);
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', flexWrap: 'wrap' }}>
                  <span style={{ color: 'var(--accent-cyan)', minWidth: 74, fontFamily: 'var(--font-mono)', fontSize: '0.72rem', fontWeight: 600 }}>
                    {getTimeStr(event.timestamp)}
                  </span>
                  <span style={{
                    color: event.is_suspicious ? 'var(--accent-red)' : '#ffffff',
                    fontWeight: 700,
                    minWidth: 160,
                    fontSize: '0.92rem',
                    fontFamily: 'var(--font-tech)',
                    letterSpacing: '0.04em',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6
                  }}>
                    {event.action}
                    {event.repeats > 1 && (
                      <span 
                        style={{ 
                          background: 'rgba(0, 242, 255, 0.16)', 
                          color: 'var(--accent-cyan)', 
                          border: '1px solid rgba(0, 242, 255, 0.45)',
                          borderRadius: 3,
                          fontWeight: 700, 
                          fontSize: '0.66rem',
                          padding: '1px 5px',
                          fontFamily: 'var(--font-mono)'
                        }}
                        title={`Aggregated burst: ${event.repeats} consecutive events`}
                      >
                        ×{event.repeats}
                      </span>
                    )}
                  </span>
                  {event.is_suspicious && event.severity && (
                    <span className={`badge badge-${event.severity}`}>{event.severity}</span>
                  )}
                  {event.event_id && (
                    <span style={{ color: 'var(--accent-cyan)', opacity: 0.75, fontSize: '0.68rem', fontFamily: 'var(--font-mono)' }}>
                      ID:{event.event_id}
                    </span>
                  )}
                  {event.user && (
                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.74rem', background: 'rgba(0,0,0,0.35)', padding: '2px 6px', borderRadius: 3 }}>
                      USER: {event.user}
                    </span>
                  )}
                  {event.ip_address && (
                    <span style={{ color: 'var(--accent-blue)', fontSize: '0.74rem', fontFamily: 'var(--font-mono)' }}>
                      IP: {event.ip_address}
                    </span>
                  )}
                  {event.process && (
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)' }} title={event.process}>
                      CMD: {event.process}
                    </span>
                  )}
                  {event.message && (
                    <span style={{ color: 'var(--text-secondary)', opacity: 0.8, fontSize: '0.68rem', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)' }} title={event.message}>
                      MSG: {event.message}
                    </span>
                  )}
                  {event.mitre_technique && <span className="mitre-tag">{event.mitre_technique}</span>}
                  
                  <span style={{ marginLeft: 'auto', fontSize: '0.65rem', color: isExpanded ? 'var(--accent-cyan)' : 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {isExpanded ? '▲ COLLAPSE' : '▼ DETAILS'}
                  </span>
                </div>

                {isExpanded && (
                  <div style={{ marginTop: 8, width: '100%' }}>
                    <LogExplanationCard
                      event={event}
                      globalIndex={i}
                      copiedId={copiedId}
                      copyLog={(text, id) => {
                        playCyberClick();
                        navigator.clipboard?.writeText(text);
                        setCopiedId(id);
                        setTimeout(() => setCopiedId(null), 1500);
                      }}
                    />
                  </div>
                )}
              </div>
            );
          })}
          <div ref={feedEndRef} />
        </div>
      </div>
    </div>
  );
}
