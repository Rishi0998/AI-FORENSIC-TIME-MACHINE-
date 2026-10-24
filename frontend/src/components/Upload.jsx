import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { uploadLogs, extractLocalChannel } from '../api';

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
    setLoading(true);
    setError(null);
    try {
      const result = await uploadLogs(file);
      onAnalysisComplete(result);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze logs');
    } finally {
      setLoading(false);
    }
  };

  const handleExtractWindows = async (channelId) => {
    const channel = winChannels.find(c => c.id === channelId);
    if (!channel || !channel.available) {
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
    try {
      const result = await extractLocalChannel(channelId);
      onAnalysisComplete(result);
    } catch (err) {
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
      <div className="card fade-in">
        <div className="loading-state">
          <div className="spinner"></div>
          <div className="loading-text">
            {extracting
              ? `Extracting live system logs from ${winChannels.find(c => c.id === extracting)?.name || extracting}...`
              : 'Processing real logs — parsing events, detecting threats, constructing attack graph...'}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in">
      {/* ── Live Monitor Banner ─────────────────────────────────── */}
      <div 
        className="card" 
        style={{ 
          marginBottom: 20, 
          background: 'linear-gradient(135deg, rgba(0,242,255,0.08) 0%, rgba(138,43,226,0.08) 100%)',
          border: '1px solid rgba(0,242,255,0.25)',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '18px 24px'
        }}
        onClick={() => navigate('/app/monitor')}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ 
            width: 44, 
            height: 44, 
            borderRadius: '50%', 
            background: 'rgba(0,242,255,0.15)', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            color: 'var(--accent-cyan)'
          }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/><path d="M12 2a15 15 0 0 1 4 10"/><circle cx="12" cy="12" r="2"/>
            </svg>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)' }}>Real-Time System Log Monitor</h3>
              <span className="live-tag" style={{ position: 'static' }}>
                <span className="live-dot"></span>
                ACTIVE WEBSOCKET
              </span>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Watch live security and system events stream directly from your machine with continuous threat detection.
            </p>
          </div>
        </div>
        <button className="btn btn-primary" style={{ padding: '8px 18px', fontSize: '0.8rem' }} onClick={(e) => { e.stopPropagation(); navigate('/app/monitor'); }}>
          Open Monitor →
        </button>
      </div>

      {/* ── File Upload Zone ────────────────────────────────────── */}
      <div
        className={`upload-zone ${dragOver ? 'dragover' : ''}`}
        onDrop={onDrop}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onClick={() => fileInput.current?.click()}
      >
        <div className="upload-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
        </div>
        <h3>Drop real log files here or click to upload</h3>
        <p>Supports raw production logs (.log, .txt, .csv, syslog, auth.log, Windows Event text exports)</p>
        <input ref={fileInput} type="file" accept=".log,.txt,.csv" style={{ display: 'none' }} onChange={(e) => e.target.files[0] && handleFile(e.target.files[0])} />
      </div>

      {error && (
        <div style={{ marginTop: 12, padding: '12px 16px', background: 'var(--accent-red-dim)', borderRadius: 'var(--radius-md)', color: 'var(--accent-red)', fontSize: '0.82rem', border: '1px solid rgba(239,68,68,0.2)' }}>
          {error}
        </div>
      )}

      {/* ── Extract System Logs Banner ────────────────────────────── */}
      <div
        className="extract-system-banner"
        onClick={() => setShowExtract(!showExtract)}
        style={{ marginTop: 24 }}
      >
        <div className="extract-banner-left">
          <div className="extract-banner-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
          </div>
          <div>
            <h3>Extract Live Logs from This Machine</h3>
            <p>Directly ingest real event channels from this local operating system for instant forensics</p>
          </div>
        </div>
        <div className="extract-banner-action">
          <span className="live-tag" style={{ position: 'static' }}>
            <span className="live-dot"></span>
            LIVE HOST
          </span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
            style={{ transition: 'transform 0.2s', transform: showExtract ? 'rotate(180deg)' : 'rotate(0deg)' }}>
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </div>
      </div>

      {/* ── Live Windows Channels Grid ────────────────────────────── */}
      {showExtract && (
        <div className="extract-channels-panel fade-in">
          {winChannels.length === 0 ? (
            <div className="extract-empty">
              <div className="spinner" style={{ width: 20, height: 20, borderWidth: 2, marginBottom: 8 }}></div>
              <p>Scanning local event channels...</p>
            </div>
          ) : (
            <div className="extract-grid">
              {winChannels.map(ch => (
                <div
                  key={ch.id}
                  className={`extract-card ${!ch.available ? 'disabled' : ''} ${extracting === ch.id ? 'extracting' : ''}`}
                  onClick={() => !extracting ? handleExtractWindows(ch.id) : null}
                  style={{ cursor: extracting ? 'wait' : ch.available ? 'pointer' : 'pointer' }}
                >
                  <div className="extract-card-header">
                    <h4>{ch.name}</h4>
                    {ch.available ? (
                      <span className="badge badge-success">Available</span>
                    ) : ch.needs_admin ? (
                      <span className="badge badge-high" title="Requires running backend as Administrator">🔒 Admin</span>
                    ) : (
                      <span className="badge badge-medium">Empty</span>
                    )}
                  </div>
                  <p className="extract-card-desc">{ch.description}</p>
                  <div className="extract-card-footer">
                    <span className="extract-channel-name">{ch.channel}</span>
                    {ch.event_count > 0 && (
                      <span className="extract-event-count">{ch.event_count.toLocaleString()} real events</span>
                    )}
                  </div>
                  {extracting === ch.id && (
                    <div className="extract-loading-overlay">
                      <div className="spinner" style={{ width: 20, height: 20, borderWidth: 2 }}></div>
                      <span>Ingesting live channel...</span>
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
