import { useState, useEffect, useMemo } from 'react';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend, Filler } from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { getTimeline } from '../api';
import { playCyberClick, playTargetLock, playThreatAlert } from '../cyberAudio';
import CyberGlitchText from './CyberGlitchText';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend, Filler);

// Electric Neon Cyberpunk Palette (High-Voltage contrast)
const SEVERITY_COLORS = {
  low: 'rgba(0, 242, 255, 0.72)',       // Electric Cyber Cyan
  medium: 'rgba(255, 187, 0, 0.85)',    // Glowing Cyber Amber
  high: 'rgba(255, 94, 0, 0.92)',       // Vivid Plasma Orange
  critical: 'rgba(255, 0, 85, 0.98)',   // Neon Crimson Laser
};

const SEVERITY_BORDERS = {
  low: '#00f2fe',
  medium: '#ffbb00',
  high: '#ff5e00',
  critical: '#ff0055',
};

const PAGE_SIZE = 100;

export default function Timeline({ sessionId }) {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(0);
  const [expandedRow, setExpandedRow] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    getTimeline(sessionId).then(data => {
      setTimeline(data.timeline || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [sessionId]);

  // Telemetry counts by severity
  const counts = useMemo(() => {
    const c = { all: timeline.length, critical: 0, high: 0, medium: 0, low: 0, suspicious: 0 };
    timeline.forEach(e => {
      if (e.is_suspicious) c.suspicious++;
      const s = (e.severity || 'low').toLowerCase();
      if (c[s] !== undefined) c[s]++;
    });
    return c;
  }, [timeline]);

  // Filtered data
  const filtered = useMemo(() => {
    let result = timeline;
    if (filter === 'suspicious') result = result.filter(e => e.is_suspicious);
    if (severityFilter !== 'all') result = result.filter(e => (e.severity || 'low').toLowerCase() === severityFilter);
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(e =>
        (e.action || '').toLowerCase().includes(term) ||
        (e.user || '').toLowerCase().includes(term) ||
        (e.ip_address || '').toLowerCase().includes(term) ||
        (e.process || '').toLowerCase().includes(term) ||
        (e.detection_rule || '').toLowerCase().includes(term) ||
        (e.mitre_technique || '').toLowerCase().includes(term) ||
        (e.timestamp || '').toLowerCase().includes(term)
      );
    }
    return result;
  }, [timeline, filter, searchTerm, severityFilter]);

  // Paginated data
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginatedEvents = useMemo(() => {
    const start = page * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [filtered, page]);

  // Reset page on filter change
  useEffect(() => { setPage(0); }, [filter, searchTerm, severityFilter]);

  // Chart data
  const chartConfig = useMemo(() => {
    const timeGroups = {};
    filtered.forEach(e => {
      const t = e.timestamp?.substring(0, 16) || 'unknown';
      if (!timeGroups[t]) timeGroups[t] = { low: 0, medium: 0, high: 0, critical: 0 };
      const sev = (e.severity || 'low').toLowerCase();
      if (timeGroups[t][sev] !== undefined) {
        timeGroups[t][sev]++;
      } else {
        timeGroups[t].low++;
      }
    });

    const labels = Object.keys(timeGroups).map(t => t.split('T').pop() || t.split(' ').pop() || t);
    return {
      labels,
      datasets: [
        { 
          label: 'Critical', 
          data: Object.values(timeGroups).map(g => g.critical), 
          backgroundColor: SEVERITY_COLORS.critical, 
          borderColor: SEVERITY_BORDERS.critical, 
          borderWidth: 1.5, 
          stack: 's',
          hoverBackgroundColor: '#ff0055'
        },
        { 
          label: 'High', 
          data: Object.values(timeGroups).map(g => g.high), 
          backgroundColor: SEVERITY_COLORS.high, 
          borderColor: SEVERITY_BORDERS.high, 
          borderWidth: 1.5, 
          stack: 's',
          hoverBackgroundColor: '#ff5e00'
        },
        { 
          label: 'Medium', 
          data: Object.values(timeGroups).map(g => g.medium), 
          backgroundColor: SEVERITY_COLORS.medium, 
          borderColor: SEVERITY_BORDERS.medium, 
          borderWidth: 1.5, 
          stack: 's',
          hoverBackgroundColor: '#ffbb00'
        },
        { 
          label: 'Low', 
          data: Object.values(timeGroups).map(g => g.low), 
          backgroundColor: SEVERITY_COLORS.low, 
          borderColor: SEVERITY_BORDERS.low, 
          borderWidth: 1.5, 
          stack: 's',
          hoverBackgroundColor: '#00f2fe'
        },
      ],
    };
  }, [filtered]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    onClick: (evt, elements) => {
      if (elements && elements.length > 0) {
        const idx = elements[0].index;
        const bucketTime = chartConfig.labels[idx];
        if (bucketTime) {
          playTargetLock();
          setSearchTerm(bucketTime);
        }
      }
    },
    plugins: {
      legend: { 
        position: 'top', 
        labels: { 
          color: '#cbd5e1', 
          font: { size: 11, family: 'Rajdhani, sans-serif', weight: '600' }, 
          padding: 16, 
          usePointStyle: true, 
          pointStyle: 'circle' 
        } 
      },
      tooltip: {
        backgroundColor: 'rgba(4,7,20,0.96)', 
        borderColor: 'rgba(0,242,255,0.6)', 
        borderWidth: 1.5,
        titleColor: '#00f2fe', 
        bodyColor: '#e2e8f0',
        titleFont: { family: 'Rajdhani, sans-serif', weight: '700', size: 13 }, 
        bodyFont: { family: 'JetBrains Mono', size: 11 },
        padding: 12, 
        cornerRadius: 2,
        callbacks: {
          label: (context) => ` ${context.dataset.label}: ${context.raw} events (Click to isolate)`
        }
      },
    },
    scales: {
      x: { 
        stacked: true, 
        ticks: { color: '#64748b', font: { size: 9, family: 'JetBrains Mono' }, maxRotation: 45 }, 
        grid: { color: 'rgba(0,242,255,0.06)' } 
      },
      y: { 
        stacked: true, 
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono' } }, 
        grid: { color: 'rgba(0,242,255,0.06)' } 
      },
    },
  };

  const copyLog = (text, id) => {
    playCyberClick();
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  if (loading) return (
    <div className="card fade-in" style={{ padding: '60px 24px', textAlign: 'center', border: '1px solid rgba(0,242,254,0.3)' }}>
      <div className="loading-state">
        <div className="spinner" style={{ width: 44, height: 44, borderColor: 'rgba(0,242,255,0.2)', borderTopColor: 'var(--accent-cyan)' }}></div>
        <div className="loading-text" style={{ fontFamily: 'var(--font-heading)', color: 'var(--accent-cyan)', letterSpacing: '0.12em', marginTop: 14 }}>
          PARSING TEMPORAL EVENT MATRIX...
        </div>
      </div>
    </div>
  );

  return (
    <div className="fade-in">
      {/* ── 1. Cybernetic Temporal Incident Density Chart ─────────────────── */}
      <div className="timeline-chart-card">
        <div className="chart-scanline" />
        <div className="card-header" style={{ padding: '16px 20px 10px', borderBottom: '1px solid rgba(0, 242, 254, 0.12)' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--accent-cyan)', letterSpacing: '0.12em', marginBottom: 2 }}>
              [ 0xTEMPORAL_RADAR // SPECTRUM ANALYSIS ]
            </div>
            <div className="card-title" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', color: '#fff', fontSize: '1.15rem' }}>
              <CyberGlitchText text="TEMPORAL INCIDENT DENSITY" />
            </div>
            <p style={{ margin: '3px 0 0 0', fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              EVENT FREQUENCY BUCKETED ACROSS INCIDENT SPECTRUM &bull; CLICK ANY BAR TO ISOLATE TIME WINDOW
            </p>
          </div>
          <div className="filter-group-cyber">
            <button 
              className={`filter-btn-cyber ${filter === 'all' ? 'active' : ''}`} 
              onClick={() => { playCyberClick(); setFilter('all'); }}
            >
              <span>ALL TELEMETRY</span>
              <span className="filter-count-badge">{timeline.length}</span>
            </button>
            <button 
              className={`filter-btn-cyber danger ${filter === 'suspicious' ? 'active' : ''}`} 
              onClick={() => { playThreatAlert(); setFilter('suspicious'); }}
            >
              <span>⚠ THREAT SIGNALS</span>
              <span className="filter-count-badge" style={{ color: counts.suspicious > 0 ? '#ff0055' : undefined }}>
                {counts.suspicious}
              </span>
            </button>
          </div>
        </div>
        <div style={{ height: 280, padding: '10px 16px 14px', position: 'relative' }}>
          <Bar data={chartConfig} options={chartOptions} />
        </div>
      </div>

      {/* ── 2. Tactical SOC Command Terminal Search & Filter Console ──────── */}
      <div className="timeline-terminal-console">
        <div className="terminal-prompt-bar">
          <div className="terminal-prompt-label">
            <span className="pulse-dot" style={{ background: 'var(--accent-cyan)' }} />
            <span>CHRONOS://SOC-STREAM&gt;</span>
          </div>

          <div className="terminal-input-wrapper">
            <input
              type="text"
              className="terminal-search-input"
              placeholder="SEARCH TELEMETRY (ACTION, USER, IP, PROCESS, MITRE, TIME)..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
            {searchTerm && (
              <button 
                className="terminal-clear-btn" 
                onClick={() => { playCyberClick(); setSearchTerm(''); }}
                title="Clear search"
              >
                ✕ CLEAR
              </button>
            )}
          </div>

          {/* Severity Filter Pills with live counts */}
          <div className="filter-group-cyber">
            <button 
              className={`filter-btn-cyber ${severityFilter === 'all' ? 'active' : ''}`} 
              onClick={() => { playCyberClick(); setSeverityFilter('all'); }}
            >
              <span>ALL SEV</span>
              <span className="filter-count-badge">{counts.all}</span>
            </button>

            <button 
              className={`filter-btn-cyber danger ${severityFilter === 'critical' ? 'active' : ''}`} 
              onClick={() => { playThreatAlert(); setSeverityFilter('critical'); }}
            >
              <span>CRITICAL</span>
              <span className="filter-count-badge" style={{ color: counts.critical > 0 ? '#ff0055' : undefined }}>
                {counts.critical}
              </span>
            </button>

            <button 
              className={`filter-btn-cyber high ${severityFilter === 'high' ? 'active' : ''}`} 
              onClick={() => { playCyberClick(); setSeverityFilter('high'); }}
            >
              <span>HIGH</span>
              <span className="filter-count-badge" style={{ color: counts.high > 0 ? '#ff5e00' : undefined }}>
                {counts.high}
              </span>
            </button>

            <button 
              className={`filter-btn-cyber warning ${severityFilter === 'medium' ? 'active' : ''}`} 
              onClick={() => { playCyberClick(); setSeverityFilter('medium'); }}
            >
              <span>MEDIUM</span>
              <span className="filter-count-badge">{counts.medium}</span>
            </button>

            <button 
              className={`filter-btn-cyber ${severityFilter === 'low' ? 'active' : ''}`} 
              onClick={() => { playCyberClick(); setSeverityFilter('low'); }}
            >
              <span>LOW</span>
              <span className="filter-count-badge">{counts.low}</span>
            </button>
          </div>

          {/* Live Packet Counter & Quick Reset */}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
              ● {filtered.length} / {timeline.length} PACKETS LOCATED
            </span>
            {(searchTerm || severityFilter !== 'all' || filter !== 'all') && (
              <button
                onClick={() => {
                  playCyberClick();
                  setSearchTerm('');
                  setSeverityFilter('all');
                  setFilter('all');
                }}
                style={{
                  background: 'rgba(255, 0, 85, 0.15)',
                  border: '1px solid rgba(255, 0, 85, 0.4)',
                  color: '#ff0055',
                  padding: '3px 8px',
                  borderRadius: '2px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.66rem',
                  cursor: 'pointer'
                }}
              >
                RESET FILTERS
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── 3. Chrono Event Telemetry Stream (High-Tech Rows) ──────────────── */}
      <div className="card" style={{ border: '1px solid rgba(0, 242, 254, 0.22)', position: 'relative', overflow: 'hidden' }}>
        <div className="card-header" style={{ padding: '14px 18px', borderBottom: '1px solid rgba(0, 242, 254, 0.1)' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--accent-cyan)', letterSpacing: '0.12em' }}>
              [ 0xTELEMETRY_STREAM // AUDIT BUFFER ]
            </div>
            <div className="card-title" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', color: '#fff', fontSize: '1.05rem' }}>
              CHRONO EVENT TELEMETRY STREAM
            </div>
            <p style={{ margin: '3px 0 0 0', fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              DECODED AUDIT ARTIFACTS &bull; CLICK ANY ROW TO EXPAND DEEP FORENSIC DISASSEMBLY
            </p>
          </div>
          {totalPages > 1 && (
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <button className="btn btn-sm btn-outline" disabled={page === 0} onClick={() => { playCyberClick(); setPage(0); }}>|◀</button>
              <button className="btn btn-sm btn-outline" disabled={page === 0} onClick={() => { playCyberClick(); setPage(p => p - 1); }}>◀ PREV</button>
              <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', minWidth: 80, textAlign: 'center' }}>
                PAGE {page + 1} / {totalPages}
              </span>
              <button className="btn btn-sm btn-outline" disabled={page >= totalPages - 1} onClick={() => { playCyberClick(); setPage(p => p + 1); }}>NEXT ▶</button>
              <button className="btn btn-sm btn-outline" disabled={page >= totalPages - 1} onClick={() => { playCyberClick(); setPage(totalPages - 1); }}>▶|</button>
            </div>
          )}
        </div>

        <div className="event-list">
          {paginatedEvents.length === 0 && (
            <div className="empty-state" style={{ padding: 40 }}>
              <h3 style={{ fontFamily: 'var(--font-heading)', color: 'var(--accent-cyan)', letterSpacing: '0.08em' }}>NO CORRELATED TELEMETRY</h3>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Try adjusting your search criteria or filter severity level.
              </p>
            </div>
          )}

          {paginatedEvents.map((event, i) => {
            const globalIndex = page * PAGE_SIZE + i;
            const isExpanded = expandedRow === globalIndex;
            const sev = (event.severity || 'low').toLowerCase();

            return (
              <div
                key={globalIndex}
                className={`event-row-cyber ${event.is_suspicious ? 'suspicious' : ''} ${sev === 'critical' ? 'critical' : ''} ${isExpanded ? 'expanded' : ''}`}
                onClick={() => { playCyberClick(); setExpandedRow(isExpanded ? null : globalIndex); }}
                style={{
                  borderLeftColor: sev === 'critical' ? '#ff0055' : sev === 'high' ? '#ff5e00' : sev === 'medium' ? '#ffaa00' : isExpanded ? 'var(--accent-cyan)' : 'rgba(0, 242, 254, 0.4)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', flexWrap: 'wrap' }}>
                  <span className="event-time" style={{ color: 'var(--accent-cyan)', minWidth: 68, fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                    {event.timestamp?.split('T')[1]?.substring(0, 8) || event.timestamp || '—'}
                  </span>
                  <span className="event-action" style={{ color: '#fff', fontWeight: 600, fontSize: '0.82rem' }}>
                    {event.action}
                  </span>

                  <span className="event-meta" style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <span className={`stat-pill-cyber ${sev === 'critical' ? 'danger' : sev === 'high' ? 'danger' : sev === 'medium' ? 'warning' : ''}`} style={{ fontSize: '0.58rem' }}>
                      {sev.toUpperCase()}
                    </span>
                    {event.mitre_technique && (
                      <span className="stat-pill-cyber warning" style={{ fontSize: '0.58rem' }}>
                        MITRE:{event.mitre_technique}
                      </span>
                    )}
                    {event.user && (
                      <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.68rem', background: 'rgba(255,255,255,0.04)', padding: '2px 5px', borderRadius: 2 }}>
                        USER:{event.user}
                      </span>
                    )}
                    {event.ip_address && (
                      <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.68rem', background: 'rgba(0,242,254,0.06)', padding: '2px 5px', borderRadius: 2 }}>
                        IP:{event.ip_address}
                      </span>
                    )}
                    {event.process && (
                      <span style={{ color: '#00ff88', fontFamily: 'var(--font-mono)', fontSize: '0.68rem', background: 'rgba(0,255,136,0.06)', padding: '2px 5px', borderRadius: 2 }}>
                        PROC:{event.process}
                      </span>
                    )}
                    {event.detection_rule && (
                      <span style={{ color: 'var(--accent-purple)', fontSize: '0.68rem', fontFamily: 'var(--font-mono)', background: 'rgba(168,85,247,0.08)', padding: '2px 5px', borderRadius: 2 }}>
                        RULE:{event.detection_rule}
                      </span>
                    )}
                  </span>
                </div>

                {isExpanded && (
                  <div style={{ marginTop: 10, padding: '12px 14px', background: 'rgba(2,5,14,0.96)', border: '1px solid rgba(0,242,255,0.3)', borderRadius: '2px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8, borderBottom: '1px solid rgba(0,242,254,0.1)', paddingBottom: 6 }}>
                      <span style={{ fontSize: '0.68rem', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className="pulse-dot" style={{ background: 'var(--accent-cyan)' }} />
                        DECODED FORENSIC TELEMETRY BUFFER
                      </span>
                      <button
                        onClick={(e) => { e.stopPropagation(); copyLog(event.raw_log || JSON.stringify(event, null, 2), globalIndex); }}
                        className={`cyber-copy-btn ${copiedId === globalIndex ? 'copied' : ''}`}
                      >
                        {copiedId === globalIndex ? '✓ BUFFER COPIED' : '📋 COPY RAW PAYLOAD'}
                      </button>
                    </div>
                    <pre style={{ 
                      fontFamily: 'var(--font-mono)', 
                      fontSize: '0.72rem', 
                      color: '#94a3b8', 
                      overflowX: 'auto', 
                      whiteSpace: 'pre-wrap', 
                      wordBreak: 'break-all',
                      margin: 0,
                      lineHeight: 1.5,
                      maxHeight: 220
                    }}>
                      {event.raw_log || JSON.stringify(event, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Bottom Pagination */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8, padding: '14px 0', borderTop: '1px solid rgba(0,242,255,0.1)' }}>
            <button className="btn btn-sm btn-outline" disabled={page === 0} onClick={() => { playCyberClick(); setPage(0); }}>FIRST</button>
            <button className="btn btn-sm btn-outline" disabled={page === 0} onClick={() => { playCyberClick(); setPage(p => p - 1); }}>◀ PREV</button>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', margin: '0 8px' }}>
              EVENTS {page * PAGE_SIZE + 1} &ndash; {Math.min((page + 1) * PAGE_SIZE, filtered.length)} OF {filtered.length}
            </span>
            <button className="btn btn-sm btn-outline" disabled={page >= totalPages - 1} onClick={() => { playCyberClick(); setPage(p => p + 1); }}>NEXT ▶</button>
            <button className="btn btn-sm btn-outline" disabled={page >= totalPages - 1} onClick={() => { playCyberClick(); setPage(totalPages - 1); }}>LAST</button>
          </div>
        )}
      </div>
    </div>
  );
}
