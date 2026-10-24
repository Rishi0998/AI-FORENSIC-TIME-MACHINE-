import { useState, useEffect, useMemo } from 'react';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend, Filler } from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { getTimeline } from '../api';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend, Filler);

const SEVERITY_COLORS = {
  low: 'rgba(100,116,139,0.8)',
  medium: 'rgba(245,158,11,0.8)',
  high: 'rgba(249,115,22,0.8)',
  critical: 'rgba(239,68,68,0.8)',
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

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    getTimeline(sessionId).then(data => {
      setTimeline(data.timeline || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [sessionId]);

  // Filtered data
  const filtered = useMemo(() => {
    let result = timeline;
    if (filter === 'suspicious') result = result.filter(e => e.is_suspicious);
    if (severityFilter !== 'all') result = result.filter(e => e.severity === severityFilter);
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(e =>
        (e.action || '').toLowerCase().includes(term) ||
        (e.user || '').toLowerCase().includes(term) ||
        (e.ip_address || '').toLowerCase().includes(term) ||
        (e.process || '').toLowerCase().includes(term) ||
        (e.detection_rule || '').toLowerCase().includes(term) ||
        (e.mitre_technique || '').toLowerCase().includes(term)
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
      timeGroups[t][e.severity || 'low']++;
    });

    const labels = Object.keys(timeGroups).map(t => t.split('T').pop() || t.split(' ').pop() || t);
    return {
      labels,
      datasets: [
        { label: 'Critical', data: Object.values(timeGroups).map(g => g.critical), backgroundColor: SEVERITY_COLORS.critical, stack: 's' },
        { label: 'High', data: Object.values(timeGroups).map(g => g.high), backgroundColor: SEVERITY_COLORS.high, stack: 's' },
        { label: 'Medium', data: Object.values(timeGroups).map(g => g.medium), backgroundColor: SEVERITY_COLORS.medium, stack: 's' },
        { label: 'Low', data: Object.values(timeGroups).map(g => g.low), backgroundColor: SEVERITY_COLORS.low, stack: 's' },
      ],
    };
  }, [filtered]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top', labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' }, padding: 20, usePointStyle: true, pointStyle: 'circle' } },
      tooltip: {
        backgroundColor: 'rgba(10,14,23,0.95)', borderColor: 'rgba(59,130,246,0.3)', borderWidth: 1,
        titleColor: '#e2e8f0', bodyColor: '#94a3b8',
        titleFont: { family: 'Inter', weight: '600' }, bodyFont: { family: 'JetBrains Mono', size: 11 },
        padding: 12, cornerRadius: 6,
      },
    },
    scales: {
      x: { stacked: true, ticks: { color: '#64748b', font: { size: 9, family: 'JetBrains Mono' }, maxRotation: 45 }, grid: { color: 'rgba(100,116,139,0.06)' } },
      y: { stacked: true, ticks: { color: '#64748b', font: { family: 'JetBrains Mono' } }, grid: { color: 'rgba(100,116,139,0.06)' } },
    },
  };

  if (loading) return <div className="card"><div className="loading-state"><div className="spinner"></div><div className="loading-text">Loading timeline...</div></div></div>;

  const suspiciousCount = timeline.filter(e => e.is_suspicious).length;

  return (
    <div className="fade-in">
      {/* Chart */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Event Distribution</div>
          <div className="filter-group">
            <button className={`filter-btn ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>All ({timeline.length})</button>
            <button className={`filter-btn danger ${filter === 'suspicious' ? 'active' : ''}`} onClick={() => setFilter('suspicious')}>Threats ({suspiciousCount})</button>
          </div>
        </div>
        <div style={{ height: 300 }}>
          <Bar data={chartConfig} options={chartOptions} />
        </div>
      </div>

      {/* Filters & Search */}
      <div className="card" style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Search events (action, user, IP, process, MITRE)..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            style={{
              flex: '1 1 250px', padding: '7px 12px', background: 'var(--bg-input)', border: '1px solid var(--border-secondary)',
              borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '0.78rem', fontFamily: 'var(--font-primary)',
              outline: 'none',
            }}
          />
          <div className="filter-group">
            {['all', 'critical', 'high', 'medium', 'low'].map(s => (
              <button key={s} className={`filter-btn ${severityFilter === s ? 'active' : ''}`} onClick={() => setSeverityFilter(s)}>
                {s === 'all' ? 'All Sev.' : s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {filtered.length} results
          </span>
        </div>
      </div>

      {/* Event Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Event Log</div>
          {totalPages > 1 && (
            <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
              <button className="btn btn-sm btn-outline" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Prev</button>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', minWidth: 60, textAlign: 'center' }}>
                {page + 1}/{totalPages}
              </span>
              <button className="btn btn-sm btn-outline" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next</button>
            </div>
          )}
        </div>

        <div className="event-list">
          {paginatedEvents.length === 0 && (
            <div className="empty-state" style={{ padding: 32 }}>
              <h3>No matching events</h3>
              <p>Try adjusting your filters or search term.</p>
            </div>
          )}

          {paginatedEvents.map((event, i) => {
            const globalIndex = page * PAGE_SIZE + i;
            return (
              <div
                key={globalIndex}
                className={`event-row ${event.is_suspicious ? 'suspicious' : ''} ${event.severity === 'critical' ? 'critical' : ''}`}
                onClick={() => setExpandedRow(expandedRow === globalIndex ? null : globalIndex)}
                style={{ cursor: 'pointer', flexDirection: expandedRow === globalIndex ? 'column' : 'row', alignItems: expandedRow === globalIndex ? 'stretch' : 'center' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%' }}>
                  <span className="event-time">{event.timestamp?.split('T')[1]?.substring(0, 8) || '—'}</span>
                  <span className="event-action">{event.action}</span>
                  <span className="event-meta">
                    {event.is_suspicious && <span className={`badge badge-${event.severity}`}>{event.severity}</span>}
                    {event.mitre_technique && <span className="mitre-tag">{event.mitre_technique}</span>}
                    {event.user && <span>{event.user}</span>}
                    {event.ip_address && <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>{event.ip_address}</span>}
                    {event.process && <span style={{ color: 'var(--text-muted)' }}>{event.process}</span>}
                    {event.detection_rule && <span style={{ color: 'var(--accent-purple)', fontSize: '0.68rem' }}>{event.detection_rule}</span>}
                  </span>
                </div>
                {expandedRow === globalIndex && event.raw_log && (
                  <div style={{ marginTop: 6, padding: '8px 10px', background: 'var(--bg-primary)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                    {event.raw_log}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Bottom Pagination */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8, padding: '12px 0', borderTop: '1px solid var(--border-primary)' }}>
            <button className="btn btn-sm btn-outline" disabled={page === 0} onClick={() => setPage(0)}>First</button>
            <button className="btn btn-sm btn-outline" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Prev</button>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              Showing {page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
            </span>
            <button className="btn btn-sm btn-outline" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next</button>
            <button className="btn btn-sm btn-outline" disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>Last</button>
          </div>
        )}
      </div>
    </div>
  );
}
