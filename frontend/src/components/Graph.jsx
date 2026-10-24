import { useState, useEffect, useRef, useCallback } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { getGraph } from '../api';

try {
  if (typeof dagre === 'function') {
    cytoscape.use(dagre);
  } else if (dagre && typeof dagre.default === 'function') {
    cytoscape.use(dagre.default);
  }
} catch (e) {
  console.warn('Cytoscape dagre plugin registration:', e);
}

export default function Graph({ sessionId }) {
  const [graphData, setGraphData] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    getGraph(sessionId).then(data => {
      setGraphData(data.graph?.elements);
      setMetrics(data.graph?.metrics);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [sessionId]);

  const renderGraph = useCallback(() => {
    if (!containerRef.current || !graphData) return;
    if (cyRef.current) cyRef.current.destroy();

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...(graphData.nodes || []), ...(graphData.edges || [])],
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)', 'background-color': 'data(color)', 'color': '#e2e8f0',
            'text-valign': 'bottom', 'text-halign': 'center', 'font-size': '10px',
            'font-family': 'Inter, sans-serif', 'font-weight': '600', 'text-margin-y': 8,
            'text-outline-color': '#0a0e17', 'text-outline-width': 2,
            'width': 40, 'height': 40, 'border-width': 2, 'border-color': 'data(color)', 'border-opacity': 0.4,
          },
        },
        { selector: 'node[type="user"]', style: { 'shape': 'diamond', 'width': 45, 'height': 45 } },
        { selector: 'node[type="ip"]', style: { 'shape': 'ellipse', 'width': 42, 'height': 42 } },
        { selector: 'node[type="process"]', style: { 'shape': 'round-rectangle', 'width': 50, 'height': 35 } },
        {
          selector: 'edge',
          style: {
            'width': 'data(width)', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)',
            'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'label': 'data(label)',
            'font-size': '8px', 'font-family': 'JetBrains Mono, monospace', 'color': '#64748b',
            'text-rotation': 'autorotate', 'text-margin-y': -8, 'text-outline-color': '#0a0e17',
            'text-outline-width': 2, 'opacity': 0.8, 'arrow-scale': 1.2,
          },
        },
        { selector: 'node:active, node:selected', style: { 'border-width': 4, 'border-color': '#3b82f6', 'width': 55, 'height': 55 } },
      ],
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 60, rankSep: 100, edgeSep: 20, padding: 30 },
      minZoom: 0.3, maxZoom: 3, wheelSensitivity: 0.3,
    });

    cy.on('tap', 'node', (e) => {
      const node = e.target;
      setSelectedNode({
        id: node.id(), label: node.data('label'), type: node.data('type'),
        connections: node.connectedEdges().length,
        neighbors: node.neighborhood('node').map(n => ({ label: n.data('label'), type: n.data('type') })),
      });
    });
    cy.on('tap', (e) => { if (e.target === cy) setSelectedNode(null); });
    cyRef.current = cy;
  }, [graphData]);

  useEffect(() => { renderGraph(); }, [renderGraph]);

  const handleFit = () => cyRef.current?.fit(undefined, 30);
  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.7);

  if (loading) return <div className="card"><div className="loading-state"><div className="spinner"></div><div className="loading-text">Building attack graph...</div></div></div>;
  if (!graphData || graphData.nodes?.length === 0) return <div className="card"><div className="empty-state"><h3>No graph data available</h3></div></div>;

  return (
    <div className="fade-in">
      <div className="card">
        <div className="card-header">
          <div className="card-title">Attack Graph</div>
          <div className="graph-controls">
            <button className="btn btn-sm btn-outline" onClick={handleZoomIn}>+</button>
            <button className="btn btn-sm btn-outline" onClick={handleZoomOut}>-</button>
            <button className="btn btn-sm btn-outline" onClick={handleFit}>Fit</button>
          </div>
        </div>

        <div className="graph-legend">
          <span><div className="legend-dot" style={{ background: '#e74c3c', clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)' }}></div> Users</span>
          <span><div className="legend-dot" style={{ background: '#3498db', borderRadius: '50%' }}></div> IPs</span>
          <span><div className="legend-dot" style={{ background: '#2ecc71', borderRadius: '2px' }}></div> Processes</span>
          <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)' }}>
            {metrics?.node_count} nodes / {metrics?.edge_count} edges
          </span>
        </div>

        <div ref={containerRef} className="graph-container"></div>

        {selectedNode && (
          <div style={{ marginTop: 12, padding: 12, background: 'var(--accent-blue-dim)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(59,130,246,0.2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <strong>{selectedNode.label}</strong>
              <span className={`badge badge-${selectedNode.type === 'user' ? 'high' : selectedNode.type === 'ip' ? 'info' : 'low'}`}>{selectedNode.type}</span>
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              {selectedNode.connections} connection(s) &middot; Connected to: {selectedNode.neighbors.map(n => n.label).join(', ')}
            </div>
          </div>
        )}
      </div>

      {metrics && (
        <div className="stats-grid">
          <div className="stat-card"><div className="stat-label">Nodes</div><div className="stat-value">{metrics.node_count}</div></div>
          <div className="stat-card"><div className="stat-label">Edges</div><div className="stat-value">{metrics.edge_count}</div></div>
          <div className="stat-card"><div className="stat-label">Unique Users</div><div className="stat-value">{metrics.unique_users}</div></div>
          <div className="stat-card"><div className="stat-label">Unique IPs</div><div className="stat-value">{metrics.unique_ips}</div></div>
          <div className="stat-card"><div className="stat-label">Density</div><div className="stat-value">{metrics.density}</div></div>
        </div>
      )}
    </div>
  );
}
