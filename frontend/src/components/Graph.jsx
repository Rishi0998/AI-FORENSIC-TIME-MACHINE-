import { useState, useEffect, useRef, useCallback } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { getGraph } from '../api';
import { playCyberClick, playRadarPing } from '../cyberAudio';

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
            'label': 'data(label)',
            'background-color': 'data(color)',
            'color': '#00f2fe',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '10px',
            'font-family': 'Rajdhani, Space Grotesk, sans-serif',
            'font-weight': '700',
            'text-margin-y': 8,
            'text-outline-color': '#040711',
            'text-outline-width': 3,
            'width': 44,
            'height': 44,
            'border-width': 2,
            'border-color': '#00f2fe',
            'border-opacity': 0.6,
            'transition-property': 'width, height, border-width, border-color, shadow-blur',
            'transition-duration': '0.2s',
          },
        },
        { 
          selector: 'node[type="user"]', 
          style: { 
            'shape': 'diamond', 
            'width': 50, 
            'height': 50, 
            'background-color': '#ff0055',
            'border-color': '#ff0055',
            'color': '#ff7799'
          } 
        },
        { 
          selector: 'node[type="ip"]', 
          style: { 
            'shape': 'ellipse', 
            'width': 46, 
            'height': 46, 
            'background-color': '#00f2fe',
            'border-color': '#00f2fe',
            'color': '#00f2fe'
          } 
        },
        { 
          selector: 'node[type="process"]', 
          style: { 
            'shape': 'round-rectangle', 
            'width': 56, 
            'height': 38, 
            'background-color': '#00ff88',
            'border-color': '#00ff88',
            'color': '#00ff88'
          } 
        },
        {
          selector: 'edge',
          style: {
            'width': 2.5,
            'line-color': 'rgba(138,43,226,0.6)',
            'target-arrow-color': '#8a2be2',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '8px',
            'font-family': 'JetBrains Mono, monospace',
            'color': '#94a3b8',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'text-outline-color': '#040711',
            'text-outline-width': 2,
            'opacity': 0.85,
            'arrow-scale': 1.3,
          },
        },
        { 
          selector: 'node:selected', 
          style: { 
            'border-width': 4, 
            'border-color': '#fff', 
            'width': 58, 
            'height': 58,
            'shadow-blur': 25,
            'shadow-color': '#00f2fe',
            'shadow-opacity': 0.8
          } 
        },
        {
          selector: 'edge:selected',
          style: {
            'width': 4,
            'line-color': '#00f2fe',
            'target-arrow-color': '#00f2fe',
            'opacity': 1
          }
        }
      ],
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 70, rankSep: 110, edgeSep: 25, padding: 40 },
      minZoom: 0.25, maxZoom: 3.5, wheelSensitivity: 0.3,
    });

    cy.on('tap', 'node', (e) => {
      playRadarPing();
      const node = e.target;
      setSelectedNode({
        id: node.id(),
        label: node.data('label'),
        type: node.data('type'),
        connections: node.connectedEdges().length,
        neighbors: node.neighborhood('node').map(n => ({ id: n.id(), label: n.data('label'), type: n.data('type') })),
      });
    });

    cy.on('tap', (e) => { 
      if (e.target === cy) {
        setSelectedNode(null); 
      }
    });

    cyRef.current = cy;
  }, [graphData]);

  useEffect(() => { renderGraph(); }, [renderGraph]);

  const handleFit = () => { playCyberClick(); cyRef.current?.fit(undefined, 40); };
  const handleZoomIn = () => { playCyberClick(); cyRef.current?.zoom(cyRef.current.zoom() * 1.3); };
  const handleZoomOut = () => { playCyberClick(); cyRef.current?.zoom(cyRef.current.zoom() * 0.7); };

  const focusNode = (nodeId) => {
    playCyberClick();
    if (!cyRef.current) return;
    const node = cyRef.current.$id(nodeId);
    if (node.length > 0) {
      cyRef.current.animate({
        center: { eles: node },
        zoom: 1.5,
      }, { duration: 400 });
      node.select();
    }
  };

  if (loading) return (
    <div className="card fade-in" style={{ padding: '60px 24px', textAlign: 'center' }}>
      <div className="loading-state">
        <div className="spinner" style={{ width: 44, height: 44, borderColor: 'rgba(0,242,255,0.2)', borderTopColor: 'var(--accent-cyan)' }}></div>
        <div className="loading-text" style={{ fontFamily: 'var(--font-heading)', color: 'var(--accent-cyan)', letterSpacing: '0.1em' }}>
          SYNTHESIZING TOPOLOGICAL ATTACK GRAPH...
        </div>
      </div>
    </div>
  );

  if (!graphData || graphData.nodes?.length === 0) return (
    <div className="card fade-in">
      <div className="empty-state">
        <h3 style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', color: 'var(--text-primary)' }}>NO ATTACK GRAPH TOPOLOGY FOUND</h3>
        <p>Upload forensic logs or stream live host telemetry to visualize adversarial paths.</p>
      </div>
    </div>
  );

  return (
    <div className="fade-in">
      {/* ── Attack Graph Command Center ─────────────────────────── */}
      <div className="card" style={{ position: 'relative', overflow: 'hidden' }}>
        <div className="card-header" style={{ marginBottom: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'var(--accent-cyan)', boxShadow: '0 0 10px var(--accent-cyan)' }}></div>
              <div className="card-title" style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.1em', fontSize: '1.05rem', color: '#fff' }}>
                TOPOLOGICAL ATTACK CORRELATION GRAPH
              </div>
            </div>
            <p style={{ margin: '4px 0 0 20px', fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              DIRECTED GRAPH MAPPING LATERAL MOVEMENT, ENTITY RELATIONS &amp; IMPACT RADIUS
            </p>
          </div>

          <div className="graph-controls" style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-sm btn-outline" onClick={handleZoomIn} title="Zoom In" style={{ minWidth: 32 }}>+</button>
            <button className="btn btn-sm btn-outline" onClick={handleZoomOut} title="Zoom Out" style={{ minWidth: 32 }}>-</button>
            <button className="btn btn-sm btn-outline" onClick={handleFit} title="Fit to Screen">FIT MATRIX</button>
          </div>
        </div>

        {/* Tactical Legend Bar */}
        <div className="graph-legend" style={{ background: 'rgba(6,11,25,0.7)', border: '1px solid rgba(0,242,255,0.15)', padding: '10px 16px', borderRadius: '6px', marginBottom: 14 }}>
          <span>
            <div className="legend-dot" style={{ background: '#ff0055', boxShadow: '0 0 8px #ff0055', clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)' }}></div> 
            <strong style={{ color: '#ff7799' }}>ADVERSARY / USER</strong>
          </span>
          <span>
            <div className="legend-dot" style={{ background: '#00f2fe', boxShadow: '0 0 8px #00f2fe', borderRadius: '50%' }}></div> 
            <strong style={{ color: '#00f2fe' }}>REMOTE / LOCAL IP</strong>
          </span>
          <span>
            <div className="legend-dot" style={{ background: '#00ff88', boxShadow: '0 0 8px #00ff88', borderRadius: '2px' }}></div> 
            <strong style={{ color: '#00ff88' }}>BINARY / PROCESS</strong>
          </span>
          <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--accent-cyan)' }}>
            {metrics?.node_count || 0} NODES &bull; {metrics?.edge_count || 0} EDGES
          </span>
        </div>

        {/* Interactive Canvas */}
        <div 
          ref={containerRef} 
          className="graph-container" 
          style={{ 
            height: 480, 
            background: 'radial-gradient(circle at center, rgba(0,242,255,0.03) 0%, rgba(4,7,17,0.95) 100%)',
            border: '1px solid rgba(0,242,255,0.2)',
            borderRadius: '8px',
            position: 'relative'
          }}
        ></div>

        {/* Holographic Tactical Node Telemetry HUD */}
        {selectedNode && (
          <div style={{
            marginTop: 14,
            padding: '16px 20px',
            background: 'linear-gradient(135deg, rgba(0,242,255,0.1) 0%, rgba(138,43,226,0.1) 100%)',
            borderRadius: '8px',
            border: '1px solid rgba(0,242,255,0.4)',
            boxShadow: '0 0 25px rgba(0,242,255,0.15)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8, flexWrap: 'wrap', gap: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', fontSize: '1rem', color: '#fff' }}>
                  {selectedNode.label}
                </span>
                <span className={`badge ${selectedNode.type === 'user' ? 'badge-critical' : selectedNode.type === 'ip' ? 'badge-info' : 'badge-success'}`}>
                  {selectedNode.type.toUpperCase()}
                </span>
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                DEGREE CENTRALITY: {selectedNode.connections} CONNECTIONS
              </div>
            </div>

            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 10 }}>
              Connected Sub-Graph Entities:
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {selectedNode.neighbors.map((n, idx) => (
                <button
                  key={idx}
                  onClick={() => focusNode(n.id)}
                  style={{
                    background: 'rgba(4,7,17,0.85)',
                    border: '1px solid rgba(0,242,255,0.3)',
                    borderRadius: '4px',
                    padding: '4px 10px',
                    fontSize: '0.72rem',
                    fontFamily: 'var(--font-mono)',
                    color: n.type === 'user' ? '#ff7799' : n.type === 'ip' ? 'var(--accent-cyan)' : '#00ff88',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6
                  }}
                  title="Click to focus connected node"
                >
                  <span>{n.label}</span>
                  <span style={{ fontSize: '0.65rem', opacity: 0.6 }}>({n.type})</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Topological Metrics Stats Grid ─────────────────────── */}
      {metrics && (
        <div className="stats-grid" style={{ marginTop: 16 }}>
          <div className="stat-card">
            <div className="stat-label">TOTAL NODES</div>
            <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{metrics.node_count}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">CORRELATED EDGES</div>
            <div className="stat-value" style={{ color: 'var(--accent-purple)' }}>{metrics.edge_count}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">UNIQUE IDENTITIES</div>
            <div className="stat-value" style={{ color: 'var(--accent-red)' }}>{metrics.unique_users}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">NETWORK ENDPOINTS</div>
            <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{metrics.unique_ips}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">GRAPH DENSITY</div>
            <div className="stat-value" style={{ color: 'var(--accent-green)' }}>{metrics.density}</div>
          </div>
        </div>
      )}
    </div>
  );
}
