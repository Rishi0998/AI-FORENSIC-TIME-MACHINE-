import { useState, useEffect, useRef, useCallback } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { getGraph } from '../api';
import {
  playCyberClick,
  playRadarPing,
  playTargetLock,
  playThreatAlert,
  playWarpEffect,
  playGlitchSound,
} from '../cyberAudio';

try {
  if (typeof dagre === 'function') {
    cytoscape.use(dagre);
  } else if (dagre && typeof dagre.default === 'function') {
    cytoscape.use(dagre.default);
  }
} catch (e) {
  console.warn('Cytoscape dagre registration:', e);
}

// Layout definitions
const LAYOUT_CONFIGS = {
  cose: {
    name: 'cose',
    animate: true,
    animationDuration: 700,
    animationEasing: 'ease-out-cubic',
    nodeRepulsion: () => 20000,
    idealEdgeLength: () => 140,
    edgeElasticity: () => 120,
    gravity: 0.2,
    numIter: 500,
    padding: 60,
  },
  dagre: {
    name: 'dagre',
    rankDir: 'LR',
    nodeSep: 75,
    rankSep: 130,
    edgeSep: 35,
    padding: 60,
    animate: true,
    animationDuration: 600,
  },
  circle: {
    name: 'circle',
    animate: true,
    animationDuration: 600,
    padding: 60,
  },
  breadthfirst: {
    name: 'breadthfirst',
    directed: true,
    roots: 'node[type="host"], node[type="system"], node[type="ip"]',
    spacingFactor: 1.3,
    animate: true,
    animationDuration: 600,
    padding: 60,
  },
};

// Custom High-Precision 360-Degree Radial Radar Layout
function runRadarLayout(cy) {
  if (!cy || cy.nodes().length === 0) return;

  const hostNodes = cy.nodes('node[type="host"]');
  const systemNodes = cy.nodes('node[type="system"]');
  const serviceNodes = cy.nodes('node[type="service"]');
  const userNodes = cy.nodes('node[type="user"]');
  const procNodes = cy.nodes('node[type="process"], node[type="malware"]');
  const ipAdversaryNodes = cy.nodes('node[type="ip"], node[type="adversary"]');

  const positions = {};

  // Tier 0: Center (Host Core)
  hostNodes.forEach((node) => {
    positions[node.id()] = { x: 0, y: 0 };
  });

  // Tier 1: Inner Orbit (System Authorities & Core Services, R=160px)
  const tier1 = [...systemNodes, ...serviceNodes];
  const count1 = tier1.length;
  tier1.forEach((node, idx) => {
    const angle = (idx * 2 * Math.PI) / (count1 || 1) - Math.PI / 2;
    positions[node.id()] = {
      x: Math.round(Math.cos(angle) * 160),
      y: Math.round(Math.sin(angle) * 160),
    };
  });

  // Tier 2: Mid Orbit (Users & Workload Binaries, R=290px, angular offset)
  const tier2 = [...userNodes, ...procNodes];
  const count2 = tier2.length;
  tier2.forEach((node, idx) => {
    const angle = (idx * 2 * Math.PI) / (count2 || 1) - Math.PI / 2 + Math.PI / (count2 || 2);
    positions[node.id()] = {
      x: Math.round(Math.cos(angle) * 290),
      y: Math.round(Math.sin(angle) * 290),
    };
  });

  // Tier 3: Outer Perimeter (External IPs, Gateway, Adversaries, R=420px)
  const count3 = ipAdversaryNodes.length;
  ipAdversaryNodes.forEach((node, idx) => {
    const angle = (idx * 2 * Math.PI) / (count3 || 1) + Math.PI / 4;
    positions[node.id()] = {
      x: Math.round(Math.cos(angle) * 410),
      y: Math.round(Math.sin(angle) * 410),
    };
  });

  // Apply positions with smooth animation
  cy.nodes().forEach((node) => {
    const targetPos = positions[node.id()] || { x: 0, y: 0 };
    node.animate(
      { position: targetPos },
      { duration: 750, easing: 'ease-out-cubic' }
    );
  });

  setTimeout(() => {
    cy.fit(undefined, 50);
  }, 780);
}

export default function Graph({ sessionId }) {
  const [graphData, setGraphData] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [layoutMode, setLayoutMode] = useState('radar'); // Default to our radar!
  const [filterMode, setFilterMode] = useState('all');
  const [particlesEnabled, setParticlesEnabled] = useState(true);
  const [particleSpeedMultiplier, setParticleSpeedMultiplier] = useState(1.5);
  const [radarEnabled, setRadarEnabled] = useState(true);
  const [blastActive, setBlastActive] = useState(false);
  const [quarantinedNodes, setQuarantinedNodes] = useState(new Set());
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const cyRef = useRef(null);
  const animFrameRef = useRef(null);

  const particlesRef = useRef([]);
  const shockwavesRef = useRef([]);
  const radarAngleRef = useRef(0);

  const fetchGraphData = useCallback((recalc = false, sample = false) => {
    if (!sessionId && !sample) {
      setLoading(false);
      return;
    }
    setLoading(true);
    getGraph(sample ? 'demo' : sessionId, recalc, sample)
      .then((data) => {
        setGraphData(data.graph?.elements);
        setMetrics(data.graph?.metrics);
        setLoading(false);
        if (sample) setIsDemoMode(true);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [sessionId]);

  useEffect(() => {
    fetchGraphData(false, false);
  }, [fetchGraphData]);

  const initCytoscape = useCallback(() => {
    if (!containerRef.current || !graphData) return;
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const elements = [...(graphData.nodes || []), ...(graphData.edges || [])];

    const cy = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        // ── Base Node Style ───────────────────────────────────────────
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#ffffff',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '11px',
            'font-family': 'JetBrains Mono, Rajdhani, monospace',
            'font-weight': '700',
            'text-margin-y': 10,
            'text-outline-color': '#040711',
            'text-outline-width': 3.5,
            'text-outline-opacity': 0.95,
            'text-background-color': 'rgba(6, 11, 25, 0.92)',
            'text-background-padding': '3px 6px',
            'text-background-shape': 'round-rectangle',
            'text-background-opacity': 0.92,
            'text-border-color': 'data(color)',
            'text-border-width': 1,
            'text-border-opacity': 0.75,
            'background-color': 'data(color)',
            'background-opacity': 0.28,
            'border-width': 3,
            'border-color': 'data(color)',
            'border-opacity': 0.9,
            'width': 54,
            'height': 54,
            'transition-property': 'width, height, border-width, border-color, shadow-blur, opacity',
            'transition-duration': '0.3s',
            'shadow-blur': 22,
            'shadow-color': 'data(color)',
            'shadow-opacity': 0.65,
          },
        },
        // ── Node Types ────────────────────────────────────────────────
        {
          selector: 'node[type="host"]',
          style: {
            'shape': 'hexagon',
            'width': 70,
            'height': 70,
            'border-width': 4,
            'background-opacity': 0.35,
            'shadow-blur': 32,
            'shadow-color': '#a855f7',
            'shadow-opacity': 0.85,
          },
        },
        {
          selector: 'node[type="system"]',
          style: {
            'shape': 'barrel',
            'width': 58,
            'height': 54,
            'border-width': 3.5,
            'background-opacity': 0.3,
          },
        },
        {
          selector: 'node[type="adversary"]',
          style: {
            'shape': 'diamond',
            'width': 64,
            'height': 64,
            'border-width': 4,
            'background-opacity': 0.35,
            'shadow-blur': 35,
            'shadow-color': '#ff0055',
            'shadow-opacity': 0.9,
          },
        },
        {
          selector: 'node[type="user"]',
          style: {
            'shape': 'round-diamond',
            'width': 56,
            'height': 56,
            'border-width': 3,
            'background-opacity': 0.3,
          },
        },
        {
          selector: 'node[type="ip"]',
          style: {
            'shape': 'ellipse',
            'width': 58,
            'height': 58,
            'border-width': 3.5,
            'background-opacity': 0.3,
          },
        },
        {
          selector: 'node[type="process"]',
          style: {
            'shape': 'round-rectangle',
            'width': 62,
            'height': 44,
            'border-width': 3,
            'background-opacity': 0.28,
          },
        },
        {
          selector: 'node[type="malware"]',
          style: {
            'shape': 'round-rectangle',
            'width': 68,
            'height': 46,
            'border-width': 4,
            'background-opacity': 0.38,
            'shadow-blur': 35,
            'shadow-color': '#ff0055',
          },
        },
        {
          selector: 'node[type="service"]',
          style: {
            'shape': 'round-octagon',
            'width': 62,
            'height': 46,
            'border-width': 3,
            'background-opacity': 0.28,
          },
        },
        // ── Base Edge Style (Laser Beams with Badge Labels) ────────────
        {
          selector: 'edge',
          style: {
            'width': 'data(width)',
            'line-color': 'data(color)',
            'target-arrow-color': 'data(color)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '9.5px',
            'font-family': 'JetBrains Mono, monospace',
            'font-weight': '600',
            'color': '#f8fafc',
            'text-rotation': 'autorotate',
            'text-margin-y': -10,
            'text-background-color': '#060b19',
            'text-background-opacity': 0.92,
            'text-background-padding': '3px 5px',
            'text-background-shape': 'round-rectangle',
            'text-border-color': 'data(color)',
            'text-border-width': 1,
            'text-border-opacity': 0.7,
            'opacity': 0.9,
            'arrow-scale': 1.4,
          },
        },
        {
          selector: 'edge[?suspicious]',
          style: {
            'width': 4.2,
            'line-color': '#ff0055',
            'target-arrow-color': '#ff0055',
            'opacity': 1.0,
            'arrow-scale': 1.55,
          },
        },
        // ── Interactive Selection & Hover ──────────────────────────────
        {
          selector: 'node:selected',
          style: {
            'border-width': 5,
            'border-color': '#ffffff',
            'width': 74,
            'height': 74,
            'shadow-blur': 45,
            'shadow-color': '#00f2fe',
            'shadow-opacity': 1.0,
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'width': 6,
            'line-color': '#00f2fe',
            'target-arrow-color': '#00f2fe',
            'opacity': 1.0,
          },
        },
        {
          selector: '.hovered-highlight',
          style: {
            'border-width': 4.5,
            'border-color': '#ffffff',
            'shadow-blur': 35,
            'shadow-color': '#00f2fe',
            'opacity': 1,
          },
        },
        {
          selector: '.connected-edge',
          style: {
            'width': 5.5,
            'line-color': '#00f2fe',
            'target-arrow-color': '#00f2fe',
            'opacity': 1,
          },
        },
        {
          selector: '.dimmed',
          style: {
            'opacity': 0.15,
            'shadow-opacity': 0,
          },
        },
        {
          selector: '.highlighted-chain',
          style: {
            'border-width': 5,
            'border-color': '#ff0055',
            'shadow-blur': 40,
            'shadow-color': '#ff0055',
            'shadow-opacity': 1,
            'opacity': 1,
          },
        },
        {
          selector: '.quarantined-node',
          style: {
            'border-color': '#ff0000',
            'border-style': 'dashed',
            'background-color': '#330000',
            'color': '#ff3333',
            'shadow-color': '#ff0000',
            'shadow-blur': 25,
          },
        },
      ],
      layout: layoutMode === 'radar' ? { name: 'preset' } : (LAYOUT_CONFIGS[layoutMode] || LAYOUT_CONFIGS.cose),
      minZoom: 0.2,
      maxZoom: 4.0,
      wheelSensitivity: 0.25,
    });

    // Run our custom 360-degree radar if selected
    if (layoutMode === 'radar') {
      runRadarLayout(cy);
    }

    // Tap Events
    cy.on('tap', 'node', (e) => {
      playTargetLock();
      const node = e.target;
      setSelectedNode({
        id: node.id(),
        label: node.data('label'),
        type: node.data('type'),
        icon: node.data('icon') || '⚡',
        role: node.data('role') || 'Active Topological Entity',
        threatLevel: node.data('threat_level') || 'benign',
        threatScore: node.data('threat_score') || 0,
        blastRadius: node.data('blast_radius') || 0,
        eventCount: node.data('event_count') || 1,
        mitre: node.data('mitre_techniques') || [],
        connections: node.connectedEdges().length,
        inDegree: node.incomers('edge').length,
        outDegree: node.outgoers('edge').length,
        neighbors: node.neighborhood('node').map((n) => ({
          id: n.id(),
          label: n.data('label'),
          type: n.data('type'),
          color: n.data('color'),
          icon: n.data('icon') || '⚡',
        })),
      });
    });

    // Hover Tooltip Events
    cy.on('mouseover', 'node', (e) => {
      const node = e.target;
      const pos = e.renderedPosition;
      setTooltipPos({ x: pos.x, y: pos.y });
      setHoveredNode({
        id: node.id(),
        label: node.data('label'),
        type: node.data('type'),
        icon: node.data('icon') || '⚡',
        role: node.data('role') || 'Entity',
        threatScore: node.data('threat_score') || 0,
        threatLevel: node.data('threat_level') || 'benign',
        blastRadius: node.data('blast_radius') || 0,
        events: node.data('event_count') || 1,
      });

      // Highlight connections
      cy.elements().addClass('dimmed');
      node.removeClass('dimmed').addClass('hovered-highlight');
      node.connectedEdges().removeClass('dimmed').addClass('connected-edge');
      node.neighborhood('node').removeClass('dimmed');
    });

    cy.on('mouseout', 'node', () => {
      setHoveredNode(null);
      cy.elements().removeClass('dimmed hovered-highlight connected-edge');
    });

    cy.on('tap', (e) => {
      if (e.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;
  }, [graphData, layoutMode]);

  useEffect(() => {
    initCytoscape();
  }, [initCytoscape]);

  const applyLayout = (name) => {
    playWarpEffect();
    playCyberClick();
    setLayoutMode(name);
    if (!cyRef.current) return;

    if (name === 'radar') {
      runRadarLayout(cyRef.current);
    } else {
      const config = LAYOUT_CONFIGS[name] || LAYOUT_CONFIGS.cose;
      const layout = cyRef.current.layout(config);
      layout.run();
    }
  };

  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.elements().removeClass('dimmed highlighted-chain');

    if (filterMode === 'threats') {
      const benign = cy.elements('node[threat_level="benign"], node[threat_level="info"], edge[!suspicious]');
      benign.addClass('dimmed');
    } else if (filterMode === 'critical') {
      const criticalNodes = cy.nodes('node[threat_level="critical"], node[type="adversary"], node[type="malware"]');
      const criticalEdges = cy.edges('edge[?suspicious]');
      cy.elements().addClass('dimmed');
      criticalNodes.removeClass('dimmed').addClass('highlighted-chain');
      criticalEdges.removeClass('dimmed');
    }
  }, [filterMode]);

  const triggerBlastRadius = () => {
    if (!cyRef.current) return;
    playThreatAlert();
    playWarpEffect();
    setBlastActive(true);

    const cy = cyRef.current;
    const startNode = selectedNode
      ? cy.$id(selectedNode.id)
      : cy.nodes('node[threat_level="critical"], node[type="adversary"]').first();

    if (startNode.length === 0) {
      const centerNode = cy.nodes().first();
      createShockwave(centerNode);
    } else {
      createShockwave(startNode);
    }

    setTimeout(() => {
      setBlastActive(false);
    }, 2800);
  };

  const createShockwave = (node) => {
    if (!node || node.length === 0) return;
    const pos = node.renderedPosition();
    shockwavesRef.current.push({
      x: pos.x,
      y: pos.y,
      radius: 10,
      maxRadius: 400,
      alpha: 1.0,
      color: '#ff0055',
    });

    const downstream = node.successors();
    downstream.flashClass('highlighted-chain', 2200);
  };

  const toggleQuarantine = (nodeId) => {
    playGlitchSound();
    playThreatAlert();
    setQuarantinedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });

    if (cyRef.current) {
      const node = cyRef.current.$id(nodeId);
      node.toggleClass('quarantined-node');
    }
  };

  const focusNode = (nodeId) => {
    playRadarPing();
    if (!cyRef.current) return;
    const node = cyRef.current.$id(nodeId);
    if (node.length > 0) {
      cyRef.current.animate(
        {
          center: { eles: node },
          zoom: 1.6,
        },
        { duration: 500, easing: 'ease-out-cubic' }
      );
      node.select();
    }
  };

  const handleExportPNG = () => {
    playCyberClick();
    if (!cyRef.current) return;
    const png64 = cyRef.current.png({
      output: 'blob',
      bg: '#040711',
      full: true,
      scale: 2.5,
    });
    const url = URL.createObjectURL(png64);
    const a = document.createElement('a');
    a.href = url;
    a.download = `chrono-attack-graph-${Date.now()}.png`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── High-Tech Canvas Overlay Render Loop ──────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let isRunning = true;

    const initParticles = () => {
      if (!cyRef.current) return;
      const edges = cyRef.current.edges();
      if (edges.length === 0) return;

      if (particlesRef.current.length < edges.length * 2) {
        const newParticles = [];
        edges.forEach((edge) => {
          const isSusp = edge.data('suspicious');
          const color = isSusp ? '#ff0055' : edge.data('color') || '#00f2fe';
          const baseSpeed = isSusp ? 0.018 : 0.011 + Math.random() * 0.006;
          newParticles.push({
            edgeId: edge.id(),
            t: Math.random(),
            speed: baseSpeed * particleSpeedMultiplier,
            color,
            size: isSusp ? 5.0 : 3.5,
          });
          newParticles.push({
            edgeId: edge.id(),
            t: (Math.random() + 0.5) % 1,
            speed: baseSpeed * particleSpeedMultiplier,
            color,
            size: isSusp ? 4.0 : 2.8,
          });
        });
        particlesRef.current = newParticles;
      }
    };

    const renderOverlay = () => {
      if (!isRunning) return;

      const rect = canvas.getBoundingClientRect();
      if (canvas.width !== rect.width || canvas.height !== rect.height) {
        canvas.width = rect.width;
        canvas.height = rect.height;
      }

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const cy = cyRef.current;
      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      const centerY = height / 2;

      // ── 1. Animated Radar Sweep & Tactical Compass ──
      if (radarEnabled) {
        radarAngleRef.current += 0.016;
        const currentAngle = radarAngleRef.current;
        const radarRadius = Math.max(width, height) * 0.65;

        // Compass degree ticks on outer perimeter
        const compassPoints = [
          { label: '0° N', angle: -Math.PI / 2 },
          { label: '45° NE', angle: -Math.PI / 4 },
          { label: '90° E', angle: 0 },
          { label: '135° SE', angle: Math.PI / 4 },
          { label: '180° S', angle: Math.PI / 2 },
          { label: '225° SW', angle: (3 * Math.PI) / 4 },
          { label: '270° W', angle: Math.PI },
          { label: '315° NW', angle: (-3 * Math.PI) / 4 },
        ];

        ctx.font = '600 8.5px "JetBrains Mono", monospace';
        ctx.fillStyle = 'rgba(0, 242, 255, 0.35)';
        ctx.textAlign = 'center';

        const outerR = 390;
        compassPoints.forEach((cp) => {
          const cx = centerX + Math.cos(cp.angle) * outerR;
          const cyPos = centerY + Math.sin(cp.angle) * outerR;
          ctx.fillText(cp.label, cx, cyPos);
        });

        // Concentric range rings with distance tags
        [150, 270, 390].forEach((r, idx) => {
          ctx.strokeStyle = idx === 1 ? 'rgba(0, 242, 255, 0.12)' : 'rgba(0, 242, 255, 0.06)';
          ctx.lineWidth = idx === 1 ? 1.5 : 1;
          ctx.beginPath();
          ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
          ctx.stroke();

          // Distance tag
          ctx.fillStyle = 'rgba(0, 242, 255, 0.25)';
          ctx.fillText(`${(idx + 1) * 150}M REACH`, centerX + r + 6, centerY + 3);
        });

        // Radar beam sweep arc with gradient
        ctx.save();
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radarRadius, currentAngle - 0.38, currentAngle);
        ctx.closePath();
        const gradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, radarRadius);
        gradient.addColorStop(0, 'rgba(0, 242, 255, 0.16)');
        gradient.addColorStop(1, 'rgba(0, 242, 255, 0.0)');
        ctx.fillStyle = gradient;
        ctx.fill();

        // Leading edge laser line
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(
          centerX + Math.cos(currentAngle) * radarRadius,
          centerY + Math.sin(currentAngle) * radarRadius
        );
        ctx.strokeStyle = 'rgba(0, 242, 255, 0.45)';
        ctx.lineWidth = 1.8;
        ctx.stroke();
        ctx.restore();
      }

      // ── 2. Render Node Icons Centered Inside Shapes ──
      if (cy) {
        ctx.save();
        ctx.font = '16px "Segoe UI Emoji", "Apple Color Emoji", sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        cy.nodes().forEach((node) => {
          const pos = node.renderedPosition();
          if (pos && pos.x >= 0 && pos.x <= width && pos.y >= 0 && pos.y <= height) {
            const icon = node.data('icon') || '⚡';
            ctx.shadowColor = node.data('color') || '#00f2fe';
            ctx.shadowBlur = 8;
            ctx.fillText(icon, pos.x, pos.y);
          }
        });
        ctx.restore();
      }

      // ── 3. Traveling Photon Energy Particles on Edges ──
      if (particlesEnabled && cy) {
        initParticles();

        particlesRef.current.forEach((p) => {
          p.t += p.speed;
          if (p.t > 1) p.t = 0;

          const edge = cy.$id(p.edgeId);
          if (edge && edge.length > 0) {
            const srcPos = edge.source().renderedPosition();
            const tgtPos = edge.target().renderedPosition();

            if (srcPos && tgtPos) {
              const px = srcPos.x + (tgtPos.x - srcPos.x) * p.t;
              const py = srcPos.y + (tgtPos.y - srcPos.y) * p.t;

              ctx.save();
              ctx.shadowColor = p.color;
              ctx.shadowBlur = 12;
              ctx.fillStyle = p.color;
              ctx.beginPath();
              ctx.arc(px, py, p.size, 0, Math.PI * 2);
              ctx.fill();

              // Trailing photon spark
              const prevT = Math.max(0, p.t - 0.06);
              const trailX = srcPos.x + (tgtPos.x - srcPos.x) * prevT;
              const trailY = srcPos.y + (tgtPos.y - srcPos.y) * prevT;
              ctx.strokeStyle = p.color;
              ctx.globalAlpha = 0.45;
              ctx.lineWidth = p.size * 0.75;
              ctx.beginPath();
              ctx.moveTo(trailX, trailY);
              ctx.lineTo(px, py);
              ctx.stroke();
              ctx.restore();
            }
          }
        });
      }

      // ── 4. Expanding Blast Shockwaves ──
      for (let i = shockwavesRef.current.length - 1; i >= 0; i--) {
        const wave = shockwavesRef.current[i];
        wave.radius += 6.0;
        wave.alpha -= 0.015;

        if (wave.alpha <= 0 || wave.radius >= wave.maxRadius) {
          shockwavesRef.current.splice(i, 1);
          continue;
        }

        ctx.save();
        ctx.shadowColor = wave.color;
        ctx.shadowBlur = 24;
        ctx.strokeStyle = wave.color;
        ctx.globalAlpha = wave.alpha;
        ctx.lineWidth = 3.5;
        ctx.beginPath();
        ctx.arc(wave.x, wave.y, wave.radius, 0, Math.PI * 2);
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(wave.x, wave.y, Math.max(0, wave.radius - 28), 0, Math.PI * 2);
        ctx.lineWidth = 1.5;
        ctx.globalAlpha = wave.alpha * 0.55;
        ctx.stroke();
        ctx.restore();
      }

      // ── 5. Holographic Target Lock-On Reticle ──
      if (selectedNode && cy) {
        const node = cy.$id(selectedNode.id);
        if (node && node.length > 0) {
          const pos = node.renderedPosition();
          const r = 40;
          const time = Date.now() * 0.003;

          ctx.save();
          ctx.translate(pos.x, pos.y);

          ctx.strokeStyle = selectedNode.threatLevel === 'critical' ? '#ff0055' : '#00f2fe';
          ctx.lineWidth = 2.2;
          ctx.shadowColor = ctx.strokeStyle;
          ctx.shadowBlur = 14;

          const bracketLen = 14;
          const dist = r + 8;

          // 4 Corner brackets
          ctx.beginPath();
          ctx.moveTo(-dist, -dist + bracketLen);
          ctx.lineTo(-dist, -dist);
          ctx.lineTo(-dist + bracketLen, -dist);
          ctx.stroke();

          ctx.beginPath();
          ctx.moveTo(dist - bracketLen, -dist);
          ctx.lineTo(dist, -dist);
          ctx.lineTo(dist, -dist + bracketLen);
          ctx.stroke();

          ctx.beginPath();
          ctx.moveTo(-dist, dist - bracketLen);
          ctx.lineTo(-dist, dist);
          ctx.lineTo(-dist + bracketLen, dist);
          ctx.stroke();

          ctx.beginPath();
          ctx.moveTo(dist - bracketLen, dist);
          ctx.lineTo(dist, dist);
          ctx.lineTo(dist, dist - bracketLen);
          ctx.stroke();

          // Outer dashed spinning ring
          ctx.save();
          ctx.rotate(time);
          ctx.setLineDash([8, 8]);
          ctx.beginPath();
          ctx.arc(0, 0, r + 16, 0, Math.PI * 2);
          ctx.stroke();
          ctx.restore();

          ctx.font = '700 9.5px "JetBrains Mono", monospace';
          ctx.fillStyle = ctx.strokeStyle;
          ctx.textAlign = 'center';
          ctx.fillText(`TARGET LOCKED // ${selectedNode.type.toUpperCase()}`, 0, -dist - 12);

          ctx.restore();
        }
      }

      animFrameRef.current = requestAnimationFrame(renderOverlay);
    };

    renderOverlay();

    return () => {
      isRunning = false;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [particlesEnabled, particleSpeedMultiplier, radarEnabled, selectedNode]);

  if (loading) {
    return (
      <div className="card fade-in" style={{ padding: '70px 24px', textAlign: 'center' }}>
        <div className="loading-state">
          <div
            className="spinner"
            style={{
              width: 50,
              height: 50,
              borderColor: 'rgba(0,242,255,0.2)',
              borderTopColor: 'var(--accent-cyan)',
              margin: '0 auto 16px',
            }}
          ></div>
          <div
            className="loading-text"
            style={{
              fontFamily: 'var(--font-heading)',
              color: 'var(--accent-cyan)',
              letterSpacing: '0.12em',
              fontSize: '1.1rem',
            }}
          >
            SYNTHESIZING MULTI-LAYERED CYBER ATTACK TOPOLOGY...
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 6, fontFamily: 'var(--font-mono)' }}>
            ANALYZING CORRELATION MATRICES &bull; ELIMINATING ISOLATED CHANNELS &bull; COMPUTING BLAST RADII
          </p>
        </div>
      </div>
    );
  }

  if (!graphData || (!graphData.nodes?.length && !isDemoMode)) {
    return (
      <div className="card fade-in" style={{ padding: '60px 24px', textAlign: 'center' }}>
        <div className="empty-state">
          <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>🕸️</div>
          <h3 style={{ fontFamily: 'var(--font-heading)', letterSpacing: '0.08em', color: 'var(--text-primary)', marginBottom: 8 }}>
            NO TOPOLOGICAL GRAPH LOADED
          </h3>
          <p style={{ color: 'var(--text-muted)', maxWidth: 520, margin: '0 auto 24px' }}>
            Upload forensic logs, extract local Windows/Linux channels, or immediately launch the full weaponized APT attack graph simulation.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
            <button
              className="btn btn-primary"
              onClick={() => {
                playWarpEffect();
                fetchGraphData(false, true);
              }}
              style={{ padding: '10px 24px', fontSize: '0.9rem' }}
            >
              🧬 LOAD WEAPONIZED APT ATTACK DEMO
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in cyber-attack-graph-wrapper">
      <div className="card" style={{ position: 'relative', overflow: 'hidden', padding: '18px 20px' }}>
        {/* Top Header HUD Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 16,
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div
                style={{
                  width: 12,
                  height: 12,
                  borderRadius: '50%',
                  background: isDemoMode ? '#ff0055' : 'var(--accent-cyan)',
                  boxShadow: `0 0 14px ${isDemoMode ? '#ff0055' : 'var(--accent-cyan)'}`,
                }}
              ></div>
              <div
                className="card-title"
                style={{
                  fontFamily: 'var(--font-heading)',
                  letterSpacing: '0.1em',
                  fontSize: '1.15rem',
                  color: '#fff',
                }}
              >
                {isDemoMode ? '⚔️ WEAPONIZED APT KILL CHAIN SIMULATION' : 'TOPOLOGICAL CYBER THREAT ATTACK GRAPH'}
              </div>
            </div>
            <p
              style={{
                margin: '4px 0 0 22px',
                fontSize: '0.75rem',
                color: 'var(--text-muted)',
                fontFamily: 'var(--font-mono)',
              }}
            >
              ZERO-ORPHAN DIRECTED GRAPH // CORRELATED KERNEL SUBSYSTEMS, IDENTITIES &amp; NETWORK VECTORS
            </p>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              className="btn btn-sm btn-outline"
              onClick={() => {
                playCyberClick();
                fetchGraphData(true, false);
              }}
              title="Re-run heuristic graph generator with latest topology logic"
              style={{ fontSize: '0.72rem', borderColor: 'rgba(0,242,255,0.4)' }}
            >
              🔄 RE-SYNTHESIZE MATRIX
            </button>

            <button
              className={`btn btn-sm ${isDemoMode ? 'btn-danger' : 'btn-outline'}`}
              onClick={() => {
                playWarpEffect();
                fetchGraphData(false, true);
              }}
              title="Load full 16-node APT Ransomware lateral movement attack graph"
              style={{ fontSize: '0.72rem', borderColor: '#ff0055', color: '#ff7799' }}
            >
              🧬 LOAD APT ATTACK DEMO
            </button>

            <button
              className="btn btn-sm btn-outline"
              onClick={() => {
                playCyberClick();
                setIsExpanded(!isExpanded);
              }}
              title="Toggle expanded command center height"
              style={{ fontSize: '0.72rem' }}
            >
              {isExpanded ? '⛶ STANDARD VIEW' : '⛶ EXPAND CANVAS'}
            </button>

            <button
              className="btn btn-sm btn-outline"
              onClick={handleExportPNG}
              title="Export high-res PNG tactical blueprint"
              style={{ fontSize: '0.72rem' }}
            >
              📷 EXPORT BLUEPRINT
            </button>
          </div>
        </div>

        {/* ── High-Tech Cyber Toolbar ──────────────────────────────── */}
        <div
          style={{
            background: 'rgba(6,11,25,0.85)',
            border: '1px solid rgba(0,242,255,0.2)',
            padding: '10px 14px',
            borderRadius: '8px',
            marginBottom: 14,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          {/* Layout Mode Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginRight: 4 }}>
              TOPOLOGY LAYOUT:
            </span>
            {[
              { id: 'radar', label: '🎯 RADAR 360°' },
              { id: 'cose', label: '⚡ NEURAL FORCE' },
              { id: 'dagre', label: '🧬 LATERAL KILL CHAIN' },
              { id: 'circle', label: '🪐 ORBITAL RING' },
              { id: 'breadthfirst', label: '🌳 PROCESS TREE' },
            ].map((m) => (
              <button
                key={m.id}
                onClick={() => applyLayout(m.id)}
                className={`btn btn-sm ${layoutMode === m.id ? 'btn-primary' : 'btn-outline'}`}
                style={{
                  fontSize: '0.7rem',
                  padding: '3px 9px',
                  background: layoutMode === m.id ? 'rgba(0,242,255,0.22)' : 'transparent',
                  borderColor: layoutMode === m.id ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.12)',
                  fontWeight: layoutMode === m.id ? '700' : '500',
                }}
              >
                {m.label}
              </button>
            ))}
          </div>

          {/* Blast Radius & Particle Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button
              onClick={triggerBlastRadius}
              className={`btn btn-sm ${blastActive ? 'btn-danger' : 'btn-outline'}`}
              style={{
                fontSize: '0.72rem',
                borderColor: '#ff0055',
                color: '#fff',
                background: blastActive ? '#ff0055' : 'rgba(255,0,85,0.15)',
                boxShadow: blastActive ? '0 0 16px #ff0055' : 'none',
              }}
              title="Simulate malware infection detonation shockwave"
            >
              💥 DETONATE BLAST RADIUS
            </button>

            <button
              onClick={() => {
                playCyberClick();
                setParticlesEnabled(!particlesEnabled);
              }}
              className="btn btn-sm btn-outline"
              style={{
                fontSize: '0.7rem',
                padding: '3px 8px',
                borderColor: particlesEnabled ? 'var(--accent-green)' : 'rgba(255,255,255,0.12)',
                color: particlesEnabled ? 'var(--accent-green)' : 'var(--text-muted)',
              }}
              title="Toggle photon particle beams flowing along edges"
            >
              ✨ PARTICLES: {particlesEnabled ? 'ON' : 'OFF'}
            </button>

            <button
              onClick={() => {
                playCyberClick();
                setRadarEnabled(!radarEnabled);
              }}
              className="btn btn-sm btn-outline"
              style={{
                fontSize: '0.7rem',
                padding: '3px 8px',
                borderColor: radarEnabled ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.12)',
                color: radarEnabled ? 'var(--accent-cyan)' : 'var(--text-muted)',
              }}
              title="Toggle 360-degree radar scanner sweep"
            >
              📡 RADAR: {radarEnabled ? 'ON' : 'OFF'}
            </button>

            <button
              className="btn btn-sm btn-outline"
              onClick={() => {
                playCyberClick();
                cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
              }}
              title="Zoom In"
              style={{ minWidth: 28, padding: '3px 7px' }}
            >
              +
            </button>
            <button
              className="btn btn-sm btn-outline"
              onClick={() => {
                playCyberClick();
                cyRef.current?.zoom(cyRef.current.zoom() * 0.7);
              }}
              title="Zoom Out"
              style={{ minWidth: 28, padding: '3px 7px' }}
            >
              -
            </button>
            <button
              className="btn btn-sm btn-outline"
              onClick={() => {
                playCyberClick();
                cyRef.current?.fit(undefined, 50);
              }}
              title="Fit to screen"
              style={{ fontSize: '0.7rem', padding: '3px 9px' }}
            >
              FIT MATRIX
            </button>
          </div>
        </div>

        {/* ── Filter & Tactical Legend Bar ─────────────────────────── */}
        <div
          className="graph-legend"
          style={{
            background: 'rgba(4,7,17,0.7)',
            border: '1px solid rgba(0,242,255,0.12)',
            padding: '8px 14px',
            borderRadius: '6px',
            marginBottom: 14,
            display: 'flex',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 14,
            fontSize: '0.75rem',
          }}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>🖥️</span>
            <div style={{ width: 11, height: 11, background: '#a855f7', clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)', boxShadow: '0 0 8px #a855f7' }}></div>
            <strong style={{ color: '#c084fc' }}>HOST CORE</strong>
          </span>

          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>🛡️</span>
            <div style={{ width: 10, height: 10, background: '#6366f1', borderRadius: '3px', boxShadow: '0 0 8px #6366f1' }}></div>
            <strong style={{ color: '#818cf8' }}>SYSTEM AUTHORITY</strong>
          </span>

          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>👤</span>
            <div style={{ width: 10, height: 10, background: '#0284c7', transform: 'rotate(45deg)', boxShadow: '0 0 8px #0284c7' }}></div>
            <strong style={{ color: '#38bdf8' }}>USER ACCOUNT</strong>
          </span>

          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>💀</span>
            <div style={{ width: 11, height: 11, background: '#ff0055', transform: 'rotate(45deg)', boxShadow: '0 0 10px #ff0055' }}></div>
            <strong style={{ color: '#ff7799' }}>ADVERSARY / MALWARE</strong>
          </span>

          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>🌐</span>
            <div style={{ width: 10, height: 10, background: '#00f2fe', borderRadius: '50%', boxShadow: '0 0 8px #00f2fe' }}></div>
            <strong style={{ color: '#00f2fe' }}>NETWORK IP</strong>
          </span>

          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>⚡</span>
            <div style={{ width: 12, height: 8, background: '#05ffa1', borderRadius: '2px', boxShadow: '0 0 8px #05ffa1' }}></div>
            <strong style={{ color: '#05ffa1' }}>BINARY / SERVICE</strong>
          </span>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>FILTER:</span>
            {['all', 'threats', 'critical'].map((f) => (
              <button
                key={f}
                onClick={() => {
                  playCyberClick();
                  setFilterMode(f);
                }}
                className={`badge ${filterMode === f ? (f === 'all' ? 'badge-info' : 'badge-critical') : ''}`}
                style={{
                  cursor: 'pointer',
                  border: filterMode === f ? '1px solid currentColor' : '1px solid rgba(255,255,255,0.15)',
                  background: filterMode === f ? undefined : 'transparent',
                  color: filterMode === f ? undefined : 'var(--text-muted)',
                  fontSize: '0.68rem',
                  padding: '2px 7px',
                }}
              >
                {f.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* ── Interactive Dual-Layer Canvas ───────────────────────── */}
        <div
          style={{
            position: 'relative',
            height: isExpanded ? 760 : 560,
            width: '100%',
            background: 'radial-gradient(circle at center, rgba(0,242,255,0.05) 0%, rgba(4,7,17,0.98) 100%)',
            border: '1px solid rgba(0,242,255,0.3)',
            borderRadius: '10px',
            overflow: 'hidden',
            boxShadow: 'inset 0 0 50px rgba(0,0,0,0.85), 0 0 25px rgba(0,242,255,0.1)',
            transition: 'height 0.3s ease',
          }}
        >
          <div
            ref={containerRef}
            style={{
              position: 'absolute',
              inset: 0,
              width: '100%',
              height: '100%',
              zIndex: 1,
            }}
          />

          <canvas
            ref={canvasRef}
            style={{
              position: 'absolute',
              inset: 0,
              width: '100%',
              height: '100%',
              pointerEvents: 'none',
              zIndex: 2,
            }}
          />

          <div
            style={{
              position: 'absolute',
              top: 10,
              left: 12,
              fontFamily: 'var(--font-mono)',
              fontSize: '0.66rem',
              color: 'rgba(0,242,255,0.6)',
              zIndex: 3,
              pointerEvents: 'none',
              letterSpacing: '0.08em',
            }}
          >
            [ TOPOLOGICAL SENSOR: ONLINE // RADAR: 360° // SCANNER: ACTIVE ]
          </div>

          <div
            style={{
              position: 'absolute',
              bottom: 10,
              right: 14,
              fontFamily: 'var(--font-mono)',
              fontSize: '0.68rem',
              color: 'var(--accent-cyan)',
              zIndex: 3,
              pointerEvents: 'none',
              letterSpacing: '0.05em',
            }}
          >
            {metrics?.node_count || 0} NODES &bull; {metrics?.edge_count || 0} EDGES &bull; DENSITY {metrics?.density || 0}
          </div>

          {blastActive && (
            <div
              style={{
                position: 'absolute',
                top: 20,
                left: '50%',
                transform: 'translateX(-50%)',
                background: 'rgba(255,0,85,0.92)',
                color: '#fff',
                padding: '6px 18px',
                borderRadius: '6px',
                fontFamily: 'var(--font-heading)',
                fontSize: '0.85rem',
                letterSpacing: '0.1em',
                boxShadow: '0 0 25px #ff0055',
                zIndex: 4,
              }}
            >
              ⚠️ MALWARE ATTACK BLAST PROPAGATING THROUGH TOPOLOGY
            </div>
          )}

          {/* Floating Live Hover Tooltip */}
          {hoveredNode && !selectedNode && (
            <div
              style={{
                position: 'absolute',
                left: Math.min(tooltipPos.x + 18, (containerRef.current?.clientWidth || 600) - 240),
                top: Math.max(tooltipPos.y - 45, 12),
                background: 'rgba(6, 11, 25, 0.94)',
                border: `1px solid ${hoveredNode.threatScore > 40 ? '#ff0055' : 'var(--accent-cyan)'}`,
                boxShadow: `0 0 16px ${hoveredNode.threatScore > 40 ? 'rgba(255,0,85,0.4)' : 'rgba(0,242,255,0.25)'}`,
                padding: '8px 12px',
                borderRadius: '6px',
                pointerEvents: 'none',
                zIndex: 10,
                minWidth: 190,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <span style={{ fontSize: '1rem' }}>{hoveredNode.icon}</span>
                <span style={{ fontFamily: 'var(--font-heading)', fontSize: '0.82rem', color: '#fff', fontWeight: 700 }}>
                  {hoveredNode.label}
                </span>
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', marginBottom: 4 }}>
                {hoveredNode.role}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                <span>THREAT: {hoveredNode.threatScore}/100</span>
                <span>BLAST: {hoveredNode.blastRadius} NODES</span>
              </div>
            </div>
          )}
        </div>

        {/* ── Selected Node Telemetry HUD ──────────────────────────── */}
        {selectedNode && (
          <div
            className="fade-in"
            style={{
              marginTop: 16,
              padding: '16px 20px',
              background: 'linear-gradient(135deg, rgba(0,242,255,0.08) 0%, rgba(168,85,247,0.08) 100%)',
              borderRadius: '8px',
              border: `1px solid ${selectedNode.threatLevel === 'critical' ? 'rgba(255,0,85,0.5)' : 'rgba(0,242,255,0.4)'}`,
              boxShadow: `0 0 25px ${selectedNode.threatLevel === 'critical' ? 'rgba(255,0,85,0.2)' : 'rgba(0,242,255,0.15)'}`,
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 10,
                flexWrap: 'wrap',
                gap: 10,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: '1.4rem' }}>{selectedNode.icon}</span>
                <span
                  style={{
                    fontFamily: 'var(--font-heading)',
                    letterSpacing: '0.08em',
                    fontSize: '1.15rem',
                    color: '#fff',
                  }}
                >
                  {selectedNode.label}
                </span>
                <span
                  className={`badge ${
                    selectedNode.threatLevel === 'critical'
                      ? 'badge-critical'
                      : selectedNode.threatLevel === 'high'
                      ? 'badge-high'
                      : 'badge-info'
                  }`}
                  style={{ fontSize: '0.72rem' }}
                >
                  {selectedNode.type.toUpperCase()}
                </span>
                {quarantinedNodes.has(selectedNode.id) && (
                  <span className="badge badge-critical" style={{ fontSize: '0.7rem' }}>
                    ⛔ ISOLATED / QUARANTINED
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn btn-sm btn-outline"
                  onClick={() => focusNode(selectedNode.id)}
                  style={{ fontSize: '0.7rem', padding: '3px 8px' }}
                >
                  🎯 LOCK ON &amp; CENTER
                </button>

                <button
                  className={`btn btn-sm ${quarantinedNodes.has(selectedNode.id) ? 'btn-success' : 'btn-danger'}`}
                  onClick={() => toggleQuarantine(selectedNode.id)}
                  style={{ fontSize: '0.7rem', padding: '3px 8px' }}
                >
                  {quarantinedNodes.has(selectedNode.id) ? 'RESTORE ACCESS' : '🛡️ ISOLATE / QUARANTINE'}
                </button>
              </div>
            </div>

            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 12, fontFamily: 'var(--font-mono)' }}>
              ROLE: <span style={{ color: 'var(--accent-cyan)' }}>{selectedNode.role}</span> &bull; TOTAL INGESTED EVENTS: {selectedNode.eventCount}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 14 }}>
              <div style={{ background: 'rgba(4,7,17,0.7)', padding: '8px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: 4 }}>
                  THREAT SCORE GAUGE ({selectedNode.threatScore}/100)
                </div>
                <div style={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.1)', borderRadius: 3, overflow: 'hidden' }}>
                  <div
                    style={{
                      height: '100%',
                      width: `${Math.max(selectedNode.threatScore, 6)}%`,
                      background: selectedNode.threatScore > 50 ? '#ff0055' : selectedNode.threatScore > 20 ? '#ff7700' : 'var(--accent-cyan)',
                      boxShadow: `0 0 8px ${selectedNode.threatScore > 50 ? '#ff0055' : 'var(--accent-cyan)'}`,
                    }}
                  />
                </div>
              </div>

              <div style={{ background: 'rgba(4,7,17,0.7)', padding: '8px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  BLAST RADIUS (IMPACT REACH)
                </div>
                <div style={{ fontSize: '1.1rem', fontFamily: 'var(--font-heading)', color: selectedNode.blastRadius > 3 ? '#ff0055' : 'var(--accent-cyan)' }}>
                  {selectedNode.blastRadius} DOWNSTREAM ENTITIES
                </div>
              </div>

              <div style={{ background: 'rgba(4,7,17,0.7)', padding: '8px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  CENTRALITY DEGREE
                </div>
                <div style={{ fontSize: '1.1rem', fontFamily: 'var(--font-heading)', color: 'var(--accent-purple)' }}>
                  {selectedNode.connections} EDGES ({selectedNode.inDegree} IN / {selectedNode.outDegree} OUT)
                </div>
              </div>
            </div>

            {selectedNode.mitre && selectedNode.mitre.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: 6 }}>
                  MAPPED MITRE ATT&amp;CK TTPs:
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {selectedNode.mitre.map((m, idx) => (
                    <span key={idx} className="badge badge-critical" style={{ fontSize: '0.7rem' }}>
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
              Directly Correlated Topo-Peers:
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {selectedNode.neighbors.map((n, idx) => (
                <button
                  key={idx}
                  onClick={() => focusNode(n.id)}
                  style={{
                    background: 'rgba(4,7,17,0.85)',
                    border: `1px solid ${n.color || 'rgba(0,242,255,0.3)'}`,
                    borderRadius: '4px',
                    padding: '4px 10px',
                    fontSize: '0.72rem',
                    fontFamily: 'var(--font-mono)',
                    color: n.color || 'var(--accent-cyan)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                  }}
                  title="Click to lock-on to connected node"
                >
                  <span>{n.icon}</span>
                  <span>{n.label}</span>
                  <span style={{ fontSize: '0.65rem', opacity: 0.65 }}>({n.type})</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {metrics && (
        <div className="stats-grid" style={{ marginTop: 16 }}>
          <div className="stat-card">
            <div className="stat-label">TOTAL TOPOLOGICAL NODES</div>
            <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>
              {metrics.node_count}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">CORRELATED EDGES</div>
            <div className="stat-value" style={{ color: 'var(--accent-purple)' }}>
              {metrics.edge_count}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">COMPROMISED VECTOR NODES</div>
            <div className="stat-value" style={{ color: metrics.compromised_count > 0 ? '#ff0055' : 'var(--accent-green)' }}>
              {metrics.compromised_count || 0}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">THREAT RATIO</div>
            <div className="stat-value" style={{ color: metrics.threat_ratio > 30 ? '#ff0055' : 'var(--accent-cyan)' }}>
              {metrics.threat_ratio || 0}%
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">GRAPH CONNECTIVITY DENSITY</div>
            <div className="stat-value" style={{ color: 'var(--accent-green)' }}>
              {metrics.density}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
