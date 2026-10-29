import React from 'react';

export default function CyberTicker({ sessionInfo, defconLevel = 'DEFCON 5' }) {
  const isCritical = defconLevel === 'DEFCON 1';
  const tagColor = isCritical ? 'var(--accent-red)' : 'var(--accent-cyan)';

  const items = [
    `CHRONO FORENSICS v4.2 // QUANTUM STREAM ACTIVE`,
    `DEFCON LEVEL: ${defconLevel}`,
    `MITRE ATT&CK KNOWLEDGE GRAPH: 184 TACTICAL VECTORS MONITORED`,
    `LOCAL HOST HARVESTER: 6 WINDOWS EVTX CHANNELS SYNCHRONIZED`,
    sessionInfo ? `ACTIVE SESSION: ${sessionInfo.session_id} // ${sessionInfo.filename}` : `REAL-TIME INCIDENT RECONSTRUCTION ENGINE STANDBY`,
    `REPLAY BUFFER: 100% TEMPORAL DETERMINISM`,
    `CYBER DEFENSE STATUS: CONTINUOUS EVENT CORRELATION ENGAGED`,
  ];

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        height: 24,
        background: 'rgba(4, 7, 17, 0.95)',
        borderTop: `1px solid ${isCritical ? 'rgba(255, 0, 85, 0.4)' : 'rgba(0, 242, 254, 0.25)'}`,
        zIndex: 999,
        display: 'flex',
        alignItems: 'center',
        overflow: 'hidden',
        backdropFilter: 'blur(8px)',
        boxShadow: isCritical ? '0 -2px 10px rgba(255,0,85,0.2)' : '0 -2px 10px rgba(0,242,254,0.1)',
      }}
    >
      {/* Fixed Telemetry Badge */}
      <div
        style={{
          background: isCritical ? 'rgba(255,0,85,0.2)' : 'rgba(0,242,254,0.15)',
          color: tagColor,
          fontFamily: 'var(--font-mono)',
          fontSize: '0.65rem',
          fontWeight: 700,
          padding: '0 10px',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          borderRight: `1px solid ${isCritical ? 'rgba(255,0,85,0.4)' : 'rgba(0,242,254,0.3)'}`,
          whiteSpace: 'nowrap',
          zIndex: 2,
        }}
      >
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: tagColor,
            boxShadow: `0 0 6px ${tagColor}`,
            animation: 'pulseSlow 1.5s infinite',
          }}
        />
        <span>TELEMETRY FEED</span>
      </div>

      {/* Marquee Track */}
      <div
        style={{
          display: 'flex',
          whiteSpace: 'nowrap',
          animation: 'tickerSlide 35s linear infinite',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.68rem',
          color: 'var(--text-secondary)',
          letterSpacing: '0.08em',
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.animationPlayState = 'paused';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.animationPlayState = 'running';
        }}
      >
        {items.concat(items).map((item, idx) => (
          <span key={idx} style={{ marginRight: 32, display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: tagColor }}>&bull;</span>
            <span>{item}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
