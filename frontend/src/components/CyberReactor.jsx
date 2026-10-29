import React from 'react';

export default function CyberReactor({ size = 38, isCritical = false }) {
  const primaryColor = isCritical ? 'var(--accent-red)' : 'var(--accent-cyan)';
  const secondaryColor = isCritical ? '#ff6600' : 'var(--accent-purple)';

  return (
    <div
      style={{
        width: size,
        height: size,
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        perspective: 300,
      }}
    >
      {/* Outer Ring */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          borderRadius: '50%',
          border: `1.5px dashed ${primaryColor}`,
          boxShadow: `0 0 10px ${primaryColor}`,
          animation: 'reactorSpinCW 8s linear infinite',
        }}
      />

      {/* Middle Ring */}
      <div
        style={{
          position: 'absolute',
          inset: 4,
          borderRadius: '50%',
          border: `1.5px dotted ${secondaryColor}`,
          animation: 'reactorSpinCCW 5s linear infinite',
        }}
      />

      {/* Inner Core */}
      <div
        style={{
          width: size * 0.38,
          height: size * 0.38,
          borderRadius: '50%',
          background: `radial-gradient(circle, #fff 0%, ${primaryColor} 70%, transparent 100%)`,
          boxShadow: `0 0 12px ${primaryColor}`,
          animation: 'corePulse 1.8s ease-in-out infinite',
        }}
      />
    </div>
  );
}
