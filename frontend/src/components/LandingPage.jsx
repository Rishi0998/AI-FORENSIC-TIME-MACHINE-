import { useNavigate } from 'react-router-dom';
import './LandingPage.css';

export default function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="landing-container">
      <div className="landing-bg">
        <div className="grid-overlay"></div>
      </div>

      <header className="landing-header">
        <div className="landing-logo">
          <div className="logo-icon">T</div>
          <div className="logo-text">
            <span>AI Forensics</span>
            <span className="small">Digital Time Machine</span>
          </div>
        </div>
        <nav className="landing-nav">
          <a href="#features">Features</a>
          <a href="#how-it-works">Process</a>
          <a href="#capabilities">System</a>
          <button className="btn-hero-primary" style={{ padding: '10px 20px', fontSize: '0.7rem' }} onClick={() => navigate('/app')}>
            Access System
          </button>
        </nav>
      </header>

      <main className="landing-hero">
        <div className="hero-badge">Military Grade Digital Forensics</div>
        <h1>
          Trace the <span className="accent">Unseen</span>.<br/>
          Rewind the <span className="accent">Attack</span>.
        </h1>
        <p>
          Reconstruct breaches with surgical precision. Our autonomous AI engine 
          correlates billions of data points to reveal the exact trajectory of 
          cyber adversaries.
        </p>
        <div className="hero-actions">
          <button className="btn-hero-primary" onClick={() => navigate('/app/monitor')}>
            ⚡ Launch Real-Time Monitor
          </button>
          <button className="btn-hero-secondary" onClick={() => navigate('/app')}>
            📁 Ingest System Logs
          </button>
        </div>
        
        <div className="hero-stats">
          <div className="stat-item">
            <span className="stat-num">99.9</span>
            <span className="stat-desc">Analysis Core</span>
          </div>
          <div className="stat-item">
            <span className="stat-num">1.2ms</span>
            <span className="stat-desc">Sync Rate</span>
          </div>
          <div className="stat-item">
            <span className="stat-num">4K+</span>
            <span className="stat-desc">Signatures</span>
          </div>
        </div>

        <div className="hero-visual">
          <div className="terminal-frame">
            <div className="terminal-header">
              <div className="terminal-dots">
                <div className="t-dot active"></div>
                <div className="t-dot"></div>
                <div className="t-dot"></div>
              </div>
              <div className="terminal-title">RECONSTRUCTION_ENGINE::STATUS_OK</div>
            </div>
            <div className="terminal-body">
              <div className="log-line"><span>[SYS]</span> INITIALIZING FORENSIC CORE...</div>
              <div className="log-line"><span>[SYS]</span> NEURAL LINK ESTABLISHED</div>
              <div className="log-line" style={{ color: '#00f2ff' }}>[!] ANOMALY DETECTED IN SECTOR 7G</div>
              <div className="log-line" style={{ color: '#ff00ff' }}>[CRIT] UNAUTHORIZED PRIVILEGE ESCALATION</div>
              <div className="log-line"><span>[TRC]</span> ORIGIN IP: 185.244.11.X</div>
              <div className="log-line" style={{ color: '#00ff00' }}>[SUC] TIMELINE CORRELATED SUCCESSFULLY</div>
              <div className="log-line cursor">_</div>
            </div>
          </div>
        </div>
      </main>

      <section id="features" className="features-section">
        <div className="section-header">
          <h2>Investigation Arsenal</h2>
          <p>State-of-the-art tools for the modern operative.</p>
        </div>
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/>
              </svg>
            </div>
            <h3>Event Timeline</h3>
            <p>Scrub through history with millisecond precision to isolate the breach.</p>
          </div>
          <div className="feature-card">
            <div className="feature-icon">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><path d="M12 2a15 15 0 0 1 4 10"/>
              </svg>
            </div>
            <h3>Graph Analysis</h3>
            <p>Trace the flow of attack vectors across your entire infrastructure.</p>
          </div>
          <div className="feature-card">
            <div className="feature-icon">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              </svg>
            </div>
            <h3>AI Reporting</h3>
            <p>Autonomous intelligence extraction for executive-ready reports.</p>
          </div>
        </div>
      </section>

      <section id="how-it-works" className="how-it-works">
        <div className="section-header">
          <h2>Operation Flow</h2>
        </div>
        <div className="process-flow">
          <div className="process-step">
            <div className="step-num">01</div>
            <h4>Ingest</h4>
            <p>Upload raw datasets from any environment.</p>
          </div>
          <div className="process-step">
            <div className="step-num">02</div>
            <h4>Correlate</h4>
            <p>Neural engine builds attack relationships.</p>
          </div>
          <div className="process-step">
            <div className="step-num">03</div>
            <h4>Resolve</h4>
            <p>Export forensic proof for legal or technical use.</p>
          </div>
        </div>
      </section>

      <section id="capabilities" className="capabilities-section">
        <div className="section-header">
          <h2>System Capabilities</h2>
        </div>
        <div className="capabilities-grid">
          <div className="cap-card"><h4>MITRE EXPLOIT MAPPING</h4></div>
          <div className="cap-card"><h4>NETWORK RECONSTRUCTION</h4></div>
          <div className="cap-card"><h4>LOG ENTROPY ANALYSIS</h4></div>
          <div className="cap-card"><h4>AUTONOMOUS TRACING</h4></div>
          <div className="cap-card"><h4>SIEM INTEGRATION</h4></div>
          <div className="cap-card"><h4>EVIDENCE RECOVERY</h4></div>
        </div>
      </section>

      <section className="cta-banner">
        <h2>Initiate Protocol</h2>
        <p>Access the world's most advanced forensic suite now.</p>
        <button className="btn-hero-secondary" style={{ marginTop: '32px', borderColor: '#000', color: '#000' }} onClick={() => navigate('/app')}>
          Launch Interface
        </button>
      </section>

      <footer className="landing-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <h2>AI FORENSICS TIME MACHINE</h2>
            <p style={{ color: '#555', marginTop: '12px' }}>Securing the future by investigating the past.</p>
          </div>
          <div className="footer-links" style={{ display: 'flex', gap: '40px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <span style={{ fontWeight: 800 }}>SYSTEM</span>
              <a href="#">Status</a>
              <a href="#">API</a>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <span style={{ fontWeight: 800 }}>POLICY</span>
              <a href="#">Privacy</a>
              <a href="#">Auth</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
