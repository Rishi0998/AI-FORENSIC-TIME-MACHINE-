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
          <div className="logo-shield">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <circle cx="12" cy="11" r="3"/>
              <path d="M12 8v3l2 2"/>
            </svg>
          </div>
          <div className="logo-text">
            <span>Chronos Forensics</span>
            <span className="small">AI DIGITAL FORENSICS TIME MACHINE</span>
          </div>
        </div>
        <nav className="landing-nav">
          <a href="#features">Capabilities</a>
          <a href="#how-it-works">Pipeline</a>
          <a href="#capabilities">Coverage</a>
          <button 
            className="btn-hero-primary" 
            style={{ padding: '8px 18px', fontSize: '0.8rem' }} 
            onClick={() => navigate('/app')}
          >
            Open Investigation Console &rarr;
          </button>
        </nav>
      </header>

      <main className="landing-hero">
        <div className="hero-badge">
          <span className="hero-badge-dot"></span>
          <span>ENTERPRISE DIGITAL FORENSICS &bull; MITRE ATT&amp;CK CORRELATED</span>
        </div>
        <h1>
          Trace the <span className="accent">Unseen</span>.<br/>
          Rewind the <span className="accent">Attack</span>.
        </h1>
        <p>
          Reconstruct multi-stage security breaches with second-by-second temporal precision. 
          Our autonomous AI correlation engine normalizes disparate log streams, builds interactive attack graphs, 
          and generates executive-ready incident post-mortems in seconds.
        </p>
        <div className="hero-actions">
          <button className="btn-hero-primary" onClick={() => navigate('/app/monitor')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/><path d="M12 2a15 15 0 0 1 4 10"/><circle cx="12" cy="12" r="2"/>
            </svg>
            <span>Launch Live Event Monitor</span>
          </button>
          <button className="btn-hero-secondary" onClick={() => navigate('/app')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            <span>Ingest Host System Logs</span>
          </button>
        </div>
        
        <div className="hero-stats">
          <div className="stat-item">
            <span className="stat-num">100%</span>
            <span className="stat-desc">Local Air-Gapped Privacy</span>
          </div>
          <div className="stat-item">
            <span className="stat-num">&lt; 2s</span>
            <span className="stat-desc">AI Kill Chain Synthesis</span>
          </div>
          <div className="stat-item">
            <span className="stat-num">MITRE</span>
            <span className="stat-desc">ATT&amp;CK Matrix Mapped</span>
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
              <div className="terminal-title">incident_analysis_engine.py &bull; TLS 1.3 Active</div>
            </div>
            <div className="terminal-body">
              <div className="log-line"><span>[INFO]</span> Initializing Chronos telemetry ingestion pipeline...</div>
              <div className="log-line"><span>[INFO]</span> Correlating multi-host SSH &amp; sudo authentication events</div>
              <div className="log-line" style={{ color: '#38bdf8' }}>[DETECT] T1110.001 Brute Force authentication detected from 198.51.100.42</div>
              <div className="log-line" style={{ color: '#f87171' }}>[CRIT] T1548.003 Privilege Escalation to root confirmed</div>
              <div className="log-line"><span>[TRACE]</span> Exfiltration beacon identified to external C2 channel</div>
              <div className="log-line" style={{ color: '#4ade80' }}>[RESOLVED] Full attack chain correlated &bull; Session report ready</div>
              <div className="log-line cursor">_</div>
            </div>
          </div>
        </div>
      </main>

      <section id="features" className="features-section">
        <div className="section-header">
          <h2>Forensic Investigation Suite</h2>
          <p>Enterprise-grade digital forensics tools designed for incident responders and SOC analysts.</p>
        </div>
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/>
              </svg>
            </div>
            <h3>Chrono Event Timeline</h3>
            <p>Scrub through high-volume event logs with millisecond precision to pinpoint the initial compromise vector.</p>
          </div>
          <div className="feature-card">
            <div className="feature-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><circle cx="18" cy="6" r="3"/><line x1="8.6" y1="7.4" x2="15.4" y2="16.6"/><line x1="15.4" y1="7.4" x2="8.6" y2="16.6"/>
              </svg>
            </div>
            <h3>Interactive Attack Graph</h3>
            <p>Visualize lateral movement, infected hosts, elevated processes, and C2 communication nodes in an interactive graph.</p>
          </div>
          <div className="feature-card">
            <div className="feature-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
              </svg>
            </div>
            <h3>AI Incident Intelligence</h3>
            <p>Automated kill chain mapping, MITRE ATT&amp;CK classification, root cause analysis, and one-click PDF/HTML export.</p>
          </div>
        </div>
      </section>

      <section id="how-it-works" className="how-it-works">
        <div className="section-header">
          <h2>Investigation Workflow</h2>
          <p>Streamlined three-step process from raw logs to courtroom-admissible forensic reports.</p>
        </div>
        <div className="process-flow">
          <div className="process-step">
            <div className="step-num">01</div>
            <h4>Ingest &amp; Normalize</h4>
            <p>Upload raw datasets or stream live local Windows/Linux event logs into the forensic queue.</p>
          </div>
          <div className="process-step">
            <div className="step-num">02</div>
            <h4>Correlate &amp; Replay</h4>
            <p>The AI correlation engine maps relationships, flags IOCs, and reconstructs the sequential timeline.</p>
          </div>
          <div className="process-step">
            <div className="step-num">03</div>
            <h4>Export Report</h4>
            <p>Generate cryptographic evidence summaries, mitigation recommendations, and executive briefs.</p>
          </div>
        </div>
      </section>

      <section id="capabilities" className="capabilities-section">
        <div className="section-header">
          <h2>Technical Specifications</h2>
        </div>
        <div className="capabilities-grid">
          <div className="cap-card"><h4>MITRE ATT&amp;CK MAPPING</h4></div>
          <div className="cap-card"><h4>LATERAL MOVEMENT TRACKING</h4></div>
          <div className="cap-card"><h4>PROCESS TREE RECONSTRUCTION</h4></div>
          <div className="cap-card"><h4>AIR-GAPPED AI INFERENCE</h4></div>
          <div className="cap-card"><h4>REAL-TIME TELEMETRY STREAM</h4></div>
          <div className="cap-card"><h4>LEGAL-GRADE EVIDENCE EXPORT</h4></div>
        </div>
      </section>

      <section className="cta-banner">
        <h2>Ready to investigate an incident?</h2>
        <p>Access the investigation console and analyze live host telemetry or ingest logs.</p>
        <button className="btn-hero-primary" style={{ marginTop: '24px' }} onClick={() => navigate('/app')}>
          Open Investigation Console &rarr;
        </button>
      </section>

      <footer className="landing-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <h2>CHRONOS FORENSICS</h2>
            <p style={{ color: 'var(--text-muted)', marginTop: '8px', fontSize: '0.85rem' }}>
              Autonomous digital forensics and incident timeline reconstruction.
            </p>
          </div>
          <div className="footer-links">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <span style={{ fontWeight: 700, fontSize: '0.8rem', color: '#fff' }}>SYSTEM</span>
              <a href="#features">Features</a>
              <a href="#how-it-works">Pipeline</a>
              <a href="/app/settings">Configuration</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
