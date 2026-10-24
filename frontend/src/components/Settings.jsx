import { useState, useEffect } from 'react';
import api from '../api';

export default function Settings() {
  const [config, setConfig] = useState({
    ai_model: 'auto',
    gemini_key: '',
    openai_key: '',
    ollama_url: 'http://localhost:11434',
  });
  const [status, setStatus] = useState(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    api.get('/settings').then(res => setConfig(res.data)).catch(() => {});
  }, []);

  const handleSave = async () => {
    try {
      await api.post('/settings', config);
      setStatus({ type: 'success', msg: 'Settings saved.' });
      setTimeout(() => setStatus(null), 3000);
    } catch (err) {
      setStatus({ type: 'error', msg: 'Failed to save settings.' });
    }
  };

  const handleTestAI = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await api.post('/test-ai');
      setTestResult(res.data);
    } catch (err) {
      setTestResult({ success: false, message: err.response?.data?.detail || 'Test failed' });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="fade-in">
      {/* AI Configuration */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">AI Engine Configuration</div>
        </div>

        <div style={{ maxWidth: 560 }}>
          <FieldGroup label="AI Model Priority">
            <select
              value={config.ai_model}
              onChange={e => setConfig({ ...config, ai_model: e.target.value })}
              style={selectStyle}
            >
              <option value="auto">Auto (Gemini → OpenAI → Ollama → Rule-based)</option>
              <option value="gemini">Google Gemini only</option>
              <option value="openai">OpenAI only</option>
              <option value="ollama">Ollama (local) only</option>
              <option value="none">Rule-based only (no AI)</option>
            </select>
            <p style={helpStyle}>Controls which AI model is used for forensic analysis reports.</p>
          </FieldGroup>

          <FieldGroup label="Gemini API Key">
            <input
              type="password"
              value={config.gemini_key}
              onChange={e => setConfig({ ...config, gemini_key: e.target.value })}
              placeholder="AIzaSy..."
              style={inputStyle}
            />
            <p style={helpStyle}>Get a free key from <a href="https://aistudio.google.com/apikey" target="_blank" rel="noreferrer">aistudio.google.com/apikey</a></p>
          </FieldGroup>

          <FieldGroup label="OpenAI API Key">
            <input
              type="password"
              value={config.openai_key}
              onChange={e => setConfig({ ...config, openai_key: e.target.value })}
              placeholder="sk-..."
              style={inputStyle}
            />
          </FieldGroup>

          <FieldGroup label="Ollama URL">
            <input
              type="text"
              value={config.ollama_url}
              onChange={e => setConfig({ ...config, ollama_url: e.target.value })}
              placeholder="http://localhost:11434"
              style={inputStyle}
            />
          </FieldGroup>

          <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
            <button className="btn btn-primary" onClick={handleSave}>Save Settings</button>
            <button className="btn btn-outline" onClick={handleTestAI} disabled={testing}>
              {testing ? 'Testing...' : 'Test AI Connection'}
            </button>
          </div>

          {status && (
            <div style={{ marginTop: 10, padding: '8px 12px', background: status.type === 'success' ? 'var(--accent-green-dim)' : 'var(--accent-red-dim)', borderRadius: 'var(--radius-sm)', color: status.type === 'success' ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '0.78rem' }}>
              {status.msg}
            </div>
          )}

          {testResult && (
            <div style={{ marginTop: 10, padding: '10px 14px', background: testResult.success ? 'var(--accent-green-dim)' : 'var(--accent-red-dim)', borderRadius: 'var(--radius-sm)', color: testResult.success ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '0.78rem' }}>
              <strong>{testResult.success ? 'AI connected' : 'AI test failed'}</strong>
              {testResult.model && <span> — Model: {testResult.model}</span>}
              {testResult.message && <div style={{ marginTop: 4 }}>{testResult.message}</div>}
            </div>
          )}
        </div>
      </div>

      {/* System Info */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">System Information</div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
          <InfoItem label="Backend" value="FastAPI + SQLite" />
          <InfoItem label="Frontend" value="React + Vite" />
          <InfoItem label="AI Models" value="Gemini 2.0 Flash, GPT-4o-mini" />
          <InfoItem label="Graph Engine" value="NetworkX + Cytoscape.js" />
          <InfoItem label="API Endpoint" value="http://localhost:8000" />
          <InfoItem label="Version" value="3.0.0" />
        </div>
      </div>

      {/* About */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Keyboard Shortcuts</div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, maxWidth: 400 }}>
          {[
            ['Navigate pages', 'Sidebar links'],
            ['New analysis', 'Top-right button'],
            ['Search events', 'Timeline search bar'],
            ['Export PDF', 'Report > Download'],
          ].map(([action, key], i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border-primary)' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{action}</span>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{key}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function FieldGroup({ label, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-heading)', marginBottom: 5 }}>{label}</label>
      {children}
    </div>
  );
}

function InfoItem({ label, value }) {
  return (
    <div style={{ padding: 10, background: 'var(--bg-elevated)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-primary)' }}>
      <div style={{ fontSize: '0.65rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 3 }}>{label}</div>
      <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{value}</div>
    </div>
  );
}

const inputStyle = {
  width: '100%', padding: '8px 12px', background: 'var(--bg-input)',
  border: '1px solid var(--border-secondary)', borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)', fontSize: '0.8rem', fontFamily: 'var(--font-mono)', outline: 'none',
};

const selectStyle = {
  ...inputStyle, fontFamily: 'var(--font-primary)',
};

const helpStyle = {
  fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 3,
};
