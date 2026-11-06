import { useState, useEffect, useRef } from 'react';
import { chatWithEvidence } from '../api';

const QUICK_STARTER_PROMPTS = [
  { label: '⚡ Summarize Attack Path', prompt: 'Summarize the adversary kill chain and initial access vector step-by-step.' },
  { label: '🔍 Extract All IOCs', prompt: 'Extract all Indicators of Compromise (IPs, malicious paths, processes) into a structured list.' },
  { label: '💻 PowerShell Analysis', prompt: 'Were any suspicious PowerShell or CMD commands executed? Analyze their arguments.' },
  { label: '🛡️ MITRE Mapping', prompt: 'What specific MITRE ATT&CK techniques and tactics were identified in this session?' },
  { label: '🛑 Containment Script', prompt: 'Generate a ready-to-run PowerShell containment script to isolate the host and block malicious IPs.' },
  { label: '📋 CISO Executive Brief', prompt: 'Draft a concise CISO executive incident notification explaining the blast radius and urgency.' }
];

export default function ForensicCopilot({ sessionId, sessionInfo, isOpen, onClose, initialPrompt, onClearInitialPrompt }) {
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      role: 'assistant',
      content: `### 🛡️ Autonomous Forensic AI Copilot Online\n\nI am connected to the active digital forensics session. All answers are strictly grounded in the ingested **EVTX & syslog telemetry**, correlation graphs, and MITRE detection rules.\n\nAsk me anything about attack paths, compromised users, suspicious processes, or request automated containment scripts below.`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      modelUsed: 'gemini-3.5-flash-lite',
      suggestedFollowups: [
        'Summarize the adversary kill chain and initial access vector',
        'Extract all Indicators of Compromise (IOCs) into a list',
        'Generate a ready-to-run PowerShell containment script'
      ]
    }
  ]);

  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeModel, setActiveModel] = useState('GEMINI 3.5 FLASH');
  const [copiedId, setCopiedId] = useState(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 150);
      if (initialPrompt && !isLoading) {
        handleSendMessage(initialPrompt);
        if (onClearInitialPrompt) onClearInitialPrompt();
      }
    }
  }, [isOpen, initialPrompt]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  const handleSendMessage = async (textToSend) => {
    const query = (textToSend || inputQuery).trim();
    if (!query || isLoading) return;

    const userMessageId = `user-${Date.now()}`;
    const userMsg = {
      id: userMessageId,
      role: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setIsLoading(true);

    // Build chat history for context
    const historyPayload = messages
      .filter((m) => m.id !== 'welcome')
      .slice(-6)
      .map((m) => ({ role: m.role, content: m.content }));

    try {
      const res = await chatWithEvidence(sessionId || 'live-session', query, historyPayload);
      
      const assistantMsg = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: res.reply || 'No direct forensic telemetry found for this query.',
        modelUsed: res.model_used || 'gemini-3.5-flash-lite',
        suggestedFollowups: res.suggested_followups || [],
        relevantEventIds: res.relevant_event_ids || [],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      };

      if (res.model_used) {
        setActiveModel(res.model_used.toUpperCase().replace('MODELS/', ''));
      }

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      console.error('[Copilot] Error:', err);
      const errorMsg = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `⚠️ **Copilot Query Error:** Unable to retrieve telemetry response from backend service (${err.message || 'Network Timeout'}). Please verify the backend server is active.`,
        modelUsed: 'local-error-fallback',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const clearChat = () => {
    setMessages([
      {
        id: 'welcome-reset',
        role: 'assistant',
        content: `### 🔄 Session Investigation Context Reset\n\nAI Copilot ready. Active Session: **${sessionId || 'Live Monitor'}**. Ask a new question or click a starter investigation query below.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        modelUsed: activeModel,
        suggestedFollowups: [
          'Summarize the adversary kill chain and initial access vector',
          'Extract all Indicators of Compromise (IOCs) into a list',
          'Generate a ready-to-run PowerShell containment script'
        ]
      }
    ]);
  };

  if (!isOpen) return null;

  return (
    <div className={`forensic-copilot-container ${isExpanded ? 'expanded' : ''}`}>
      {/* ── Copilot Header Bar ── */}
      <div className="copilot-header">
        <div className="copilot-header-left">
          <div className="copilot-live-indicator">
            <span className="live-dot-pulse"></span>
            <span className="copilot-title-text">AI FORENSIC COPILOT</span>
          </div>
          <span className="copilot-model-pill">
            {activeModel.includes('GEMINI') ? '⚡ ' : '🛡️ '}
            {activeModel}
          </span>
          {sessionId && (
            <span className="copilot-session-pill">
              SESSION: #{sessionId.substring(0, 8)}
            </span>
          )}
        </div>

        <div className="copilot-header-actions">
          <button
            className="copilot-icon-btn"
            title="Clear Chat History"
            onClick={clearChat}
          >
            🗑️
          </button>
          <button
            className="copilot-icon-btn"
            title={isExpanded ? 'Restore Size' : 'Expand Terminal'}
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? '❐' : '⛶'}
          </button>
          <button
            className="copilot-icon-btn close"
            title="Close Copilot"
            onClick={onClose}
          >
            ✕
          </button>
        </div>
      </div>

      {/* ── Quick Starter Pills (Always available at top) ── */}
      <div className="copilot-quick-pills-bar">
        <span className="pills-label">QUICK INVESTIGATE:</span>
        <div className="pills-scroll-track">
          {QUICK_STARTER_PROMPTS.map((p, idx) => (
            <button
              key={idx}
              className="copilot-quick-pill"
              onClick={() => handleSendMessage(p.prompt)}
              disabled={isLoading}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Messages Feed ── */}
      <div className="copilot-messages-feed">
        {messages.map((m) => (
          <div key={m.id} className={`copilot-message-row ${m.role}`}>
            <div className="copilot-avatar">
              {m.role === 'user' ? '👤' : '⚡'}
            </div>

            <div className="copilot-message-bubble">
              <div className="copilot-bubble-meta">
                <span className="bubble-author">
                  {m.role === 'user' ? 'SOC ANALYST' : 'COPILOT INVESTIGATOR'}
                </span>
                <span className="bubble-time">{m.timestamp}</span>
                {m.role === 'assistant' && (
                  <button
                    className="bubble-copy-btn"
                    onClick={() => handleCopy(m.content, m.id)}
                    title="Copy response to clipboard"
                  >
                    {copiedId === m.id ? '✓ COPIED' : '📋 COPY'}
                  </button>
                )}
              </div>

              <div className="copilot-bubble-content">
                <RenderCopilotMarkdown content={m.content} onCopy={handleCopy} />
              </div>

              {/* Event References Badges */}
              {m.relevantEventIds && m.relevantEventIds.length > 0 && (
                <div className="copilot-cited-events">
                  <span className="cited-label">GROUNDED EVENTS:</span>
                  {m.relevantEventIds.map((eid, i) => (
                    <span key={i} className="cited-event-badge">
                      EVENT #{eid}
                    </span>
                  ))}
                </div>
              )}

              {/* Follow-up Suggestions Chips */}
              {m.suggestedFollowups && m.suggestedFollowups.length > 0 && !isLoading && (
                <div className="copilot-followups-container">
                  <div className="followup-title">RECOMMENDED FOLLOW-UP INVESTIGATIONS:</div>
                  <div className="followup-chips">
                    {m.suggestedFollowups.map((f, i) => (
                      <button
                        key={i}
                        className="followup-chip"
                        onClick={() => handleSendMessage(f)}
                      >
                        ↳ {f}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="copilot-message-row assistant">
            <div className="copilot-avatar pulse">⚡</div>
            <div className="copilot-message-bubble loading">
              <div className="copilot-thinking-state">
                <div className="copilot-spinner"></div>
                <div className="thinking-text">
                  <span>RETRIEVING FORENSIC EVIDENCE & CORRELATING MITRE TECHNIQUES...</span>
                  <span className="thinking-sub">Querying Google Gemini with active session telemetry</span>
                </div>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* ── Copilot Input Bar ── */}
      <div className="copilot-input-area">
        <div className="copilot-input-wrapper">
          <span className="terminal-prompt">&gt;</span>
          <textarea
            ref={inputRef}
            className="copilot-textarea"
            rows={2}
            placeholder={
              sessionId
                ? "Ask a forensic question about this session (e.g., 'What IP did PowerShell connect to?')..."
                : "Ask anything about cyber forensics or incident response triage..."
            }
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
          />
          <button
            className={`copilot-send-btn ${inputQuery.trim() ? 'active' : ''}`}
            onClick={() => handleSendMessage()}
            disabled={!inputQuery.trim() || isLoading}
            title="Send query (Enter)"
          >
            {isLoading ? '...' : 'TRANSMIT ↵'}
          </button>
        </div>

        <div className="copilot-footer-telemetry">
          <span>AI ENGINE: GOOGLE GEMINI 3.5 FLASH</span>
          <span>CONTEXT: 100% TELEMETRY GROUNDED</span>
          <span>ENTER TO SEND // SHIFT+ENTER FOR NEWLINE</span>
        </div>
      </div>
    </div>
  );
}

/* ── Rich Markdown Renderer for Copilot Responses ── */
function RenderCopilotMarkdown({ content, onCopy }) {
  if (!content) return null;

  // Split code blocks from prose
  const codeBlockRegex = /```([a-zA-Z0-9_\-]*)\n([\s\S]*?)```/g;
  const segments = [];
  let lastIndex = 0;
  let match;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    if (match.index > lastIndex) {
      segments.push({ type: 'text', value: content.substring(lastIndex, match.index) });
    }
    segments.push({
      type: 'code',
      lang: match[1] || 'plaintext',
      value: match[2].trim()
    });
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < content.length) {
    segments.push({ type: 'text', value: content.substring(lastIndex) });
  }

  return (
    <div className="copilot-markdown-rendered">
      {segments.map((seg, sIdx) => {
        if (seg.type === 'code') {
          return (
            <div key={sIdx} className="copilot-code-block">
              <div className="code-block-header">
                <span className="code-lang-tag">{(seg.lang || 'SCRIPT').toUpperCase()}</span>
                <button
                  className="code-copy-btn"
                  onClick={() => onCopy(seg.value, `code-${sIdx}`)}
                >
                  📋 COPY SCRIPT
                </button>
              </div>
              <pre className="code-pre">
                <code>{seg.value}</code>
              </pre>
            </div>
          );
        }

        // Render prose lines
        return (
          <div key={sIdx} className="copilot-prose-block">
            {seg.value.split('\n').map((line, lIdx) => {
              if (line.startsWith('### ')) {
                return <h3 key={lIdx} className="copilot-h3">{line.replace('### ', '')}</h3>;
              }
              if (line.startsWith('## ')) {
                return <h2 key={lIdx} className="copilot-h2">{line.replace('## ', '')}</h2>;
              }
              if (line.startsWith('# ')) {
                return <h1 key={lIdx} className="copilot-h1">{line.replace('# ', '')}</h1>;
              }
              if (line.startsWith('#### ')) {
                return <h4 key={lIdx} className="copilot-h4">{line.replace('#### ', '')}</h4>;
              }
              if (line.startsWith('- ') || line.startsWith('* ')) {
                return (
                  <div key={lIdx} className="copilot-list-item">
                    <span className="list-bullet">▪</span>
                    <span>{renderInlineFormatting(line.substring(2))}</span>
                  </div>
                );
              }
              if (line.match(/^\d+\.\s/)) {
                return (
                  <div key={lIdx} className="copilot-list-item numbered">
                    <span className="list-num">{line.match(/^\d+\./)[0]}</span>
                    <span>{renderInlineFormatting(line.replace(/^\d+\.\s/, ''))}</span>
                  </div>
                );
              }
              if (line.trim() === '') {
                return <div key={lIdx} className="copilot-spacer" />;
              }

              return (
                <p key={lIdx} className="copilot-p">
                  {renderInlineFormatting(line)}
                </p>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

function renderInlineFormatting(text) {
  // Replace inline bold, code badges, and MITRE badges
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);

  return parts.map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      const codeVal = part.slice(1, -1);
      return (
        <span key={i} className="copilot-inline-code">
          {codeVal}
        </span>
      );
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return (
        <strong key={i} className="copilot-bold">
          {part.slice(2, -2)}
        </strong>
      );
    }
    return part;
  });
}

