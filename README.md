# AI Digital Forensics Time Machine

A production-grade, AI-powered cybersecurity dashboard for log forensics, attack reconstruction, and incident response reporting.

Upload system/network logs → get automated threat detection, interactive attack graphs, MITRE ATT&CK mapping, AI-powered incident analysis, and exportable PDF forensic reports with remediation recommendations.

---

## Features

| Feature | Description |
|---------|-------------|
| **Log Ingestion** | Upload `.log`, `.txt` files or extract live host channels (Windows System/App/PowerShell/Defender, Linux syslog) |
| **Real-Time Monitor** | WebSocket-based live streaming of host system events with live MITRE threat detection |
| **Event Timeline** | Interactive stacked bar chart with search, severity filtering, and paginated event table |
| **Attack Graph** | Cytoscape.js DAG visualization mapping users → IPs → processes with node inspection |
| **Forensic Replay** | Step-by-step chronological threat playback with speed controls (0.5x–4x) |
| **AI Analysis** | Risk scoring, attack kill chain mapping, MITRE ATT&CK tagging, executive summary |
| **PDF Export** | Multi-page dark-themed forensic report with cover page, threat table, and remediation |
| **Settings** | AI engine configuration, API key management, model priority selection |

---

## Tech Stack

### Backend
- **Framework:** FastAPI (Python 3.10+)
- **Database:** SQLite via SQLAlchemy
- **AI Engine:** Google Gemini 2.0 Flash (with rule-based fallback)
- **Graph Engine:** NetworkX
- **Real-time:** WebSocket (for live log monitoring)

### Frontend
- **Framework:** React 19 + Vite 8
- **Routing:** React Router v7
- **Charts:** Chart.js + react-chartjs-2
- **Graph:** Cytoscape.js + cytoscape-dagre
- **PDF:** jsPDF + jspdf-autotable
- **Styling:** Vanilla CSS (dark cybersecurity theme)

---

## Project Structure

```
ai-forensics-time-machine/
├── backend/
│   ├── main.py                  # FastAPI entry point
│   ├── database.py              # SQLite/SQLAlchemy setup
│   ├── requirements.txt         # Python dependencies
│   ├── .env                     # API keys & config (gitignored)
│   ├── models/
│   │   └── event.py             # ORM models (Event, AttackChain, AnalysisResult)
│   ├── routes/
│   │   └── api.py               # All REST + WebSocket endpoints
│   ├── services/
│   │   ├── parser.py            # Multi-format log parser (Linux, Windows, network)
│   │   ├── detector.py          # Threat detection engine (20+ rules)
│   │   ├── analyzer.py          # Attack chain builder + narrative generator
│   │   ├── graph.py             # NetworkX attack graph construction
│   │   ├── ai_explainer.py      # Gemini AI integration + fallback engine
│   │   ├── log_fetcher.py       # Live system log and channel management
│   │   └── monitor.py           # Real-time WebSocket live event monitor
│
├── frontend/
│   ├── index.html               # App entry point
│   ├── package.json             # Node.js dependencies
│   ├── vite.config.js           # Vite build config
│   └── src/
│       ├── main.jsx             # React root
│       ├── App.jsx              # Router + sidebar layout
│       ├── api.js               # Axios API client
│       ├── index.css            # Full design system (dark theme)
│       └── components/
│           ├── Upload.jsx       # File upload + source selector
│           ├── LiveMonitor.jsx  # WebSocket real-time feed
│           ├── Timeline.jsx     # Event chart + searchable table
│           ├── Graph.jsx        # Cytoscape.js attack graph
│           ├── Replay.jsx       # Step-by-step threat playback
│           ├── Analysis.jsx     # Risk score + kill chain + AI report
│           ├── ReportExport.jsx # PDF generation + remediation
│           └── Settings.jsx     # AI config + system info
│
└── README.md
```

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- npm or yarn

### 1. Clone & Setup Backend

```bash
cd ai-forensics-time-machine/backend

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Configure AI — create .env file
cat > .env << EOF
GEMINI_API_KEY=your-gemini-api-key-here
AI_MODEL=auto
EOF

# Start the backend server
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Setup Frontend

```bash
cd ai-forensics-time-machine/frontend

# Install Node.js dependencies
npm install

# Start the development server
npm run dev
```

### 3. Open the Dashboard

Navigate to **http://localhost:5173** in your browser.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload-logs` | Upload log file or select a built-in source |
| `GET` | `/api/events` | Get parsed events for a session |
| `GET` | `/api/timeline` | Get timeline data with severity breakdown |
| `GET` | `/api/graph` | Get attack graph (nodes + edges) |
| `GET` | `/api/analysis` | Get AI analysis, risk score, kill chain |
| `GET` | `/api/replay` | Get ordered suspicious events for replay |
| `GET` | `/api/log-sources` | List available log sources |
| `WS` | `/api/ws/monitor` | WebSocket for real-time log streaming |
| `GET` | `/api/settings` | Get current AI configuration |
| `POST` | `/api/settings` | Save AI configuration |
| `POST` | `/api/test-ai` | Test AI model connectivity |
| `GET` | `/api/sample-logs` | List sample log datasets |

Full interactive docs: **http://localhost:8000/docs** (Swagger UI)

---

## AI Configuration

The system supports multiple AI backends with automatic fallback:

| Priority | Engine | Model | Notes |
|----------|--------|-------|-------|
| 1 | Google Gemini | gemini-2.0-flash-lite | Free tier, 15 RPM |
| 2 | Google Gemini | gemini-2.0-flash | Fallback model |
| 3 | Google Gemini | gemini-1.5-flash | Legacy fallback |
| 4 | Rule-based | — | Always available, no API key needed |

### Getting a Gemini API Key (Free)
1. Go to [aistudio.google.com/apikey](https://aistudio.google.com/apikey)
2. Click "Create API Key"
3. Paste the key in **Settings > Gemini API Key** or in `backend/.env`

---

## Log Format Support

| Format | Example Sources |
|--------|----------------|
| **Linux Auth/Syslog** | `/var/log/auth.log`, `/var/log/syslog`, honeypot logs |
| **PAM Unix** | `pam_unix(sshd:auth)` style logs |
| **ISO Timestamp Syslog** | Modern systemd/journald logs |
| **Windows Event Log** | Security EventID-based logs (4625, 4624, etc.) |
| **Network/Firewall** | iptables, netflow, firewall DROP/ACCEPT logs |

---

## Detection Rules

The threat detection engine includes 20+ rules:

- **Brute Force** — Failed login spike detection
- **Invalid User** — SSH attempts with non-existent users
- **Privilege Escalation** — Unauthorized sudo/su usage
- **Suspicious Processes** — Known malicious binaries (nmap, nc, wget to pipes, etc.)
- **External Logins** — SSH from non-RFC1918 IP addresses
- **Post-Exploitation Recon** — Commands like `whoami`, `cat /etc/shadow`, `uname -a`
- **Outbound C2** — Connections to external IPs from internal hosts
- **CRON Persistence** — Unauthorized CRON job modifications

Each detection maps to **MITRE ATT&CK** tactics and techniques.

---

## PDF Report Contents

The exported forensic report includes:

1. **Cover Page** — Session metadata, risk classification badge
2. **Executive Summary** — AI-generated or rule-based incident analysis
3. **Attack Kill Chain** — Phase-by-phase attack reconstruction
4. **Threat Event Log** — Top 40 suspicious events in structured table
5. **Remediation Recommendations** — Prioritized action items (CRITICAL/HIGH/MEDIUM)

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `AI_MODEL` | `auto` | AI model selection: `auto`, `gemini`, `openai`, `ollama`, `none` |
| `OPENAI_API_KEY` | — | OpenAI API key (optional) |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama local server URL (optional) |

---

## Screenshots

### Log Upload
Clean, professional upload interface with drag-and-drop and log source cards.

### Event Timeline
Interactive stacked bar chart with search, severity filtering, and paginated event log.

### Attack Graph
Cytoscape.js visualization mapping the relationships between attackers, targets, and processes.

### AI Analysis
Risk scoring, attack kill chain mapping, and AI-generated executive summary.

### PDF Report Export
One-click forensic report generation with remediation recommendations.

### Settings
AI engine configuration with API key management and system information.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Address already in use` | Run `fuser -k 8000/tcp` then restart backend |
| AI shows "rule-based" | Add a Gemini API key in Settings or `.env` |
| Live Monitor shows no events | Ensure read permissions on `/var/log/auth.log` (may need `sudo`) |
| PDF not downloading | Check browser console for errors; ensure jsPDF is installed |
| CORS errors | Backend must run on port 8000, frontend on 5173 |

---

## License

MIT License — Free for personal and commercial use.

---

## Credits

- **AI Engine:** Google Gemini API
- **Graph Visualization:** Cytoscape.js
- **PDF Generation:** jsPDF + jspdf-autotable
- **Log Datasets:** Loghub, Elastic, SecRepo
- **MITRE ATT&CK:** Framework for threat classification
