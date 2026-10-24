# Project Report: AI Forensics Time Machine

## 1. Executive Summary
The **AI Forensics Time Machine** is an advanced, production-grade cybersecurity platform designed to simplify the complex task of digital forensic log analysis. By leveraging modern AI models (Google Gemini) and real-time visualization techniques, the system enables security analysts to upload raw system logs, detect threats automatically, and reconstruct attack sequences through interactive timelines and graphs.

## 2. Introduction
In the modern digital landscape, large-scale systems generate millions of log entries daily. Manually auditing these logs to identify malicious behavior is nearly impossible for human analysts. Traditional SIEM tools often produce high noise and require significant manual configuration. 

The AI Forensics Time Machine addresses these challenges by introducing an "AI-First" approach to forensics. It utilizes a modular architecture to parse multi-format logs, identify suspicious patterns using rule-based heuristics, and uses LLMs to generate human-readable narratives of security incidents.

## 3. Project Objectives
- **Automated Ingestion:** Support various log formats (Linux, Windows, Network) with automated parsing.
- **Threat Detection:** Implement a rule engine capable of identifying 20+ types of cyberattacks.
- **Visualization:** Provide interactive Cytoscape-based attack graphs and Chart.js timelines.
- **Forensic Replay:** Enable step-by-step chronological playback of security incidents.
- **AI Analysis:** Integrate Google Gemini AI for generating executive summaries and remediation steps.

## 4. Technology Stack

### 4.1 Backend Technologies
| Component | Technology Used |
| :--- | :--- |
| Language | Python 3.10+ |
| Framework | FastAPI |
| Database | SQLite with SQLAlchemy ORM |
| AI Processing | Google Gemini 2.0 Flash |
| Graph Processing | NetworkX |

### 4.2 Frontend Technologies
| Component | Technology Used |
| :--- | :--- |
| Library | React 19 |
| Build Tool | Vite 8 |
| Visualization | Chart.js, react-chartjs-2 |
| Graph Layout | Cytoscape.js |
| Styling | Vanilla CSS |

## 5. System Architecture
The system follows a modern client-server architecture. The backend handles data ingestion, processing, and AI orchestration, while the frontend handles high-performance visualization.

### 5.1 Data Flow
1. **Ingestion:** Users upload log files or select live sources.
2. **Parsing:** Parser service normalizes logs into structured Event format.
3. **Detection:** Engine scans events for threat signatures.
4. **Reconstruction:** Analyzer groups related events into Attack Chains.
5. **AI Enrichment:** AI Service processes data to generate summaries.
6. **Delivery:** JSON data is served to the frontend via REST/WebSockets.

## 6. Key Features
- **Real-Time Monitor:** Live streaming of system logs using WebSockets.
- **Attack Reconstruction Graph:** Visual mapping of attackers (IPs) to targets.
- **Event Timeline:** Temporal view of activity with severity filtering.
- **Forensic Replay UI:** Controls for speed-controlled playback of incidents.
- **Auto-Generated PDF Reports:** Professional documentation for review.

## 7. Detection Methodology
The system employs a hybrid detection model:

### 7.1 Rule-Based Engine
Identifies known patterns of abuse, such as:
- **Brute Force:** 5+ failed login attempts within 60 seconds.
- **Privilege Escalation:** Tracking unauthorized `sudo` executions.
- **Suspicious Recon:** Commands like `whoami`, `ifconfig`, and `nmap`.

### 7.2 AI Behavioral Analysis
When AI is active, the system generates:
- **Narrative Generation:** Translating raw logs into readable stories.
- **Remediation:** Recommending specific security patches or rules.

## 8. User Manual

### 8.1 Setup & Installation
1. Clone the repository and navigate to the project directory.
2. Run `pip install -r requirements.txt` in the backend directory.
3. Run `npm install` in the frontend directory.

### 8.2 Starting the Application
1. Start the backend server by running `python -m uvicorn main:app --reload` in the backend directory.
2. Start the frontend server by running `npm run dev` in the frontend directory.

### 8.3 Using the Dashboard
1. Navigate to **http://localhost:5173/** in your web browser.
2. Upload your log files using the **Upload Logs** button or choose a built-in pre-loaded dataset.
3. View the interactive timeline, explore the attack graph, and replay security incidents.
4. Navigate to the **Analysis** section for an AI-generated forensic report and remediation recommendations.
5. Export the findings as a PDF report.

## 9. Conclusion
The AI Forensics Time Machine demonstrates the power of combining traditional digital forensics with generative AI. It significantly reduces detection and response times by providing automated insights.
