import { useState, useEffect } from 'react';
import { getAnalysis, getEvents } from '../api';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

export default function ReportExport({ sessionId, sessionInfo }) {
  const [analysis, setAnalysis] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!sessionId) return;
    Promise.all([
      getAnalysis(sessionId),
      getEvents(sessionId, true),
    ]).then(([analysisData, eventsData]) => {
      setAnalysis(analysisData);
      setEvents(eventsData.events || []);
    }).catch((e) => { console.error('Report data load error:', e); }).finally(() => setLoading(false));
  }, [sessionId]);

  const generatePDF = () => {
    setGenerating(true);
    setError(null);
    setSuccess(false);

    try {
      const doc = new jsPDF('p', 'mm', 'a4');
      const pw = doc.internal.pageSize.getWidth();
      const ph = 297;
      const m = 15;
      let y = 20;

      const checkPage = (needed = 15) => {
        if (y + needed > ph - 25) { addNewPage(); }
      };

      const addNewPage = () => {
        doc.addPage();
        y = 20;
        doc.setFillColor(10, 14, 23);
        doc.rect(0, 0, pw, ph, 'F');
      };

      const drawSectionHeader = (title) => {
        checkPage(20);
        doc.setTextColor(241, 245, 249);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.text(title, m, y);
        y += 2;
        doc.setDrawColor(59, 130, 246);
        doc.setLineWidth(0.6);
        doc.line(m, y, pw - m, y);
        y += 8;
      };

      /* ── COVER PAGE ───────────────────────────────────────────────── */
      doc.setFillColor(10, 14, 23);
      doc.rect(0, 0, pw, ph, 'F');

      // Top accent line
      doc.setFillColor(59, 130, 246);
      doc.rect(0, 0, pw, 3, 'F');

      doc.setTextColor(241, 245, 249);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(26);
      doc.text('FORENSIC ANALYSIS', m, 45);
      doc.text('REPORT', m, 58);

      doc.setFontSize(11);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(148, 163, 184);
      doc.text('AI Digital Forensics Time Machine', m, 70);

      doc.setDrawColor(30, 41, 59);
      doc.setLineWidth(0.3);
      doc.line(m, 76, pw - m, 76);

      y = 86;
      doc.setFontSize(9);
      const info = [
        ['Session ID', sessionId],
        ['Generated', new Date().toLocaleString()],
        ['Total Events', String(sessionInfo?.total_events || 0)],
        ['Threats Detected', String(sessionInfo?.suspicious_events || 0)],
        ['Attack Phases', String(sessionInfo?.attack_phases || 0)],
        ['Risk Score', `${sessionInfo?.risk_score || 0}/100`],
        ['Risk Level', (sessionInfo?.risk_level || 'unknown').toUpperCase()],
      ];

      info.forEach(([label, value]) => {
        doc.setTextColor(100, 116, 139);
        doc.setFont('helvetica', 'normal');
        doc.text(label + ':', m, y);
        doc.setTextColor(203, 213, 225);
        doc.setFont('helvetica', 'bold');
        doc.text(value, m + 45, y);
        y += 6;
      });

      // Risk badge
      y += 6;
      const rl = (sessionInfo?.risk_level || 'low').toUpperCase();
      const rc = rl === 'CRITICAL' ? [239,68,68] : rl === 'HIGH' ? [249,115,22] : rl === 'MEDIUM' ? [245,158,11] : [100,116,139];
      doc.setFillColor(...rc);
      doc.roundedRect(m, y, 55, 10, 3, 3, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.text(`CLASSIFICATION: ${rl}`, m + 4, y + 7);

      /* ── EXECUTIVE SUMMARY ────────────────────────────────────────── */
      addNewPage();
      drawSectionHeader('1. EXECUTIVE SUMMARY');

      if (analysis?.explanation) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(203, 213, 225);
        const cleanText = analysis.explanation
          .replace(/#{1,3}\s*/g, '')
          .replace(/\*\*/g, '')
          .replace(/\*/g, '')
          .replace(/`/g, '')
          .replace(/🚨|🔴|🟠|🟡|🟢|📋|🧠|🔗|⚠️/g, '');
        const lines = doc.splitTextToSize(cleanText, pw - 2 * m);
        lines.forEach(line => {
          checkPage(5);
          doc.text(line, m, y);
          y += 4.8;
        });
      } else {
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(9);
        doc.setTextColor(100, 116, 139);
        doc.text('No AI analysis available. Rule-based analysis was used.', m, y);
        y += 6;
      }

      /* ── ATTACK KILL CHAIN ────────────────────────────────────────── */
      if (analysis?.chains?.length) {
        y += 6;
        drawSectionHeader('2. ATTACK KILL CHAIN');

        analysis.chains.forEach((chain, i) => {
          checkPage(22);
          // Phase box
          doc.setFillColor(26, 34, 53);
          doc.roundedRect(m, y - 4, pw - 2 * m, 20, 2, 2, 'F');

          doc.setTextColor(241, 245, 249);
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(10);
          doc.text(`Phase ${i + 1}: ${chain.chain_name || chain.phase || 'Unknown'}`, m + 4, y + 2);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7.5);
          doc.setTextColor(148, 163, 184);
          const meta = [`Severity: ${(chain.severity || '?').toUpperCase()}`];
          if (chain.mitre_tactic) meta.push(`MITRE: ${chain.mitre_tactic}`);
          doc.text(meta.join('  |  '), m + 4, y + 8);

          if (chain.description) {
            doc.setTextColor(180, 190, 210);
            const desc = doc.splitTextToSize(chain.description.substring(0, 200), pw - 2 * m - 12);
            desc.slice(0, 2).forEach(l => { doc.text(l, m + 4, y + 13); y += 3.5; });
          }
          y += 18;
        });
      }

      /* ── THREAT EVENT TABLE ───────────────────────────────────────── */
      if (events.length) {
        addNewPage();
        drawSectionHeader('3. THREAT EVENT LOG');

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(148, 163, 184);
        doc.text(`Showing top ${Math.min(events.length, 40)} of ${events.length} suspicious events`, m, y);
        y += 6;

        const tableData = events.slice(0, 40).map(e => [
          (e.timestamp || '').split('T').pop()?.substring(0, 8) || '',
          (e.action || '').substring(0, 22),
          (e.user || '-').substring(0, 12),
          e.ip_address || '-',
          (e.severity || '').toUpperCase(),
          e.mitre_technique || '-',
        ]);

        autoTable(doc, {
          startY: y,
          head: [['Time', 'Action', 'User', 'IP', 'Severity', 'MITRE']],
          body: tableData,
          theme: 'grid',
          styles: {
            fontSize: 6.5,
            textColor: [203, 213, 225],
            cellPadding: 2.5,
            lineColor: [30, 41, 59],
            lineWidth: 0.15,
            font: 'helvetica',
          },
          headStyles: {
            fillColor: [26, 34, 53],
            textColor: [148, 163, 184],
            fontStyle: 'bold',
            fontSize: 7,
            halign: 'left',
          },
          bodyStyles: {
            fillColor: [13, 19, 32],
          },
          alternateRowStyles: {
            fillColor: [17, 24, 39],
          },
          columnStyles: {
            0: { cellWidth: 18, font: 'courier' },
            1: { cellWidth: 38 },
            2: { cellWidth: 22 },
            3: { cellWidth: 30 },
            4: { cellWidth: 18, fontStyle: 'bold' },
            5: { cellWidth: 35, font: 'courier', fontSize: 6 },
          },
          margin: { left: m, right: m },
        });
      }

      /* ── REMEDIATION RECOMMENDATIONS ──────────────────────────────── */
      addNewPage();
      drawSectionHeader('4. REMEDIATION RECOMMENDATIONS');

      const recs = buildRecommendations(events, sessionInfo);
      recs.forEach((rec, i) => {
        checkPage(24);

        // Priority color
        const pc = rec.priority === 'CRITICAL' ? [239,68,68] : rec.priority === 'HIGH' ? [249,115,22] : [245,158,11];

        doc.setTextColor(241, 245, 249);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(9.5);
        doc.text(`${i + 1}. ${rec.title}`, m, y);

        // Priority label
        const labelX = m + doc.getTextWidth(`${i + 1}. ${rec.title}`) + 4;
        doc.setFillColor(...pc);
        doc.roundedRect(labelX, y - 3.5, doc.getTextWidth(rec.priority) + 6, 5, 1.5, 1.5, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(6);
        doc.text(rec.priority, labelX + 3, y);
        y += 5.5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(180, 190, 210);
        const descLines = doc.splitTextToSize(rec.description, pw - 2 * m - 6);
        descLines.forEach(l => {
          checkPage(5);
          doc.text(l, m + 4, y);
          y += 4.2;
        });
        y += 4;
      });

      /* ── FOOTER ON ALL PAGES ──────────────────────────────────────── */
      const totalPages = doc.internal.getNumberOfPages();
      for (let p = 1; p <= totalPages; p++) {
        doc.setPage(p);
        // Footer line
        doc.setDrawColor(30, 41, 59);
        doc.setLineWidth(0.2);
        doc.line(m, ph - 12, pw - m, ph - 12);
        // Footer text
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        doc.setFont('helvetica', 'normal');
        doc.text('Digital Forensics Time Machine  |  CONFIDENTIAL', m, ph - 8);
        doc.text(`Page ${p} of ${totalPages}`, pw - m - 22, ph - 8);
      }

      doc.save(`forensic-report-${sessionId}.pdf`);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 4000);
    } catch (err) {
      console.error('PDF generation error:', err);
      setError(`PDF generation failed: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  if (loading) {
    return (
      <div className="card fade-in">
        <div className="loading-state">
          <div className="spinner"></div>
          <div className="loading-text">Loading analysis data...</div>
        </div>
      </div>
    );
  }

  const recs = buildRecommendations(events, sessionInfo);

  return (
    <div className="fade-in">
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            Forensic Report Export
          </div>
          <button className="btn btn-primary" onClick={generatePDF} disabled={generating}>
            {generating ? 'Generating...' : 'Download PDF Report'}
          </button>
        </div>

        {success && (
          <div style={{ marginBottom: 12, padding: '10px 14px', background: 'var(--accent-green-dim)', borderRadius: 'var(--radius-sm)', color: 'var(--accent-green)', fontSize: '0.8rem', border: '1px solid rgba(16,185,129,0.2)' }}>
            Report downloaded successfully.
          </div>
        )}

        {error && (
          <div style={{ marginBottom: 12, padding: '10px 14px', background: 'var(--accent-red-dim)', borderRadius: 'var(--radius-sm)', color: 'var(--accent-red)', fontSize: '0.8rem', border: '1px solid rgba(239,68,68,0.2)' }}>
            {error}
          </div>
        )}

        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 20 }}>
          Generate a comprehensive PDF report containing executive summary, attack kill chain analysis,
          threat event log, MITRE ATT&CK mapping, and prioritized remediation recommendations.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
          <PreviewCard title="Cover Page" items={[`Session: ${sessionId}`, `Events: ${sessionInfo?.total_events}`, `Risk: ${sessionInfo?.risk_level?.toUpperCase()}`]} />
          <PreviewCard title="Executive Summary" items={[`AI-powered analysis`, `Engine: ${analysis?.model_used || 'rule-based'}`]} />
          <PreviewCard title="Kill Chain" items={(analysis?.chains || []).slice(0, 3).map(c => c.chain_name || c.phase)} />
          <PreviewCard title="Threat Log" items={[`${events.length} threat events`, `Tabulated with MITRE tags`]} />
          <PreviewCard title="Remediation" items={[`${recs.length} recommendations`, 'Prioritized action items']} />
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Remediation Recommendations</div>
          <span className="card-subtitle">{recs.length} items</span>
        </div>

        {recs.map((rec, i) => (
          <div key={i} style={{ padding: '12px 0', borderBottom: i < recs.length - 1 ? '1px solid var(--border-primary)' : 'none' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-heading)' }}>{i + 1}. {rec.title}</span>
              <span className={`badge badge-${rec.priority === 'CRITICAL' ? 'critical' : rec.priority === 'HIGH' ? 'high' : 'medium'}`}>{rec.priority}</span>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', paddingLeft: 16 }}>{rec.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function PreviewCard({ title, items }) {
  return (
    <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-md)', padding: 14 }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-heading)', marginBottom: 6 }}>{title}</div>
      {items.map((item, i) => <div key={i} style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 2 }}>{item}</div>)}
    </div>
  );
}

function buildRecommendations(events, sessionInfo) {
  const recs = [];
  const rules = events.map(e => e.detection_rule).filter(Boolean);
  const actions = events.map(e => e.action).filter(Boolean);

  if (rules.includes('brute_force') || rules.includes('failed_login') || actions.some(a => a.includes('failed'))) {
    recs.push({ title: 'Implement Account Lockout Policies', priority: 'CRITICAL', description: 'Configure automatic account lockout after 5 failed login attempts. Implement progressive delays between attempts. Deploy fail2ban or equivalent intrusion prevention to automatically block offending IPs.' });
    recs.push({ title: 'Enable Multi-Factor Authentication', priority: 'CRITICAL', description: 'Deploy MFA on all SSH and administrative access points. Use hardware tokens or TOTP-based authentication. Disable password-only authentication for privileged accounts.' });
    recs.push({ title: 'Block Malicious Source IPs', priority: 'HIGH', description: 'Add identified attacker IPs to firewall deny rules. Implement GeoIP-based blocking for regions with no legitimate traffic. Configure rate limiting on authentication endpoints.' });
  }
  if (rules.includes('external_login') || rules.includes('privilege_escalation')) {
    recs.push({ title: 'Audit Privileged Access', priority: 'CRITICAL', description: 'Review all accounts with sudo/root access. Remove unnecessary privileges following principle of least privilege. Implement PAM solutions.' });
    recs.push({ title: 'Investigate Compromised Sessions', priority: 'HIGH', description: 'Immediately terminate suspicious active sessions. Reset credentials for all affected accounts. Review command history for data exfiltration.' });
  }
  if (rules.includes('suspicious_process') || rules.includes('known_suspicious_binary')) {
    recs.push({ title: 'Deploy EDR Solution', priority: 'HIGH', description: 'Install endpoint detection agents on all critical systems. Configure real-time process monitoring. Block execution of unauthorized binaries.' });
  }
  if (rules.includes('outbound_external')) {
    recs.push({ title: 'Investigate Data Exfiltration', priority: 'CRITICAL', description: 'Analyze network traffic for unusual outbound transfers. Implement DLP policies. Block unauthorized outbound connections.' });
  }
  recs.push({ title: 'Enhance Log Monitoring', priority: 'MEDIUM', description: 'Centralize all logs to a SIEM platform. Enable real-time alerting for critical events. Ensure log retention meets compliance requirements (min 90 days).' });
  recs.push({ title: 'Conduct Security Assessment', priority: 'MEDIUM', description: 'Perform vulnerability assessment of affected systems. Review network segmentation and firewall rules. Apply all security patches.' });
  if (!recs.some(r => r.title.includes('MFA'))) {
    recs.push({ title: 'Strengthen Authentication', priority: 'HIGH', description: 'Enforce strong 14+ character password policies. Use SSH key pairs. Disable root login over SSH.' });
  }
  return recs;
}
