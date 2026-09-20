/**
 * MAVERICK Security Analyst Operations Dashboard - Client Controller
 * Manages priority queue, status toggles, filtering, and forensic dossier rendering.
 */

(function () {
  'use strict';

  // --- State ---
  let currentSubmissions = [];
  let activeCaseId = null;
  let activeReportData = null;

  // --- DOM Elements ---
  const statTotal = document.getElementById('stat-total');
  const statNew = document.getElementById('stat-new');
  const statCritical = document.getElementById('stat-critical');
  const statHigh = document.getElementById('stat-high');

  const statusFilter = document.getElementById('status-filter');
  const verdictFilter = document.getElementById('verdict-filter');
  const searchInput = document.getElementById('search-input');
  const clearSearchBtn = document.getElementById('clear-search-btn');
  const refreshBtn = document.getElementById('refresh-btn');

  const queueTableBody = document.getElementById('queue-table-body');
  const inspectorPanel = document.getElementById('inspector-panel');
  const inspectHeaderCaseId = document.getElementById('inspect-header-case-id');
  const closeInspectorBtn = document.getElementById('close-inspector-btn');
  const inspectStatusToggleBtn = document.getElementById('inspect-status-toggle-btn');

  // Inspector Overview Elements
  const resCaseId = document.getElementById('res-case-id');
  const copyCaseIdBtn = document.getElementById('copy-case-id-btn');
  const resCaseTime = document.getElementById('res-case-time');
  const resVerdictBadge = document.getElementById('res-verdict-badge');
  const resVerdictIcon = document.getElementById('res-verdict-icon');
  const resVerdictText = document.getElementById('res-verdict-text');
  const resRiskScore = document.getElementById('res-risk-score');
  const resRiskFill = document.getElementById('res-risk-fill');
  const downloadPdfBtn = document.getElementById('download-pdf-btn');

  const resSubject = document.getElementById('res-subject');
  const resFrom = document.getElementById('res-from');
  const resTo = document.getElementById('res-to');
  const resDate = document.getElementById('res-date');

  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  // --- Helpers ---
  function formatBytes(bytes, decimals = 1) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatTime(isoStr) {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch (_) {
      return isoStr;
    }
  }

  // --- Queue Fetching & Rendering ---
  async function fetchQueue() {
    queueTableBody.innerHTML = '<tr><td colspan="8" class="empty-cell">Refreshing triage queue...</td></tr>';

    const params = new URLSearchParams();
    if (statusFilter.value !== 'all') params.append('status', statusFilter.value);
    if (verdictFilter.value !== 'all') params.append('verdict', verdictFilter.value);
    if (searchInput.value.trim()) params.append('search', searchInput.value.trim());

    try {
      const resp = await fetch(`/api/submissions?${params.toString()}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);

      const data = await resp.json();
      currentSubmissions = data.submissions || [];
      updateMetrics(data.metrics || {});
      renderTable(currentSubmissions);
    } catch (err) {
      queueTableBody.innerHTML = `<tr><td colspan="8" class="empty-cell" style="color: #ef4444;">Failed to load queue: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  function updateMetrics(metrics) {
    statTotal.textContent = metrics.total || 0;
    statNew.textContent = metrics.new || 0;
    statCritical.textContent = metrics.critical || 0;
    statHigh.textContent = metrics.high || 0;
  }

  function renderTable(submissions) {
    queueTableBody.innerHTML = '';
    if (submissions.length === 0) {
      queueTableBody.innerHTML = '<tr><td colspan="8" class="empty-cell">No matching submissions in queue.</td></tr>';
      return;
    }

    submissions.forEach((item, idx) => {
      const tr = document.createElement('tr');
      if (item.case_id === activeCaseId) {
        tr.classList.add('row-active');
      }

      const verdict = (item.verdict || 'Low').toUpperCase();
      let verdictClass = 'badge-verdict-low';
      let verdictIcon = '🛡️';
      if (verdict === 'CRITICAL') {
        verdictClass = 'badge-verdict-critical';
        verdictIcon = '☣️';
      } else if (verdict === 'HIGH') {
        verdictClass = 'badge-verdict-high';
        verdictIcon = '🚨';
      } else if (verdict === 'MEDIUM') {
        verdictClass = 'badge-verdict-medium';
        verdictIcon = '⚠️';
      }

      const isNew = (item.status || 'New').toLowerCase() === 'new';
      const statusClass = isNew ? 'status-new' : 'status-reviewed';
      const statusText = isNew ? '● New' : '✓ Reviewed';

      tr.innerHTML = `
        <td style="color: var(--text-muted); font-family: var(--font-mono);">${idx + 1}</td>
        <td class="cell-case-id">${escapeHtml(item.case_id)}</td>
        <td class="cell-filename" title="${escapeHtml(item.filename)}">✉️ ${escapeHtml(item.filename)}</td>
        <td>
          <span class="badge-verdict ${verdictClass}">
            ${verdictIcon} ${verdict}
          </span>
        </td>
        <td style="font-family: var(--font-mono); font-weight: 700;">
          ${Number(item.risk_score).toFixed(2)}
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">
          ${formatTime(item.upload_timestamp)}
        </td>
        <td>
          <button type="button" class="status-pill ${statusClass}" data-case-id="${escapeHtml(item.case_id)}" data-status="${escapeHtml(item.status)}" title="Click to toggle status">
            ${statusText}
          </button>
        </td>
        <td style="text-align: right;">
          <button type="button" class="btn btn-preset btn-inspect" data-case-id="${escapeHtml(item.case_id)}">
            Inspect 🔍
          </button>
        </td>
      `;

      // Row click: inspect dossier
      tr.addEventListener('click', (e) => {
        // If clicking status button, do not trigger row inspection
        if (e.target.closest('.status-pill')) return;
        inspectCase(item.case_id);
      });

      // Status pill click: toggle status
      const statusBtn = tr.querySelector('.status-pill');
      statusBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const curStatus = statusBtn.getAttribute('data-status');
        const nextStatus = curStatus.toLowerCase() === 'new' ? 'Reviewed' : 'New';
        await toggleStatus(item.case_id, nextStatus);
      });

      queueTableBody.appendChild(tr);
    });
  }

  // --- Status Toggle ---
  async function toggleStatus(caseId, nextStatus) {
    try {
      const resp = await fetch(`/api/submissions/${encodeURIComponent(caseId)}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (!resp.ok) throw new Error(`Failed to update status: ${resp.statusText}`);

      // Refresh queue and metrics
      await fetchQueue();

      // If this case is currently inspected, update inspector button
      if (activeCaseId === caseId) {
        updateInspectorStatusBtn(nextStatus);
      }
    } catch (err) {
      alert(`Status update failed: ${err.message}`);
    }
  }

  function updateInspectorStatusBtn(status) {
    const isNew = (status || 'New').toLowerCase() === 'new';
    if (isNew) {
      inspectStatusToggleBtn.textContent = '✓ Mark as Reviewed';
      inspectStatusToggleBtn.className = 'btn btn-preset';
    } else {
      inspectStatusToggleBtn.textContent = '↩ Reopen as New';
      inspectStatusToggleBtn.className = 'btn btn-preset';
    }
  }

  // --- Inspect Forensic Dossier ---
  async function inspectCase(caseId) {
    activeCaseId = caseId;
    inspectHeaderCaseId.textContent = caseId;

    // Highlight active row in table
    const rows = queueTableBody.querySelectorAll('tr');
    rows.forEach(r => {
      const cidElem = r.querySelector('.cell-case-id');
      if (cidElem && cidElem.textContent === caseId) {
        r.classList.add('row-active');
      } else {
        r.classList.remove('row-active');
      }
    });

    try {
      const resp = await fetch(`/api/submissions/${encodeURIComponent(caseId)}`);
      if (!resp.ok) throw new Error('Failed to load full submission details');

      const data = await resp.json();
      const sub = data.submission || {};
      const report = sub.full_report_json || {};
      activeReportData = report;

      renderInspector(sub, report);
      updateInspectorStatusBtn(sub.status);

      inspectorPanel.style.display = 'block';
      inspectorPanel.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
      alert(`Error loading case: ${err.message}`);
    }
  }

  function renderInspector(sub, report) {
    const meta = report.case_metadata || {};
    const summary = report.case_summary || {};
    const threat = report.threat_assessment || {};
    const fusion = report.evidence_fusion || {};
    const ml = report.ml_findings || {};
    const auth = report.auth_analysis || {};
    const ioc = report.ioc_evidence || {};
    const geo = report.geo_intelligence || {};
    const att = report.attachment_findings || {};
    const timeline = report.investigation_timeline || [];
    const recs = report.recommendations || [];

    // Header Overview
    resCaseId.textContent = sub.case_id || 'MAV-UNKNOWN';
    resCaseTime.textContent = formatTime(sub.upload_timestamp);

    const verdict = (sub.verdict || threat.verdict || 'Low').toUpperCase();
    const score = typeof sub.risk_score === 'number' ? sub.risk_score : (threat.risk_score || 0.0);

    resVerdictText.textContent = verdict;
    resRiskScore.textContent = score.toFixed(2);

    resVerdictBadge.className = 'verdict-badge-lg';
    let meterColor = '#10b981';
    let verdictIcon = '🛡️';

    if (verdict === 'CRITICAL') {
      resVerdictBadge.classList.add('verdict-critical');
      meterColor = '#ef4444';
      verdictIcon = '☣️';
    } else if (verdict === 'HIGH') {
      resVerdictBadge.classList.add('verdict-high');
      meterColor = '#f97316';
      verdictIcon = '🚨';
    } else if (verdict === 'MEDIUM') {
      resVerdictBadge.classList.add('verdict-medium');
      meterColor = '#f59e0b';
      verdictIcon = '⚠️';
    } else {
      resVerdictBadge.classList.add('verdict-low');
      meterColor = '#10b981';
      verdictIcon = '🛡️';
    }

    resVerdictIcon.textContent = verdictIcon;
    resRiskFill.style.backgroundColor = meterColor;
    resRiskFill.style.width = Math.min(100, Math.max(0, Math.round(score * 100))) + '%';

    // Email Summary Strip
    resSubject.textContent = summary.subject || '(No Subject)';
    resFrom.textContent = summary.sender || '(No Sender)';
    resTo.textContent = Array.isArray(summary.recipient) ? summary.recipient.join(', ') : (summary.recipient || '(No Recipient)');
    resDate.textContent = summary.date || 'N/A';

    // Tab Header Counts
    const mlPct = Math.round((ml.phishing_probability || 0) * 100);
    document.getElementById('tab-ml-score').textContent = `${mlPct}%`;
    document.getElementById('tab-att-count').textContent = (att.total_analyzed || 0);

    // Tab 1: Fusion Breakdown
    const breakdown = fusion.score_breakdown || {};
    const mlScore = breakdown.ml_score_weighted || 0.0;
    const authScore = breakdown.auth_score_weighted || 0.0;
    const attScore = breakdown.attachment_score_weighted || 0.0;
    const iocScore = breakdown.ioc_geo_score_weighted || 0.0;

    document.getElementById('fusion-ml-score').textContent = `${mlScore.toFixed(2)} / 0.40`;
    document.getElementById('fusion-auth-score').textContent = `${authScore.toFixed(2)} / 0.20`;
    document.getElementById('fusion-att-score').textContent = `${attScore.toFixed(2)} / 0.20`;
    document.getElementById('fusion-ioc-score').textContent = `${iocScore.toFixed(2)} / 0.20`;

    document.getElementById('fusion-ml-bar').style.width = `${(mlScore / 0.40) * 100}%`;
    document.getElementById('fusion-auth-bar').style.width = `${(authScore / 0.20) * 100}%`;
    document.getElementById('fusion-att-bar').style.width = `${(attScore / 0.20) * 100}%`;
    document.getElementById('fusion-ioc-bar').style.width = `${(iocScore / 0.20) * 100}%`;

    document.getElementById('fusion-ml-raw').textContent = `Raw ML Prob: ${(breakdown.raw_ml_score || ml.phishing_probability || 0).toFixed(3)}`;
    document.getElementById('fusion-auth-raw').textContent = `Raw Auth Penalty: ${(breakdown.raw_auth_score || 0).toFixed(2)}`;
    document.getElementById('fusion-att-raw').textContent = `Raw Att Risk: ${(breakdown.raw_attachment_score || 0).toFixed(2)}`;
    document.getElementById('fusion-ioc-raw').textContent = `Raw IOC/Geo: ${(breakdown.raw_ioc_geo_score || 0).toFixed(2)}`;

    const factorsList = document.getElementById('res-factors-list');
    factorsList.innerHTML = '';
    const factors = fusion.contributing_factors || [];
    if (factors.length === 0) {
      factorsList.innerHTML = '<li>No anomalous threat factors triggered.</li>';
    } else {
      factors.forEach(f => {
        const li = document.createElement('li');
        li.textContent = f;
        factorsList.appendChild(li);
      });
    }

    // Tab 2: ML Findings
    const predLabel = (ml.predicted_label || 'benign').toUpperCase();
    const mlLabelElem = document.getElementById('ml-predicted-label');
    mlLabelElem.textContent = predLabel;
    mlLabelElem.style.color = predLabel === 'PHISHING' ? '#ef4444' : '#10b981';

    document.getElementById('ml-prob-val').textContent = `${((ml.phishing_probability || 0) * 100).toFixed(1)}%`;
    document.getElementById('ml-confidence-val').textContent = (ml.confidence_level || 'Normal').toUpperCase();

    const termsCloud = document.getElementById('ml-terms-cloud');
    termsCloud.innerHTML = '';
    const terms = ml.top_influential_terms || [];
    if (terms.length === 0) {
      termsCloud.innerHTML = '<span class="term-badge">No influential keywords triggered</span>';
    } else {
      terms.forEach(t => {
        const span = document.createElement('span');
        span.className = 'term-badge';
        const termName = typeof t === 'string' ? t : (t.term || 'term');
        const termWeight = t.impact !== undefined ? `+${Number(t.impact).toFixed(3)}` : '';
        span.innerHTML = `${escapeHtml(termName)} ${termWeight ? `<span class="term-weight">${termWeight}</span>` : ''}`;
        termsCloud.appendChild(span);
      });
    }

    // Tab 3: Authentication
    renderAuthBadge('spf-status', auth.spf ? auth.spf.status : 'none');
    renderAuthBadge('dkim-status', auth.dkim ? auth.dkim.status : 'none');
    renderAuthBadge('dmarc-status', auth.dmarc ? auth.dmarc.status : 'none');

    document.getElementById('spf-domain').textContent = (auth.spf && auth.spf.domain) || 'N/A';
    document.getElementById('spf-ip').textContent = (auth.spf && auth.spf.ip) || 'N/A';
    document.getElementById('spf-aligned').textContent = (auth.alignment && auth.alignment.spf_aligned) ? 'Aligned (Pass)' : 'Misaligned / None';

    document.getElementById('dkim-domain').textContent = (auth.dkim && auth.dkim.domain) || 'N/A';
    document.getElementById('dkim-selector').textContent = (auth.dkim && auth.dkim.selector) || 'N/A';
    document.getElementById('dkim-aligned').textContent = (auth.alignment && auth.alignment.dkim_aligned) ? 'Aligned (Pass)' : 'Misaligned / None';

    document.getElementById('dmarc-policy').textContent = (auth.dmarc && auth.dmarc.policy) ? auth.dmarc.policy.toUpperCase() : 'NONE';
    document.getElementById('dmarc-aligned').textContent = (auth.alignment && auth.alignment.dmarc_aligned) ? 'Aligned (Pass)' : 'Fail / None';

    const authNotesList = document.getElementById('auth-notes-list');
    authNotesList.innerHTML = '';
    const notes = auth.auth_notes || [];
    if (notes.length === 0) {
      authNotesList.innerHTML = '<li>All authentication mechanisms evaluated cleanly.</li>';
    } else {
      notes.forEach(n => {
        const li = document.createElement('li');
        li.textContent = n;
        authNotesList.appendChild(li);
      });
    }

    // Tab 4: IOCs & Geolocation
    const ips = ioc.ips || [];
    const urls = ioc.urls || [];
    const domains = ioc.domains || [];
    const excludedIps = ioc.excluded_ips || [];
    const geoResults = geo.results || [];

    document.getElementById('ioc-count-ips').textContent = ips.length;
    document.getElementById('ioc-count-urls').textContent = urls.length;
    document.getElementById('ioc-count-domains').textContent = domains.length;
    document.getElementById('ioc-count-rfc1918').textContent = excludedIps.length;

    const geoTableBody = document.getElementById('geo-table-body');
    geoTableBody.innerHTML = '';
    if (geoResults.length === 0) {
      geoTableBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No public IP addresses found to geolocate.</td></tr>';
    } else {
      geoResults.forEach(g => {
        const tr = document.createElement('tr');
        if (g.error) {
          tr.innerHTML = `
            <td><code>${escapeHtml(g.ip)}</code></td>
            <td colspan="4" style="color: #f59e0b;">Lookup Error: ${escapeHtml(g.error_message || 'Telemetry unavailable')}</td>
          `;
        } else {
          tr.innerHTML = `
            <td><code>${escapeHtml(g.ip)}</code></td>
            <td><strong>${escapeHtml(g.country || 'Unknown')}</strong></td>
            <td>${escapeHtml([g.region, g.city].filter(Boolean).join(', ') || 'N/A')}</td>
            <td><code>${escapeHtml(g.asn || 'N/A')}</code></td>
            <td>${escapeHtml(g.isp || 'N/A')}</td>
          `;
        }
        geoTableBody.appendChild(tr);
      });
    }

    const urlsList = document.getElementById('ioc-urls-list');
    urlsList.innerHTML = '';
    if (urls.length === 0) {
      urlsList.innerHTML = '<li class="empty-li">No URLs extracted.</li>';
    } else {
      urls.forEach(u => {
        const li = document.createElement('li');
        li.textContent = u;
        urlsList.appendChild(li);
      });
    }

    const domainsList = document.getElementById('ioc-domains-list');
    domainsList.innerHTML = '';
    if (domains.length === 0) {
      domainsList.innerHTML = '<li class="empty-li">No unique domains identified.</li>';
    } else {
      domains.forEach(d => {
        const li = document.createElement('li');
        li.textContent = d;
        domainsList.appendChild(li);
      });
    }

    const exclIpsTags = document.getElementById('ioc-excluded-ips-tags');
    exclIpsTags.innerHTML = '';
    if (excludedIps.length === 0) {
      exclIpsTags.innerHTML = '<span class="tag tag-dim">No private RFC 1918 IPs detected</span>';
    } else {
      excludedIps.forEach(ip => {
        const span = document.createElement('span');
        span.className = 'tag';
        span.textContent = ip;
        exclIpsTags.appendChild(span);
      });
    }

    // Tab 5: Attachments
    const attContainer = document.getElementById('attachments-container');
    attContainer.innerHTML = '';
    const attachments = att.attachments || [];

    if (attachments.length === 0) {
      attContainer.innerHTML = '<p class="empty-state">No attachments detected in this message.</p>';
    } else {
      attachments.forEach(a => {
        const isSuspicious = a.mismatch || a.macro_present || (a.suspicious_indicators && a.suspicious_indicators.length > 0);
        const card = document.createElement('div');
        card.className = `attachment-card ${isSuspicious ? 'suspicious' : ''}`;

        let flagsHtml = '';
        if (a.mismatch) flagsHtml += '<span class="flag-badge flag-danger">MIME MISMATCH</span> ';
        if (a.macro_present) flagsHtml += '<span class="flag-badge flag-danger">MACRO DETECTED</span> ';
        if (isSuspicious && !a.mismatch && !a.macro_present) flagsHtml += '<span class="flag-badge flag-danger">SUSPICIOUS</span> ';
        if (!isSuspicious) flagsHtml += '<span class="flag-badge flag-clean">CLEAN</span> ';

        let indicatorsHtml = '';
        if (a.suspicious_indicators && a.suspicious_indicators.length > 0) {
          indicatorsHtml = `
            <div class="attachment-indicators">
              <strong>Forensic Indicators:</strong> ${escapeHtml(a.suspicious_indicators.join(' • '))}
            </div>
          `;
        }

        const hashes = a.hashes || {};
        card.innerHTML = `
          <div class="attachment-header">
            <span class="attachment-title">📎 ${escapeHtml(a.filename || 'unnamed')}</span>
            <div class="attachment-flags">${flagsHtml}</div>
          </div>
          <div class="attachment-grid">
            <div class="attachment-prop">Claimed Type: <span>${escapeHtml(a.claimed_type || 'N/A')}</span></div>
            <div class="attachment-prop">Detected Magic: <span>${escapeHtml(a.detected_type || 'N/A')}</span></div>
            <div class="attachment-prop">File Size: <span>${formatBytes(a.size_bytes || 0)}</span></div>
            <div class="attachment-prop">SHA-256: <span>${escapeHtml(hashes.sha256 ? hashes.sha256.substring(0, 24) + '...' : 'N/A')}</span></div>
          </div>
          ${indicatorsHtml}
        `;
        attContainer.appendChild(card);
      });
    }

    // Tab 6: Hop Timeline & Recommendations
    const recsList = document.getElementById('recs-list');
    recsList.innerHTML = '';
    if (recs.length === 0) {
      recsList.innerHTML = '<p class="empty-state">No specific remediation actions triggered.</p>';
    } else {
      recs.forEach(r => {
        const item = document.createElement('div');
        const prio = (r.priority || 'medium').toLowerCase();
        item.className = `rec-item priority-${prio}`;
        item.innerHTML = `
          <div class="rec-top">
            <span class="rec-action">${escapeHtml(r.action)}</span>
            <span class="rec-priority" style="color: ${prio === 'high' ? '#ef4444' : (prio === 'medium' ? '#f59e0b' : '#10b981')}">${escapeHtml(r.priority)}</span>
          </div>
          <p class="rec-rationale">${escapeHtml(r.rationale)}</p>
        `;
        recsList.appendChild(item);
      });
    }

    const timelineList = document.getElementById('timeline-list');
    timelineList.innerHTML = '';
    if (timeline.length === 0) {
      timelineList.innerHTML = '<p class="empty-state">No Received MTA headers present.</p>';
    } else {
      timeline.forEach(t => {
        const event = document.createElement('div');
        event.className = 'timeline-event';
        const delayStr = t.delay_seconds !== null && t.delay_seconds !== undefined
          ? `+${t.delay_seconds}s delay`
          : 'originating';
        event.innerHTML = `
          <div class="timeline-hop-idx">Hop ${t.hop_index + 1}</div>
          <div>From: <strong>${escapeHtml(t.from_host || t.from_ip || 'unknown')}</strong></div>
          <div>By: <strong>${escapeHtml(t.by_host || 'unknown')}</strong></div>
          <div style="text-align: right; color: #38bdf8; font-family: var(--font-mono);">${delayStr}</div>
        `;
        timelineList.appendChild(event);
      });
    }
  }

  function renderAuthBadge(elemId, status) {
    const elem = document.getElementById(elemId);
    if (!elem) return;
    const s = (status || 'none').toLowerCase();
    elem.textContent = s.toUpperCase();
    elem.className = 'auth-status-badge';
    if (s === 'pass') elem.classList.add('badge-pass');
    else if (['fail', 'softfail', 'permerror', 'temperror'].includes(s)) elem.classList.add('badge-fail');
    else elem.classList.add('badge-neutral');
  }

  // --- Inspector Controls Event Listeners ---
  closeInspectorBtn.addEventListener('click', () => {
    inspectorPanel.style.display = 'none';
    activeCaseId = null;
    const rows = queueTableBody.querySelectorAll('tr');
    rows.forEach(r => r.classList.remove('row-active'));
  });

  inspectStatusToggleBtn.addEventListener('click', async () => {
    if (!activeCaseId) return;
    const isCurrentlyNew = inspectStatusToggleBtn.textContent.includes('Reviewed');
    const nextStatus = isCurrentlyNew ? 'Reviewed' : 'New';
    await toggleStatus(activeCaseId, nextStatus);
  });

  downloadPdfBtn.addEventListener('click', () => {
    if (!activeCaseId) return;
    window.location.href = `/api/submissions/${encodeURIComponent(activeCaseId)}/pdf`;
  });

  copyCaseIdBtn.addEventListener('click', () => {
    if (activeCaseId) {
      navigator.clipboard.writeText(activeCaseId).then(() => {
        const orig = copyCaseIdBtn.textContent;
        copyCaseIdBtn.textContent = '✓ Copied!';
        setTimeout(() => copyCaseIdBtn.textContent = orig, 2000);
      });
    }
  });

  // Tab switching in inspector
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      tabButtons.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });

  // --- Filter Listeners ---
  statusFilter.addEventListener('change', fetchQueue);
  verdictFilter.addEventListener('change', fetchQueue);
  refreshBtn.addEventListener('click', fetchQueue);

  let searchTimeout = null;
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(fetchQueue, 300);
  });

  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    fetchQueue();
  });

  // Initial Load
  fetchQueue();
})();
