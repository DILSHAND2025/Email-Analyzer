/**
 * MAVERICK Forensic Live Demo Web Interface
 * Client-side Controller & Pipeline Visualizer
 */

(function () {
  'use strict';

  // --- State Management ---
  let selectedFile = null;
  let activeReportData = null;
  let activePdfBase64 = null;
  let activeCaseId = null;

  // --- DOM Elements ---
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const browseBtn = document.getElementById('browse-btn');
  const dropzonePrompt = document.getElementById('dropzone-prompt');
  const fileLoadedBanner = document.getElementById('file-loaded-banner');
  const selectedFileName = document.getElementById('selected-file-name');
  const selectedFileSize = document.getElementById('selected-file-size');
  const clearFileBtn = document.getElementById('clear-file-btn');
  const runBtn = document.getElementById('run-btn');
  const presetButtons = document.querySelectorAll('.btn-preset');

  const loadingSection = document.getElementById('loading-section');
  const loadingStageTitle = document.getElementById('loading-stage-title');
  const loadingStageDesc = document.getElementById('loading-stage-desc');
  const progressSteps = document.querySelectorAll('.step-pill');

  const resultsSection = document.getElementById('results-section');
  const resCaseId = document.getElementById('res-case-id');
  const copyCaseIdBtn = document.getElementById('copy-case-id-btn');
  const resCaseTime = document.getElementById('res-case-time');
  const resVerdictBadge = document.getElementById('res-verdict-badge');
  const resVerdictIcon = document.getElementById('res-verdict-icon');
  const resVerdictText = document.getElementById('res-verdict-text');
  const resRiskScore = document.getElementById('res-risk-score');
  const resRiskFill = document.getElementById('res-risk-fill');
  const downloadPdfBtn = document.getElementById('download-pdf-btn');
  const resPdfHash = document.getElementById('res-pdf-hash');

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

  // --- File Selection & Drag-and-Drop ---
  function updateFileSelection(file) {
    selectedFile = file;
    if (file) {
      selectedFileName.textContent = file.name;
      selectedFileSize.textContent = formatBytes(file.size);
      dropzonePrompt.style.display = 'none';
      fileLoadedBanner.style.display = 'flex';
      runBtn.disabled = false;
    } else {
      selectedFileName.textContent = '';
      selectedFileSize.textContent = '';
      fileLoadedBanner.style.display = 'none';
      dropzonePrompt.style.display = 'flex';
      runBtn.disabled = true;
      fileInput.value = '';
    }
  }

  browseBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  dropzone.addEventListener('click', () => {
    if (!selectedFile) {
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      presetButtons.forEach(b => b.classList.remove('active'));
      updateFileSelection(e.target.files[0]);
    }
  });

  clearFileBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    presetButtons.forEach(b => b.classList.remove('active'));
    updateFileSelection(null);
  });

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt.files && dt.files.length > 0) {
      presetButtons.forEach(b => b.classList.remove('active'));
      updateFileSelection(dt.files[0]);
    }
  });

  // --- Preset One-Click Demo Buttons ---
  presetButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const sampleName = btn.getAttribute('data-sample');
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      try {
        btn.disabled = true;
        const resp = await fetch(`/demo/sample/${sampleName}`);
        if (!resp.ok) {
          throw new Error(`Failed to load demo preset: ${resp.statusText}`);
        }
        const blob = await resp.blob();
        const file = new File([blob], sampleName, { type: 'message/rfc822' });
        updateFileSelection(file);
      } catch (err) {
        alert(`Error loading sample preset: ${err.message}`);
      } finally {
        btn.disabled = false;
      }
    });
  });

  // --- Copy Case ID ---
  copyCaseIdBtn.addEventListener('click', () => {
    if (activeCaseId) {
      navigator.clipboard.writeText(activeCaseId).then(() => {
        const originalText = copyCaseIdBtn.textContent;
        copyCaseIdBtn.textContent = '✓ Copied!';
        setTimeout(() => {
          copyCaseIdBtn.textContent = originalText;
        }, 2000);
      });
    }
  });

  // --- Tab Navigation ---
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      tabButtons.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }
    });
  });

  // --- Pipeline Simulation Progress Animation ---
  let progressInterval = null;
  function startProgressAnimation() {
    let currentStep = 0;
    const stages = [
      { title: 'Step 1/8: Parsing MIME & Hop Reconstruction', desc: 'Parsing headers, body parts, and Received MTA transit timestamps.' },
      { title: 'Step 2/8: Cryptographic Identity Verification', desc: 'Validating SPF, DKIM, and RFC 7489 DMARC alignment.' },
      { title: 'Step 3/8: IOC Extraction & IP Segregation', desc: 'Harvesting network IPs, URLs, domains, and filtering RFC 1918 subnets.' },
      { title: 'Step 4/8: Machine Learning Phishing Classification', desc: 'Applying TF-IDF feature weights & Neural Network inference.' },
      { title: 'Step 5/8: Inferred IP Geolocation Telemetry', desc: 'Querying network ASN, ISP, and country metrics via ip-api.' },
      { title: 'Step 6/8: Static Attachment Forensics', desc: 'Inspecting magic bytes, macro markers (oletools), and PE headers.' },
      { title: 'Step 7/8: Multi-Dimensional Evidence Fusion', desc: 'Calculating 4-pillar weighted risk score (ML 40%, Auth 20%, Att 20%, IOC 20%).' },
      { title: 'Step 8/8: Generating Cryptographic PDF Report', desc: 'Compiling ReportLab vector layout and computing SHA-256 integrity hash.' }
    ];

    loadingSection.style.display = 'block';
    progressSteps.forEach((pill, idx) => {
      pill.classList.toggle('active', idx === 0);
    });

    progressInterval = setInterval(() => {
      currentStep = (currentStep + 1) % stages.length;
      loadingStageTitle.textContent = stages[currentStep].title;
      loadingStageDesc.textContent = stages[currentStep].desc;
      progressSteps.forEach((pill, idx) => {
        pill.classList.toggle('active', idx <= currentStep);
      });
    }, 600);
  }

  function stopProgressAnimation() {
    if (progressInterval) {
      clearInterval(progressInterval);
      progressInterval = null;
    }
    loadingSection.style.display = 'none';
  }

  // --- Pipeline Execution ---
  runBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    // UI State: Loading
    runBtn.disabled = true;
    resultsSection.style.display = 'none';
    startProgressAnimation();

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await fetch('/generate-report?format=json&include_pdf_base64=true', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        let errDetail = 'Analysis failed';
        try {
          const errData = await response.json();
          errDetail = errData.detail || errDetail;
        } catch (_) {}
        throw new Error(errDetail);
      }

      const data = await response.json();
      activeReportData = data.report;
      activePdfBase64 = data.pdf_base64;
      activeCaseId = data.case_id;

      renderResults(data);
    } catch (err) {
      alert(`Pipeline Execution Error: ${err.message}`);
    } finally {
      stopProgressAnimation();
      runBtn.disabled = false;
    }
  });

  // --- Render Results Dashboard ---
  function renderResults(data) {
    const report = data.report || {};
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

    // 1. Executive Header
    resCaseId.textContent = data.case_id || meta.case_id || 'MAV-UNKNOWN';
    resCaseTime.textContent = meta.generated_at ? new Date(meta.generated_at).toUTCString() : new Date().toUTCString();

    const verdict = (threat.verdict || 'Low').toUpperCase();
    const score = typeof threat.risk_score === 'number' ? threat.risk_score : 0.0;

    resVerdictText.textContent = verdict;
    resRiskScore.textContent = score.toFixed(2);

    // Apply color styling based on verdict
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

    // PDF Hash
    resPdfHash.textContent = data.pdf_sha256 || report.pdf_sha256 || 'N/A';

    // Email Summary Strip
    resSubject.textContent = summary.subject || '(No Subject)';
    resFrom.textContent = summary.sender || '(No Sender)';
    resTo.textContent = Array.isArray(summary.recipient) ? summary.recipient.join(', ') : (summary.recipient || '(No Recipient)');
    resDate.textContent = summary.date || 'N/A';

    // Tab Header Counts
    const mlPct = Math.round((ml.phishing_probability || 0) * 100);
    document.getElementById('tab-ml-score').textContent = `${mlPct}%`;
    document.getElementById('tab-att-count').textContent = (att.total_analyzed || 0);

    // 2. Tab 1: Fusion Breakdown
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

    // Contributing Factors List
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

    // 3. Tab 2: ML Findings
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

    // 4. Tab 3: Authentication Analysis
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
      authNotesList.innerHTML = '<li>All authentication mechanisms evaluated cleanly without forensic flags.</li>';
    } else {
      notes.forEach(n => {
        const li = document.createElement('li');
        li.textContent = n;
        authNotesList.appendChild(li);
      });
    }

    // 5. Tab 4: IOCs & Geolocation
    const ips = ioc.ips || [];
    const urls = ioc.urls || [];
    const domains = ioc.domains || [];
    const excludedIps = ioc.excluded_ips || [];
    const geoResults = geo.results || [];

    document.getElementById('ioc-count-ips').textContent = ips.length;
    document.getElementById('ioc-count-urls').textContent = urls.length;
    document.getElementById('ioc-count-domains').textContent = domains.length;
    document.getElementById('ioc-count-rfc1918').textContent = excludedIps.length;

    // Geolocation Table
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

    // URLs List
    const urlsList = document.getElementById('ioc-urls-list');
    urlsList.innerHTML = '';
    if (urls.length === 0) {
      urlsList.innerHTML = '<li class="empty-li">No URLs extracted from message body.</li>';
    } else {
      urls.forEach(u => {
        const li = document.createElement('li');
        li.textContent = u;
        urlsList.appendChild(li);
      });
    }

    // Domains List
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

    // Excluded IPs (RFC 1918)
    const exclIpsTags = document.getElementById('ioc-excluded-ips-tags');
    exclIpsTags.innerHTML = '';
    if (excludedIps.length === 0) {
      exclIpsTags.innerHTML = '<span class="tag tag-dim">No private or reserved RFC 1918 IPs detected</span>';
    } else {
      excludedIps.forEach(ip => {
        const span = document.createElement('span');
        span.className = 'tag';
        span.textContent = ip;
        exclIpsTags.appendChild(span);
      });
    }

    // 6. Tab 5: Attachments Forensics
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
        if (a.mismatch) {
          flagsHtml += '<span class="flag-badge flag-danger">MIME MISMATCH</span> ';
        }
        if (a.macro_present) {
          flagsHtml += '<span class="flag-badge flag-danger">MACRO DETECTED</span> ';
        }
        if (isSuspicious && !a.mismatch && !a.macro_present) {
          flagsHtml += '<span class="flag-badge flag-danger">SUSPICIOUS</span> ';
        }
        if (!isSuspicious) {
          flagsHtml += '<span class="flag-badge flag-clean">CLEAN</span> ';
        }

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

    // 7. Tab 6: Hop Timeline & Recommendations
    const recsList = document.getElementById('recs-list');
    recsList.innerHTML = '';
    if (recs.length === 0) {
      recsList.innerHTML = '<p class="empty-state">No specific remediation actions triggered for this risk level.</p>';
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
      timelineList.innerHTML = '<p class="empty-state">No Received MTA headers present in email metadata.</p>';
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

    // Show Results Section and scroll smoothly
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }

  function renderAuthBadge(elemId, status) {
    const elem = document.getElementById(elemId);
    if (!elem) return;
    const s = (status || 'none').toLowerCase();
    elem.textContent = s.toUpperCase();
    elem.className = 'auth-status-badge';
    if (s === 'pass') {
      elem.classList.add('badge-pass');
    } else if (['fail', 'softfail', 'permerror', 'temperror'].includes(s)) {
      elem.classList.add('badge-fail');
    } else {
      elem.classList.add('badge-neutral');
    }
  }

  // --- PDF Download Handling ---
  downloadPdfBtn.addEventListener('click', () => {
    if (!activeCaseId) return;

    if (activePdfBase64) {
      // Direct client-side download from embedded base64
      try {
        const byteCharacters = atob(activePdfBase64);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
          byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `MAVERICK-Report-${activeCaseId}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        return;
      } catch (err) {
        console.warn('Direct base64 PDF download failed, falling back to server route:', err);
      }
    }

    // Fallback: server download route
    window.location.href = `/reports/${encodeURIComponent(activeCaseId)}/pdf`;
  });

})();
