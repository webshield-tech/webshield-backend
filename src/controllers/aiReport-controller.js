/* eslint-disable no-unused-vars */
import { aiReport, analyzeVulnerabilities } from '../utils/aiReport.js';
import { Scan } from '../models/scans-mongoose.js';

const MAX_PROMPT_CHARS = 12000;
const SUPPORTED_REPORT_LANGUAGES = new Set(['english', 'urdu', 'hindi', 'arabic']);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeReportLanguage(value) {
  const lang = String(value || 'english').trim().toLowerCase();
  return SUPPORTED_REPORT_LANGUAGES.has(lang) ? lang : 'english';
}

function ensureNmapStructuredFromRaw(scan) {
  if (!scan || scan.scanType !== 'nmap' || !scan.results) return;

  const already = scan.results.nmap || {};
  const hasUseful =
    (Array.isArray(already.openPorts) && already.openPorts.length > 0) ||
    (Array.isArray(already.serviceVersions) && already.serviceVersions.length > 0) ||
    (already.osDetection && String(already.osDetection).trim());

  const raw = String(already.rawOutput || scan.results.rawOutput || '');
  if (!raw.trim()) return;

  if (hasUseful) {
    const cves = Array.from(
      new Set((raw.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((c) => c.toUpperCase()))
    );
    if (cves.length && (!already.cveList || already.cveList.length === 0)) {
      scan.results.nmap = {
        ...already,
        cveList: cves,
        rawOutput: already.rawOutput || raw,
      };
    }
    return;
  }

  const lines = raw
    .split('\n')
    .map((l) => l.replace(/\r$/, '').trim())
    .filter(Boolean);
  const openPorts = [];
  const serviceVersions = [];
  const cveSet = new Set();

  for (const line of lines) {
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(.*)$/i);
    if (portMatch) {
      if (/open/i.test(portMatch[3])) {
        openPorts.push(`${portMatch[1]}/${portMatch[2]} ${portMatch[4] || ''}`.trim());
      }
      if (portMatch[4] && /[A-Za-z0-9]/.test(portMatch[4])) {
        serviceVersions.push(`${portMatch[1]}/${portMatch[2]} ${portMatch[4]}`.trim());
      }
      const cves = (portMatch[4] || '').match(/CVE-\d{4}-\d{4,7}/gi);
      if (cves) cves.forEach((c) => cveSet.add(c.toUpperCase()));
      continue;
    }
    if ((line.startsWith('|') && line.includes(':')) || /Service Info:/i.test(line)) {
      serviceVersions.push(line);
      const cves = line.match(/CVE-\d{4}-\d{4,7}/gi);
      if (cves) cves.forEach((c) => cveSet.add(c.toUpperCase()));
    }
  }

  scan.results.nmap = {
    openPorts,
    serviceVersions,
    cveList: Array.from(cveSet),
    rawOutput: raw,
  };
}

// ---------------------------------------------------------------------------
// Single-scan legacy text report (individual tool reports)
// ---------------------------------------------------------------------------

function buildSummaryText(scan) {
  const toolResults = scan.results || {};
  let text = `ACTUAL SCAN DATA FOR ${String(scan.scanType).toUpperCase()}:\n`;
  text += `Target: ${scan.targetUrl}\n`;
  if (scan.platform) text += `Platform/OS: ${scan.platform}\n`;
  if (toolResults.serverInfo) text += `Server Info: ${toolResults.serverInfo}\n`;
  if (toolResults.techStack) text += `Technology Stack: ${toolResults.techStack}\n`;

  if (scan.scanType === 'nmap') {
    const res = toolResults.nmap || toolResults;
    text += `Open Ports: ${res.openPorts?.join(', ') || 'None detected'}\n`;
    text += `Services: ${res.serviceVersions?.join('; ') || 'No version details'}\n`;
    text += `CVEs: ${res.cveList?.slice(0, 30).join(', ') || 'None extracted'}${res.cveList?.length > 30 ? ' (and more...)' : ''}\n`;
  } else if (scan.scanType === 'nikto') {
    const res = toolResults.nikto || toolResults;
    text += `Findings: ${res.findings?.slice(0, 10).join('\n') || 'No major findings'}\n`;
  } else if (scan.scanType === 'sqlmap') {
    const res = toolResults.sqlmap || toolResults;
    text += `Vulnerable: ${res.vulnerable ? 'Yes' : 'No'}\n`;
    text += `Injection Types: ${res.injectionTypes?.join(', ') || 'N/A'}\n`;
    text += `Vulnerability Evidence: ${res.vulnerabilities?.slice(0, 10).join('\n') || 'None'}\n`;
    text += `DBMS: ${res.details?.dbms || 'Unknown'}\n`;
  } else if (scan.scanType === 'ssl') {
    const res = toolResults.ssl || toolResults;
    text += `Critical Issues: ${res.criticalIssues?.slice(0, 10).join('\n') || 'None'}\n`;
    text += `Weak Ciphers: ${res.weakCiphers?.slice(0, 10).join('\n') || 'None'}\n`;
    text += `Certificate Issues: ${res.certificateIssues?.slice(0, 10).join('\n') || 'None'}\n`;
    text += `TLS 1.2 Supported: ${res.supportsTLS12 ? 'Yes' : 'No'}\n`;
    text += `TLS 1.3 Supported: ${res.supportsTLS13 ? 'Yes' : 'No'}\n`;
  } else if (scan.scanType === 'gobuster') {
    const res = toolResults.gobuster || toolResults;
    text += `Directories Found: ${res.directories?.slice(0, 15).join(', ') || 'None'}\n`;
  } else if (scan.scanType === 'ratelimit') {
    const res = toolResults.ratelimit || toolResults;
    text += `Rate Limiting Detected: ${res.vulnerable ? 'Yes' : 'No'}\n`;
    text += `Findings: ${res.findings?.join('\n') || 'N/A'}\n`;
  } else if (scan.scanType === 'ffuf') {
    const res = toolResults.ffuf || toolResults;
    text += `Fuzzing Findings: ${res.findings?.slice(0, 15).join(', ') || 'None'}\n`;
  } else if (scan.scanType === 'wapiti') {
    const res = toolResults.wapiti || toolResults;
    text += `Wapiti Summary: ${res.summary || 'N/A'}\n`;
  } else if (scan.scanType === 'nuclei') {
    const res = toolResults.nuclei || toolResults;
    text += `Vulnerability Templates Matched: ${res.findings?.slice(0, 10).join('\n') || 'None'}\n`;
  } else if (scan.scanType === 'dns') {
    const res = toolResults.dns || toolResults;
    text += `DNS Records Found: ${Object.keys(res.records || {}).join(', ') || 'None'}\n`;
    if (res.records?.A) text += `A Records: ${res.records.A.join(', ')}\n`;
    if (res.records?.MX) text += `MX Records: ${res.records.MX.map((m) => m.exchange).join(', ')}\n`;
  } else if (scan.scanType === 'whois') {
    const res = toolResults.whois || toolResults;
    text += `Whois Data: ${res.data?.slice(0, 500) || 'N/A'}\n`;
  }

  return text;
}

function buildReportContent(scan, aiText, language = 'english') {
  const content = `
VULN SPECTRA SECURITY SCAN REPORT

Scan Overview
----------------------
Scan ID       : ${scan._id}
Target        : ${scan.targetUrl}
Type          : ${String(scan.scanType).toUpperCase()}
Date          : ${new Date(scan.createdAt).toLocaleString()}
Language      : ${language}

Security Analysis & Recommendations
----------------------
${aiText}

END OF REPORT

Generated by Vuln Spectra Security Scanner
Report ID: ${scan._id}
© ${new Date().getFullYear()} Vuln Spectra
`.trim();

  return content.replace(/WebShield/gi, 'Vuln Spectra');
}

async function ensureReportForLanguage(scan, language) {
  const requestedLanguage = normalizeReportLanguage(language);
  const existingLanguage = normalizeReportLanguage(scan.reportLanguage);

  if (
    scan.reportContent &&
    !scan.reportContent.includes('WebShield') &&
    existingLanguage === requestedLanguage
  ) {
    return { reused: true, language: requestedLanguage };
  }

  try {
    ensureNmapStructuredFromRaw(scan);
    scan.markModified('results');
  } catch (e) {
    console.warn('Fallback parse failed', e);
  }

  let summaryText = buildSummaryText(scan);
  if (summaryText.length > MAX_PROMPT_CHARS) {
    summaryText = summaryText.slice(0, MAX_PROMPT_CHARS);
  }

  const aiText = await aiReport(summaryText, requestedLanguage);
  scan.reportContent = buildReportContent(scan, aiText, requestedLanguage);
  scan.reportGeneratedAt = new Date();
  scan.reportLanguage = requestedLanguage;
  await scan.save();

  return { reused: false, language: requestedLanguage };
}

// ---------------------------------------------------------------------------
// NEW: Structured multi-tool scan input builder
// ---------------------------------------------------------------------------

/**
 * Maps database scan documents from a batch into the structured JSON input
 * format consumed by analyzeVulnerabilities().
 */
function buildStructuredScanInput(scans) {
  const target = scans[0]?.targetUrl || 'unknown';
  const rawScanMode = scans[0]?.results?.scanMode || 'quick';
  const scanType = rawScanMode === 'full' ? 'deep' : 'quick';

  // Gather platform / tech stack info from whichever scan captured it
  const platform =
    scans.find((s) => s.platform && !/unknown/i.test(s.platform))?.platform || null;
  const serverInfo = scans.find((s) => s.results?.serverInfo)?.results?.serverInfo || '';
  const techStack = scans.find((s) => s.results?.techStack)?.results?.techStack || '';
  const technologies = [serverInfo, techStack].filter(Boolean);

  const scanResults = {};

  for (const scan of scans) {
    const r = scan.results || {};

    switch (scan.scanType) {
      case 'nmap': {
        const d = r.nmap || r;
        scanResults.nmap = {
          open_ports: d.openPorts || [],
          filtered_ports: d.filteredPorts || [],
          services: d.serviceVersions || [],
          cves: (d.cveList || []).slice(0, 30),
          vulnerabilities: (d.vulnerabilities || []).slice(0, 20),
          os_detection: d.osDetection || null,
          status: scan.status,
        };
        break;
      }

      case 'nikto': {
        const d = r.nikto || r;
        scanResults.nikto = {
          total_findings: d.totalFindings || 0,
          findings: (d.findings || []).slice(0, 20),
          critical: d.criticalFindings || [],
          high: d.highFindings || [],
          medium: d.mediumFindings || [],
          low: d.lowFindings || [],
          server_info: d.serverInfo || null,
          status: scan.status,
        };
        break;
      }

      case 'sqlmap': {
        const d = r.sqlmap || r;
        scanResults.sqlmap = {
          vulnerable: d.vulnerable || false,
          injection_types: d.injectionTypes || [],
          vulnerabilities: (d.vulnerabilities || []).slice(0, 10),
          injection_points: (d.injectionPoints || []).slice(0, 10),
          dbms: d.details?.dbms || null,
          databases: d.databases || [],
          payload: d.details?.payload || null,
          summary: d.summary || null,
          status: scan.status,
        };
        break;
      }

      case 'ssl': {
        const d = r.ssl || r;
        scanResults.sslscan = {
          has_vulnerabilities: d.hasVulnerabilities || false,
          total_issues: d.totalIssues || 0,
          critical_issues: (d.criticalIssues || []).slice(0, 10),
          weak_ciphers: (d.weakCiphers || []).slice(0, 10),
          deprecated_protocols: d.deprecatedProtocols || [],
          certificate_issues: d.certificateIssues || [],
          heartbleed: d.heartbleedVulnerable || [],
          supports_tls12: d.supportsTLS12 || false,
          supports_tls13: d.supportsTLS13 || false,
          certificate: d.certificateDetails || {},
          status: scan.status,
        };
        break;
      }

      case 'gobuster': {
        const d = r.gobuster || r;
        scanResults.gobuster = {
          directories: (d.directories || []).slice(0, 30),
          count: d.count || 0,
          status: scan.status,
        };
        break;
      }

      case 'nuclei': {
        const d = r.nuclei || r;
        scanResults.nuclei = {
          findings: (d.findings || []).slice(0, 20),
          count: d.count || 0,
          status: scan.status,
        };
        break;
      }

      case 'wapiti': {
        const d = r.wapiti || r;
        scanResults.wapiti = {
          summary: d.summary || 'No output available',
          vulnerabilities_found: d.success || false,
          status: scan.status,
        };
        break;
      }

      case 'ratelimit': {
        const d = r.ratelimit || r;
        scanResults.ratelimit = {
          vulnerable: d.vulnerable || false,
          rate_limit_active: d.rateLimitActive || false,
          api_active: d.apiActive || false,
          findings: d.findings || [],
          status: scan.status,
        };
        break;
      }

      case 'ffuf': {
        const d = r.ffuf || r;
        scanResults.ffuf = {
          findings: (d.findings || []).slice(0, 20),
          count: d.count || 0,
          status: scan.status,
        };
        break;
      }

      case 'dns': {
        const d = r.dns || r;
        scanResults.dnsrecon = {
          records: d.records || {},
          status: scan.status,
        };
        break;
      }

      case 'whois': {
        const d = r.whois || r;
        scanResults.whois = {
          data: String(d.data || d.rawOutput || '').slice(0, 800),
          status: scan.status,
        };
        break;
      }

      default:
        break;
    }
  }

  return {
    target_url: target,
    scan_type: scanType,
    detected_platform: platform,
    detected_technologies: technologies,
    scan_results: scanResults,
  };
}

// ---------------------------------------------------------------------------
// Batch report text content builder (for PDF / download compat)
// ---------------------------------------------------------------------------

function buildBatchReportTextContent({ batchId, targetUrl, scans, analysisJson, language = 'english' }) {
  const toolStatus = scans
    .map((s) => `- ${String(s.scanType).toUpperCase()}: ${String(s.status).toUpperCase()}`)
    .join('\n');

  const summary = analysisJson?.summary || {};
  const findings = analysisJson?.findings || [];
  const infoFindings = analysisJson?.informational_findings || [];
  const actions = analysisJson?.prioritized_actions || [];
  const surface = analysisJson?.attack_surface || {};

  const findingsText = findings.length
    ? findings
        .map(
          (f, i) =>
            `[${i + 1}] ${f.title} (${f.severity}) — Confidence: ${Math.round((f.confidence || 0) * 100)}%\n` +
            `    Description : ${f.description}\n` +
            `    Impact      : ${f.impact}\n` +
            `    Evidence    : ${f.evidence}\n` +
            `    Affected    : ${f.affected_area}\n` +
            `    Fix         : ${f.recommendation}\n` +
            `    References  : ${(f.references || []).join(', ') || 'N/A'}\n`
        )
        .join('\n')
    : 'No critical vulnerabilities detected.';

  const infoText = infoFindings.length
    ? infoFindings.map((f) => `- ${f.title}: ${f.description}`).join('\n')
    : 'No informational findings.';

  const actionsText = actions.length
    ? actions.map((a, i) => `${i + 1}. ${a}`).join('\n')
    : 'No specific actions required.';

  return `
VULN SPECTRA SECURITY SCAN REPORT (AUTO-SCAN — AI CORRELATED)

Scan Overview
----------------------
Batch ID      : ${batchId}
Target        : ${targetUrl}
Type          : ALL TOOLS (NMAP, NIKTO, SSLSCAN, SQLMAP, NUCLEI, GOBUSTER, WAPITI, DNS, WHOIS)
Date          : ${new Date().toLocaleString()}
Language      : ${language}
Scan Quality  : ${summary.scan_quality || 'Quick Scan'}

Tool Execution Status
----------------------
${toolStatus}

Executive Summary
----------------------
Risk Score    : ${summary.risk_score ?? 'N/A'} / 100
Status        : ${summary.overall_status || 'N/A'}
Confidence    : ${summary.confidence_score != null ? Math.round(summary.confidence_score * 100) + '%' : 'N/A'}

${summary.key_message || ''}

Attack Surface
----------------------
Open Ports         : ${(surface.open_ports || []).join(', ') || 'None detected'}
Directories Found  : ${(surface.directories_found || []).join(', ') || 'None detected'}
Technologies       : ${(surface.technologies_detected || []).join(', ') || 'Unknown'}

Vulnerability Findings (${findings.length})
----------------------
${findingsText}

Informational Observations
----------------------
${infoText}

Prioritized Remediation Steps
----------------------
${actionsText}

Final Recommendation
----------------------
${analysisJson?.final_recommendation || 'See findings above for detailed guidance.'}

END OF REPORT

Generated by Vuln Spectra Security Scanner (AI Correlated Multi-Tool Analysis)
Batch Report ID: ${batchId}
© ${new Date().getFullYear()} Vuln Spectra
  `.trim();
}

// ---------------------------------------------------------------------------
// Batch scan DB helpers
// ---------------------------------------------------------------------------

async function getBatchScansOrThrow(batchId, userId) {
  const scans = await Scan.find({
    userId,
    'results.batchId': batchId,
  }).sort({ createdAt: 1 });

  if (!scans.length) {
    const err = new Error('Batch not found');
    err.status = 404;
    throw err;
  }
  return scans;
}

// ---------------------------------------------------------------------------
// Individual scan report endpoints (unchanged API)
// ---------------------------------------------------------------------------

export const generateAIReportForScan = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const requestedLanguage = normalizeReportLanguage(req.body?.language);
    const scan = await Scan.findOne({ _id: scanId, userId });

    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found' });
    if (scan.status !== 'completed')
      return res.status(400).json({ success: false, error: 'Scan not completed' });

    const ensured = await ensureReportForLanguage(scan, requestedLanguage);
    if (ensured.reused) {
      return res.json({
        success: true,
        message: 'Report already exists',
        reportGenerated: true,
        generatedAt: scan.reportGeneratedAt,
        language: ensured.language,
        scanId: scan._id,
      });
    }

    res.json({
      success: true,
      message: 'Report generated successfully',
      language: ensured.language,
      scanId: scan._id,
    });
  } catch (err) {
    console.error('Report gen error:', err);
    res.status(500).json({ success: false, error: 'Failed to generate report' });
  }
};

export const downloadReport = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const requestedLanguage = normalizeReportLanguage(req.query?.language);
    const scan = await Scan.findOne({ _id: scanId, userId });

    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found' });
    if (scan.status !== 'completed')
      return res.status(400).json({ success: false, error: 'Scan not completed' });

    await ensureReportForLanguage(scan, requestedLanguage);

    res.json({
      success: true,
      report: {
        scanId: scan._id,
        targetUrl: scan.targetUrl,
        scanType: scan.scanType,
        language: normalizeReportLanguage(scan.reportLanguage),
        content: scan.reportContent,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Download failed' });
  }
};

export const viewReport = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const requestedLanguage = normalizeReportLanguage(req.query?.language);
    const scan = await Scan.findOne({ _id: scanId, userId });

    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found' });
    if (scan.status !== 'completed')
      return res.status(400).json({ success: false, error: 'Scan not completed' });

    await ensureReportForLanguage(scan, requestedLanguage);

    res.json({
      success: true,
      report: {
        language: normalizeReportLanguage(scan.reportLanguage),
        content: scan.reportContent,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'View failed' });
  }
};

// ---------------------------------------------------------------------------
// Batch / Auto-scan report endpoints — UPGRADED with structured AI analysis
// ---------------------------------------------------------------------------

export const generateBatchAIReport = async (req, res) => {
  try {
    const userId = req.user?.userId || req.userId;
    const batchId = req.params.batchId;
    const requestedLanguage = normalizeReportLanguage(req.body?.language);
    const scans = await getBatchScansOrThrow(batchId, userId);

    const allCompleted = scans.every((s) => s.status === 'completed');
    if (!allCompleted) {
      return res
        .status(400)
        .json({ success: false, error: 'Batch scans are not all completed yet' });
    }

    // ── 1. Build structured scan input for the AI ──────────────────────────
    const structuredInput = buildStructuredScanInput(scans);

    // ── 2. Run AI correlated analysis ─────────────────────────────────────
    const analysisJson = await analyzeVulnerabilities(structuredInput, requestedLanguage);

    // ── 3. Build human-readable text report for PDF / download ────────────
    const reportContent = buildBatchReportTextContent({
      batchId,
      targetUrl: scans[0].targetUrl,
      scans,
      analysisJson,
      language: requestedLanguage,
    });

    // ── 4. Persist both the structured JSON and text report on all scans ──
    await Scan.updateMany(
      { _id: { $in: scans.map((s) => s._id) } },
      {
        $set: {
          reportContent,
          batchAnalysisJson: analysisJson,
          reportGeneratedAt: new Date(),
          reportLanguage: requestedLanguage,
        },
      }
    );

    return res.json({
      success: true,
      message: 'Batch report generated successfully',
      batchId,
      language: requestedLanguage,
      analysis: analysisJson,
    });
  } catch (err) {
    console.error('[generateBatchAIReport]', err);
    return res
      .status(err.status || 500)
      .json({ success: false, error: err.message || 'Failed to generate batch report' });
  }
};

export const viewBatchReport = async (req, res) => {
  try {
    const userId = req.user?.userId || req.userId;
    const batchId = req.params.batchId;
    const scans = await getBatchScansOrThrow(batchId, userId);
    const reportOwner = scans.find((s) => s.reportContent) || scans[0];

    if (!reportOwner.reportContent) {
      return res
        .status(404)
        .json({ success: false, error: 'Batch report not generated yet' });
    }

    return res.json({
      success: true,
      report: {
        batchId,
        content: reportOwner.reportContent,
        language: normalizeReportLanguage(reportOwner.reportLanguage),
        // Structured JSON analysis — used by dashboard UI
        analysis: reportOwner.batchAnalysisJson || null,
      },
    });
  } catch (err) {
    return res
      .status(err.status || 500)
      .json({ success: false, error: err.message || 'Failed to view batch report' });
  }
};

export const downloadBatchReport = async (req, res) => {
  try {
    const userId = req.user?.userId || req.userId;
    const batchId = req.params.batchId;
    const scans = await getBatchScansOrThrow(batchId, userId);
    const reportOwner = scans.find((s) => s.reportContent) || scans[0];

    if (!reportOwner.reportContent) {
      return res
        .status(404)
        .json({ success: false, error: 'Batch report not generated yet' });
    }

    return res.json({
      success: true,
      report: {
        batchId,
        targetUrl: scans[0].targetUrl,
        scanType: 'all-tools',
        language: normalizeReportLanguage(reportOwner.reportLanguage),
        content: reportOwner.reportContent,
        // Structured JSON analysis — used by PDF renderer
        analysis: reportOwner.batchAnalysisJson || null,
      },
    });
  } catch (err) {
    return res
      .status(err.status || 500)
      .json({ success: false, error: err.message || 'Failed to download batch report' });
  }
};
