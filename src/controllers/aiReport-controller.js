/* eslint-disable no-unused-vars */
import { aiReport } from "../utils/aiReport.js";
import { Scan } from "../models/scans-mongoose.js";

const MAX_PROMPT_CHARS = 20000;
const SUPPORTED_REPORT_LANGUAGES = new Set([
  "english",
  "urdu",
  "hindi",
  "arabic",
]);

function normalizeReportLanguage(value) {
  const lang = String(value || "english").trim().toLowerCase();
  return SUPPORTED_REPORT_LANGUAGES.has(lang) ? lang : "english";
}

function ensureNmapStructuredFromRaw(scan) {
  if (!scan || scan.scanType !== "nmap" || !scan.results) return;

  const already = scan.results.nmap || {};
  const hasUseful =
    (Array.isArray(already.openPorts) && already.openPorts.length > 0) ||
    (Array.isArray(already.serviceVersions) && already.serviceVersions.length > 0) ||
    (already.osDetection && String(already.osDetection).trim());

  const raw = String(already.rawOutput || scan.results.rawOutput || "");
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

  const lines = raw.split("\n").map((l) => l.replace(/\r$/, "").trim()).filter(Boolean);
  const openPorts = [];
  const serviceVersions = [];
  const cveSet = new Set();

  for (const line of lines) {
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(.*)$/i);
    if (portMatch) {
      if (/open/i.test(portMatch[3])) {
        openPorts.push(`${portMatch[1]}/${portMatch[2]} ${portMatch[4] || ""}`.trim());
      }
      if (portMatch[4] && /[A-Za-z0-9]/.test(portMatch[4])) {
        serviceVersions.push(`${portMatch[1]}/${portMatch[2]} ${portMatch[4]}`.trim());
      }
      const cves = (portMatch[4] || "").match(/CVE-\d{4}-\d{4,7}/gi);
      if (cves) cves.forEach((c) => cveSet.add(c.toUpperCase()));
      continue;
    }
    if ((line.startsWith("|") && line.includes(":")) || /Service Info:/i.test(line)) {
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

function buildSummaryText(scan) {
  const toolResults = scan.results || {};
  let text = `ACTUAL SCAN DATA FOR ${String(scan.scanType).toUpperCase()}:\n`;
  text += `Target: ${scan.targetUrl}\n`;
  if (scan.platform) text += `Platform Detected: ${scan.platform}\n`;
  
  if (scan.scanType === "nmap") {
    const res = toolResults.nmap || toolResults;
    text += `Open Ports: ${res.openPorts?.join(", ") || "None detected"}\n`;
    text += `Services: ${res.serviceVersions?.join("; ") || "No version details"}\n`;
    text += `CVEs: ${res.cveList?.join(", ") || "None extracted"}\n`;
  } else if (scan.scanType === "nikto") {
    const res = toolResults.nikto || toolResults;
    text += `Findings: ${res.findings?.slice(0, 10).join("\n") || "No major findings"}\n`;
  } else if (scan.scanType === "sqlmap") {
    const res = toolResults.sqlmap || toolResults;
    text += `Vulnerable: ${res.vulnerable ? "Yes" : "No"}\n`;
    text += `Injection Types: ${res.injectionTypes?.join(", ") || "N/A"}\n`;
    text += `Vulnerability Evidence: ${res.vulnerabilities?.slice(0, 10).join("\n") || "None"}\n`;
    text += `DBMS: ${res.details?.dbms || "Unknown"}\n`;
  } else if (scan.scanType === "ssl") {
    const res = toolResults.ssl || toolResults;
    text += `Critical Issues: ${res.criticalIssues?.slice(0, 10).join("\n") || "None"}\n`;
    text += `Weak Ciphers: ${res.weakCiphers?.slice(0, 10).join("\n") || "None"}\n`;
    text += `Certificate Issues: ${res.certificateIssues?.slice(0, 10).join("\n") || "None"}\n`;
    text += `TLS 1.2 Supported: ${res.supportsTLS12 ? "Yes" : "No"}\n`;
    text += `TLS 1.3 Supported: ${res.supportsTLS13 ? "Yes" : "No"}\n`;
  } else if (scan.scanType === "gobuster") {
    const res = toolResults.gobuster || toolResults;
    text += `Directories Found: ${res.directories?.slice(0, 15).join(", ") || "None"}\n`;
  } else if (scan.scanType === "ratelimit") {
    const res = toolResults.ratelimit || toolResults;
    text += `Rate Limiting Detected: ${res.vulnerable ? "Yes" : "No"}\n`;
    text += `Findings: ${res.findings?.join("\n") || "N/A"}\n`;
  } else if (scan.scanType === "ffuf") {
    const res = toolResults.ffuf || toolResults;
    text += `Fuzzing Findings: ${res.findings?.slice(0, 15).join(", ") || "None"}\n`;
  } else if (scan.scanType === "wapiti") {
    const res = toolResults.wapiti || toolResults;
    text += `Wapiti Summary: ${res.summary || "N/A"}\n`;
  } else if (scan.scanType === "nuclei") {
    const res = toolResults.nuclei || toolResults;
    text += `Vulnerability Templates Matched: ${res.findings?.slice(0, 10).join("\n") || "None"}\n`;
  } else if (scan.scanType === "dns") {
    const res = toolResults.dns || toolResults;
    text += `DNS Records Found: ${Object.keys(res.records || {}).join(", ") || "None"}\n`;
    if (res.records?.A) text += `A Records: ${res.records.A.join(", ")}\n`;
    if (res.records?.MX) text += `MX Records: ${res.records.MX.map(m => m.exchange).join(", ")}\n`;
  } else if (scan.scanType === "whois") {
    const res = toolResults.whois || toolResults;
    text += `Whois Data: ${res.data?.slice(0, 500) || "N/A"}\n`;
  }

  
  return text;
}

function buildBatchSummaryText(scans) {
  const completed = scans.filter((s) => s.status === "completed");
  const failed = scans.filter((s) => s.status === "failed");
  const target = scans[0]?.targetUrl || "unknown";
  let text = `AUTO-SCAN BATCH DATA:\nTarget: ${target}\nTotal Tools: ${scans.length}\nCompleted: ${completed.length}\nFailed: ${failed.length}\n\n`;

  for (const scan of scans) {
    text += `${buildSummaryText(scan)}\n\n`;
  }
  return text;
}

function buildReportContent(scan, aiText, language = "english") {
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

  return content.replace(/WebShield/gi, "Vuln Spectra");
}

function buildBatchReportContent({ batchId, targetUrl, scans, aiText, language = "english" }) {
  const toolStatus = scans
    .map((s) => `- ${String(s.scanType).toUpperCase()}: ${String(s.status).toUpperCase()}`)
    .join("\n");

  return `
VULN SPECTRA SECURITY SCAN REPORT (AUTO-SCAN)

Scan Overview
----------------------
Batch ID      : ${batchId}
Target        : ${targetUrl}
Type          : ALL TOOLS (NMAP, NIKTO, SSLSCAN, SQLMAP)
Date          : ${new Date().toLocaleString()}
Language      : ${language}

Tool Execution Status
----------------------
${toolStatus}

Security Analysis & Recommendations
----------------------
${aiText}

END OF REPORT

Generated by Vuln Spectra Security Scanner
Batch Report ID: ${batchId}
© ${new Date().getFullYear()} Vuln Spectra
  `.trim();
}

async function ensureReportForLanguage(scan, language) {
  const requestedLanguage = normalizeReportLanguage(language);
  const existingLanguage = normalizeReportLanguage(scan.reportLanguage);

  if (
    scan.reportContent &&
    !scan.reportContent.includes("WebShield") &&
    existingLanguage === requestedLanguage
  ) {
    return { reused: true, language: requestedLanguage };
  }

  try {
    ensureNmapStructuredFromRaw(scan);
    scan.markModified("results");
  } catch (e) {
    console.warn("Fallback parse failed", e);
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

export const generateAIReportForScan = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const requestedLanguage = normalizeReportLanguage(req.body?.language);
    const scan = await Scan.findOne({ _id: scanId, userId });

    if (!scan) return res.status(404).json({ success: false, error: "Scan not found" });
    if (scan.status !== "completed") return res.status(400).json({ success: false, error: "Scan not completed" });

    const ensured = await ensureReportForLanguage(scan, requestedLanguage);
    if (ensured.reused) {
      return res.json({
        success: true,
        message: "Report already exists",
        reportGenerated: true,
        generatedAt: scan.reportGeneratedAt,
        language: ensured.language,
        scanId: scan._id,
      });
    }

    res.json({
      success: true,
      message: "Report generated successfully",
      language: ensured.language,
      scanId: scan._id,
    });
  } catch (err) {
    console.error("Report gen error:", err);
    res.status(500).json({ success: false, error: "Failed to generate report" });
  }
};

export const downloadReport = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const requestedLanguage = normalizeReportLanguage(req.query?.language);
    const scan = await Scan.findOne({ _id: scanId, userId });
    
    if (!scan) return res.status(404).json({ success: false, error: "Scan not found" });
    if (scan.status !== "completed") return res.status(400).json({ success: false, error: "Scan not completed" });

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
    res.status(500).json({ success: false, error: "Download failed" });
  }
};

export const viewReport = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const requestedLanguage = normalizeReportLanguage(req.query?.language);
    const scan = await Scan.findOne({ _id: scanId, userId });
    
    if (!scan) return res.status(404).json({ success: false, error: "Scan not found" });
    if (scan.status !== "completed") return res.status(400).json({ success: false, error: "Scan not completed" });

    await ensureReportForLanguage(scan, requestedLanguage);

    res.json({
      success: true,
      report: {
        language: normalizeReportLanguage(scan.reportLanguage),
        content: scan.reportContent,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: "View failed" });
  }
};

async function getBatchScansOrThrow(batchId, userId) {
  const scans = await Scan.find({
    userId,
    "results.batchId": batchId,
  }).sort({ createdAt: 1 });

  if (!scans.length) {
    const err = new Error("Batch not found");
    err.status = 404;
    throw err;
  }
  return scans;
}

export const generateBatchAIReport = async (req, res) => {
  try {
    const userId = req.user?.userId || req.userId;
    const batchId = req.params.batchId;
    const requestedLanguage = normalizeReportLanguage(req.body?.language);
    const scans = await getBatchScansOrThrow(batchId, userId);

    const allCompleted = scans.every((s) => s.status === "completed");
    if (!allCompleted) {
      return res.status(400).json({ success: false, error: "Batch scans are not completed yet" });
    }

    const summaryText = buildBatchSummaryText(scans).slice(0, MAX_PROMPT_CHARS);
    const aiText = await aiReport(summaryText, requestedLanguage);
    const reportContent = buildBatchReportContent({
      batchId,
      targetUrl: scans[0].targetUrl,
      scans,
      aiText,
      language: requestedLanguage,
    });

    await Scan.updateMany(
      { _id: { $in: scans.map((s) => s._id) } },
      {
        $set: {
          reportContent,
          reportGeneratedAt: new Date(),
          reportLanguage: requestedLanguage,
        },
      }
    );

    return res.json({ success: true, message: "Batch report generated", batchId, language: requestedLanguage });
  } catch (err) {
    return res.status(err.status || 500).json({ success: false, error: err.message || "Failed to generate batch report" });
  }
};

export const viewBatchReport = async (req, res) => {
  try {
    const userId = req.user?.userId || req.userId;
    const batchId = req.params.batchId;
    const scans = await getBatchScansOrThrow(batchId, userId);
    const reportOwner = scans.find((s) => s.reportContent) || scans[0];

    if (!reportOwner.reportContent) {
      return res.status(404).json({ success: false, error: "Batch report not generated yet" });
    }

    return res.json({
      success: true,
      report: {
        batchId,
        content: reportOwner.reportContent,
        language: normalizeReportLanguage(reportOwner.reportLanguage),
      },
    });
  } catch (err) {
    return res.status(err.status || 500).json({ success: false, error: err.message || "Failed to view batch report" });
  }
};

export const downloadBatchReport = async (req, res) => {
  try {
    const userId = req.user?.userId || req.userId;
    const batchId = req.params.batchId;
    const scans = await getBatchScansOrThrow(batchId, userId);
    const reportOwner = scans.find((s) => s.reportContent) || scans[0];

    if (!reportOwner.reportContent) {
      return res.status(404).json({ success: false, error: "Batch report not generated yet" });
    }

    return res.json({
      success: true,
      report: {
        batchId,
        targetUrl: scans[0].targetUrl,
        scanType: "all-tools",
        language: normalizeReportLanguage(reportOwner.reportLanguage),
        content: reportOwner.reportContent,
      },
    });
  } catch (err) {
    return res.status(err.status || 500).json({ success: false, error: err.message || "Failed to download batch report" });
  }
};
