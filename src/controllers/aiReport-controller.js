import { aiReport } from "../utils/aiReport.js";
import { Scan } from "../models/scans-mongoose.js";

const MAX_PROMPT_CHARS = 20000;

function ensureNmapStructuredFromRaw(scan) {
  if (!scan || scan.scanType !== "nmap" || !scan.results) return;

  const already = scan.results.nmap || {};
  const hasUseful =
    (Array.isArray(already.openPorts) && already.openPorts.length > 0) ||
    (Array.isArray(already.serviceVersions) &&
      already.serviceVersions.length > 0) ||
    (already.osDetection && String(already.osDetection).trim());

  const raw = String(already.rawOutput || scan.results.rawOutput || "");
  if (!raw.trim()) return;
  if (hasUseful) {
    const cves = Array.from(
      new Set(
        (raw.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((c) => c.toUpperCase()),
      ),
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

  // Parse raw output lines
  const lines = raw
    .split("\n")
    .map((l) => l.replace(/\r$/, "").trim())
    .filter(Boolean);

  const openPorts = [];
  const serviceVersions = [];
  const osHints = [];
  const cveSet = new Set();
  const hostInfo = {};
  const sshHostKeys = [];

  for (const line of lines) {
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(.*)$/i);
    if (portMatch) {
      const port = portMatch[1];
      const proto = portMatch[2];
      const state = portMatch[3];
      const rest = portMatch[4] || "";

      if (/open/i.test(state)) {
        const readable = `${port}/${proto} ${rest}`.trim();
        openPorts.push(readable);
      }

      // collect service/version if present
      if (rest && /[A-Za-z0-9]/.test(rest)) {
        serviceVersions.push(`${port}/${proto} ${rest}`.trim());
      }

      // capture CVEs embedded in the rest
      const cves = rest.match(/CVE-\d{4}-\d{4,7}/gi);
      if (cves) cves.forEach((c) => cveSet.add(c.toUpperCase()));
      continue;
    }

    // Handle "Discovered open port" lines
    const discoveredMatch = line.match(
      /Discovered open port (\d+)\/(tcp|udp)/i,
    );
    if (discoveredMatch) {
      const port = discoveredMatch[1];
      const proto = discoveredMatch[2];
      const readable = `${port}/${proto} open`;
      if (!openPorts.includes(readable)) {
        openPorts.push(readable);
      }
      continue;
    }

    if (
      /ssh-hostkey/i.test(line) ||
      line.toLowerCase().startsWith("| ssh-hostkey") ||
      line.toLowerCase().startsWith("ssh-hostkey:")
    ) {
      sshHostKeys.push(line);
      continue;
    }
    if (
      (line.startsWith("|") && line.includes(":")) ||
      /Service Info:/i.test(line) ||
      /http-server-header|http-title/i.test(line)
    ) {
      serviceVersions.push(line);
      const cves = line.match(/CVE-\d{4}-\d{4,7}/gi);
      if (cves) cves.forEach((c) => cveSet.add(c.toUpperCase()));
      continue;
    }

    // OS detection
    if (
      /OS details:|Aggressive OS guesses:|No exact OS matches|Running:|OS:|Uptime guess:/i.test(
        line,
      )
    ) {
      osHints.push(line);
      continue;
    }

    const cves = line.match(/CVE-\d{4}-\d{4,7}/gi);
    if (cves) cves.forEach((c) => cveSet.add(c.toUpperCase()));
  }

  // Merge into scan.results.nmap (don't delete existing structured fields if present)
  const merged = {
    ...(scan.results.nmap || {}),
    openPorts:
      scan.results.nmap?.openPorts && scan.results.nmap.openPorts.length
        ? scan.results.nmap.openPorts
        : openPorts,
    serviceVersions:
      scan.results.nmap?.serviceVersions &&
      scan.results.nmap.serviceVersions.length
        ? scan.results.nmap.serviceVersions
        : serviceVersions,
    osDetection:
      scan.results.nmap?.osDetection ||
      (osHints.length ? osHints.join("; ") : undefined),
    cveList:
      scan.results.nmap?.cveList && scan.results.nmap.cveList.length
        ? scan.results.nmap.cveList
        : Array.from(cveSet),
    hostInfo: {
      ...(scan.results.nmap?.hostInfo || {}),
      ...(Object.keys(hostInfo).length ? hostInfo : {}),
    },
    sshHostKeys:
      scan.results.nmap?.sshHostKeys && scan.results.nmap.sshHostKeys.length
        ? scan.results.nmap.sshHostKeys
        : sshHostKeys.length
          ? sshHostKeys
          : undefined,
    rawOutput: scan.results.nmap?.rawOutput || scan.results.rawOutput || raw,
  };

  scan.results.nmap = merged;
}

// Helper function to get tool-specific results
function getToolResults(scan) {
  if (!scan.results) return null;

  // For backward compatibility, check both structures
  switch (scan.scanType) {
    case "nmap":
      return scan.results.nmap || scan.results;
    case "nikto":
      return scan.results.nikto || scan.results;
    case "ssl":
      return scan.results.ssl || scan.results;
    case "sqlmap":
      return scan.results.sqlmap || scan.results;
    default:
      return scan.results;
  }
}

// Diagnostics helpers

function analyzeNmapOutput(raw = "") {
  const s = String(raw || "");
  if (!s.trim())
    return "No scanner output was captured (process may have been killed, truncated, or produced no output).";
  if (
    /Failed to resolve|Name or service not known|Could not resolve/i.test(s)
  ) {
    return "Target DNS resolution failed or target is unreachable.";
  }
  if (/Failed to find any hosts/i.test(s)) {
    return "Nmap could not find the host — target may be down or filtered.";
  }
  if (/All \d+ scanned ports on .* are closed/i.test(s)) {
    return "All scanned ports appear closed — no open services were discovered.";
  }
  if (/OS detection.*requires root|You must be root/i.test(s)) {
    return "OS detection often requires root privileges; run nmap as root or give the process necessary capabilities for better OS fingerprints (or remove -O if not permitted).";
  }
  if (/No exact OS matches for host|No OS matches/i.test(s)) {
    return "OS fingerprinting did not produce a confident match — network filtering or limited responses likely prevented OS detection.";
  }
  if (/Service detection performed/i.test(s) && !/open/i.test(s)) {
    return "Service/version detection ran but did not find version strings — the host may be using firewall/IDS or services may not respond with version banners.";
  }
  if (/Read timed out|timed out|Operation timed|scan timed out/i.test(s)) {
    return "Scan timed out before completing — try increasing timeout or scanning fewer ports.";
  }
  return null;
}

function analyzeNiktoOutput(raw = "") {
  const s = String(raw || "");
  if (!s.trim())
    return "No output captured from Nikto (process may have been killed or timed out).";
  if (/could not connect|connection refused|Connection timed out/i.test(s)) {
    return "Nikto could not connect to the target — check network connectivity or that the web server is running.";
  }
  if (/404 Not Found|403 Forbidden/i.test(s)) {
    return "The server returned HTTP errors (403/404) that may limit Nikto's findings.";
  }
  if (/login required|authentication required/i.test(s)) {
    return "Target requires authentication; unauthenticated scanning will miss protected endpoints.";
  }
  return null;
}

function analyzeSslOutput(raw = "") {
  const s = String(raw || "");
  if (!s.trim()) return "No output captured from SSL scanner.";
  if (/connection refused|connection timed out/i.test(s))
    return "Could not connect to target port for TLS handshake.";
  if (/self signed|expired|certificate verify failed/i.test(s))
    return "Certificate issues detected (self-signed or expired) which are reported elsewhere in the results.";
  return null;
}

function analyzeSqlmapOutput(raw = "") {
  const s = String(raw || "");
  if (!s.trim())
    return "No output captured from sqlmap (process may have been terminated or produced no output).";
  if (/could not fingerprint|could not connect|connection refused/i.test(s))
    return "sqlmap could not reach the target or fingerprint the backend DBMS.";
  if (/not injectable|does not seem to be injectable/i.test(s))
    return "sqlmap found no injectable parameters during the test.";
  return null;
}

function nmapDiagnostic(scan) {
  const results = getToolResults(scan);
  const raw = results?.rawOutput || scan.results?.rawOutput || "";
  const reason = analyzeNmapOutput(raw);
  if (reason) return `Diagnostics: ${reason}`;
  if (!results)
    return "Diagnostics: No structured nmap results were saved; raw output may be truncated or parsing failed.";

  const parts = [];
  if (!results.openPorts || results.openPorts.length === 0)
    parts.push("No open ports discovered by the scan.");
  if (!results.serviceVersions || results.serviceVersions.length === 0)
    parts.push("Service/version detection produced no version strings.");
  if (!results.osDetection)
    parts.push("OS detection produced no confident match.");
  if (parts.length) return "Diagnostics: " + parts.join(" ");
  return null;
}

function niktoDiagnostic(scan) {
  const results = getToolResults(scan);
  const raw = results?.rawOutput || scan.results?.rawOutput || "";
  const reason = analyzeNiktoOutput(raw);
  if (reason) return `Diagnostics: ${reason}`;

  if (!results) return "Diagnostics: Nikto results missing or parser failed.";

  // Check if scan completed
  if (results.scanStats?.scanCompleted) {
    if (results.totalFindings > 0) {
      return null;
    } else {
      return "Diagnostics: Scan completed but found no vulnerabilities.";
    }
  }

  if ((results.totalFindings || 0) === 0) {
    return "Diagnostics: Nikto reported no findings (target may be secured or scanning limited by server responses).";
  }

  return null;
}

function sslDiagnostic(scan) {
  const results = getToolResults(scan);
  const raw = results?.rawOutput || scan.results?.rawOutput || "";
  const reason = analyzeSslOutput(raw);
  if (reason) return `Diagnostics: ${reason}`;
  if (!results)
    return "Diagnostics: SSL scan results missing or parser failed.";
  return null;
}

function sqlmapDiagnostic(scan) {
  const results = getToolResults(scan);
  const raw = results?.rawOutput || scan.results?.rawOutput || "";
  const reason = analyzeSqlmapOutput(raw);
  if (reason) return `Diagnostics: ${reason}`;
  if (!results) return "Diagnostics: SQLMap results missing or parser failed.";
  return null;
}

// Raw results builder with diagnostics

function buildRawResults(scan) {
  let results = "";
  const toolResults = getToolResults(scan);

  // NMAP
  if (scan.scanType === "nmap") {
    const n = toolResults;
    const openPortsCount =
      n && n.openPorts && Array.isArray(n.openPorts) ? n.openPorts.length : 0;
    results += `\nNMAP SCAN RESULTS:\n------------------\nOpen Ports: ${openPortsCount}\n\n`;
    if (openPortsCount > 0) results += (n.openPorts || []).join("\n") + "\n";
    else results += "No open ports detected\n";

    if (n?.hostInfo) {
      results += "\nHOST INFORMATION:\n";
      if (n.hostInfo.status) results += `${n.hostInfo.status}\n`;
      if (n.hostInfo.serviceInfo)
        results += `Service Info: ${n.hostInfo.serviceInfo}\n`;
    }

    if (n?.serviceVersions?.length) {
      results += "\nSERVICE DETAILS:\n" + n.serviceVersions.join("\n") + "\n";
    } else {
      const diag = nmapDiagnostic(scan);
      if (diag)
        results += `\nSERVICE DETAILS: No version data available.\n${diag}\n`;
    }

    if (n?.vulnerabilities?.length)
      results +=
        "\nVULNERABILITIES DETECTED:\n" + n.vulnerabilities.join("\n") + "\n";
    else {
      const raw = n?.rawOutput || scan.results?.rawOutput || "";
      if (raw && /CVE-\d{4}-\d{4,7}/i.test(raw)) {
        results += `\nVULNERABILITIES: CVE identifiers were found in raw output but not structured. See rawOutput excerpt below.\n`;
      } else {
        results += "\nVULNERABILITIES: None detected in parsed output.\n";
      }
    }

    if (n?.cveList?.length)
      results += "\nCVE IDENTIFIERS:\n" + n.cveList.join(", ") + "\n";

    if (n?.osDetection)
      results += "\nOPERATING SYSTEM DETECTION:\n" + n.osDetection + "\n";
    else {
      const diag = nmapDiagnostic(scan);
      if (diag)
        results += `\nOPERATING SYSTEM DETECTION: Not detected.\n${diag}\n`;
      else results += "\nOPERATING SYSTEM DETECTION: Not detected.\n";
    }

    results +=
      "\nRaw Output (excerpt):\n" +
      (n?.rawOutput || scan.results?.rawOutput || "N/A")
        .split("\n")
        .slice(0, 200)
        .join("\n") +
      "\n";
  }

  // NIKTO
  if (scan.scanType === "nikto") {
    const k = toolResults;
    results += `\nNIKTO SCAN RESULTS:\n-------------------\nTotal Findings: ${k?.totalFindings || 0}\n`;

    // Show server info if available
    if (k?.serverInfo) {
      results += `Server: ${k.serverInfo}\n`;
    }

    // Show scan stats if available
    if (k?.scanStats) {
      results += `Requests Made: ${k.scanStats.requestsMade || 0}\n`;
      results += `Items Reported: ${k.scanStats.itemsReported || 0}\n`;
    }

    results += "\n";

    if (k?.criticalFindings?.length) {
      results +=
        "CRITICAL FINDINGS:\n" +
        k.criticalFindings.map((f, i) => `${i + 1}. ${f}`).join("\n") +
        "\n\n";
    }

    if (k?.highFindings?.length) {
      results +=
        "HIGH FINDINGS:\n" +
        k.highFindings.map((f, i) => `${i + 1}. ${f}`).join("\n") +
        "\n\n";
    }

    if (k?.mediumFindings?.length) {
      results +=
        "MEDIUM FINDINGS:\n" +
        k.mediumFindings.map((f, i) => `${i + 1}. ${f}`).join("\n") +
        "\n\n";
    }

    if (k?.lowFindings?.length) {
      results +=
        "LOW FINDINGS:\n" +
        k.lowFindings.map((f, i) => `${i + 1}. ${f}`).join("\n") +
        "\n\n";
    }

    if (k?.findings?.length) {
      results +=
        "ALL FINDINGS:\n" +
        k.findings.map((f, i) => `${i + 1}. ${f}`).join("\n") +
        "\n";
    } else {
      const diag = niktoDiagnostic(scan);
      results += `No detailed findings available.\n${diag ? diag + "\n" : ""}`;
    }
  }

  // SSL
  if (scan.scanType === "ssl") {
    const s = toolResults;
    results += `\nSSL/TLS SCAN RESULTS:\n---------------------\nTotal Issues: ${s?.totalIssues || 0}\n\n`;

    if (s?.certificateDetails) {
      const cert = s.certificateDetails;
      results += "CERTIFICATE DETAILS:\n";
      if (cert.subject) results += `Subject: ${cert.subject}\n`;
      if (cert.issuer) results += `Issuer: ${cert.issuer}\n`;
      if (cert.validFrom) results += `Valid From: ${cert.validFrom}\n`;
      if (cert.validTo) results += `Valid To: ${cert.validTo}\n`;
      if (cert.signatureAlgorithm)
        results += `Signature Algorithm: ${cert.signatureAlgorithm}\n`;
      results += "\n";
    }

    if (s?.supportsTLS12 || s?.supportsTLS13) {
      results += "TLS SUPPORT:\n";
      if (s.supportsTLS12) results += "✓ TLS 1.2 supported\n";
      if (s.supportsTLS13) results += "✓ TLS 1.3 supported\n";
      results += "\n";
    }

    if (!(s?.issues?.length || 0)) {
      const diag = sslDiagnostic(scan);
      results += `No SSL/TLS issues listed.\n${diag ? diag + "\n" : ""}`;
    } else {
      results +=
        "ISSUES:\n" +
        s.issues.map((issue, i) => `${i + 1}. ${issue}`).join("\n") +
        "\n";
    }

    results +=
      "\nRaw Output (excerpt):\n" +
      (s?.rawOutput || scan.results?.rawOutput || "N/A")
        .split("\n")
        .slice(0, 200)
        .join("\n") +
      "\n";
  }

  // SQLMAP
  if (scan.scanType === "sqlmap") {
    const q = toolResults;
    results += `\nSQLMAP SCAN RESULTS:\n--------------------\nVulnerable: ${q?.vulnerable ? "YES" : "NO"}\n\n`;

    if (q?.details?.dbms) {
      results += `Database Management System: ${q.details.dbms}\n`;
    }

    if (q?.details?.payload) {
      results += `Payload: ${q.details.payload}\n`;
    }

    if (q?.details?.databasesFound) {
      results += `Databases Found: ${q.details.databasesFound}\n`;
    }

    results += "\n";

    if (q?.vulnerabilities?.length) {
      results +=
        "VULNERABILITIES:\n" +
        q.vulnerabilities.map((v, i) => `${i + 1}. ${v}`).join("\n") +
        "\n";
    }

    if (q?.databases?.length) {
      results +=
        "\nDATABASES:\n" +
        q.databases.map((db, i) => `${i + 1}. ${db}`).join("\n") +
        "\n";
    }

    if (q?.tables?.length) {
      results +=
        "\nTABLES:\n" +
        q.tables.map((t, i) => `${i + 1}. ${t}`).join("\n") +
        "\n";
    }

    if (!q?.vulnerabilities?.length && !q?.vulnerable) {
      const diag = sqlmapDiagnostic(scan);
      results += `No SQL injection findings.\n${diag ? diag + "\n" : ""}`;
    }

    results +=
      "\nRaw Output (excerpt):\n" +
      (q?.rawOutput || scan.results?.rawOutput || "N/A")
        .split("\n")
        .slice(0, 200)
        .join("\n") +
      "\n";
  }

  return results || "No detailed results available";
}

// Prompt builder for AI

function buildSummaryText(scan) {
  let text = `
Target URL: ${scan.targetUrl}
Scan Tool: ${scan.scanType}
Scan Time: ${new Date(scan.createdAt).toLocaleString()}

SCAN RESULTS:
=============
`;

  const toolResults = getToolResults(scan);

  if (scan.scanType === "nmap") {
    text += `
[NETWORK PORT AND SERVICE SCAN]
Tool Used: Nmap
`;
    const openPortsCount =
      toolResults &&
      toolResults.openPorts &&
      Array.isArray(toolResults.openPorts)
        ? toolResults.openPorts.length
        : 0;

    if (openPortsCount > 0) {
      text += `OPEN PORTS (${openPortsCount}):\n`;
      text += toolResults.openPorts.join("\n") + "\n\n";
    } else {
      text += `OPEN PORTS: NONE FOUND\n\n`;
    }

    if (toolResults?.serviceVersions?.length) {
      text += `SERVICE VERSIONS:\n${toolResults.serviceVersions.join("\n")}\n\n`;
    } else {
      const diag = nmapDiagnostic(scan);
      if (diag)
        text += `SERVICE VERSIONS: No version info available. ${diag}\n\n`;
      else text += `SERVICE VERSIONS: No version info available.\n\n`;
    }

    if (toolResults?.cveList?.length) {
      text += `CVE LIST:\n${toolResults.cveList.join(", ")}\n\n`;
    } else {
      const diag = nmapDiagnostic(scan);
      if (diag) text += `CVE LIST: None extracted. ${diag}\n\n`;
      else text += `CVE LIST: None extracted.\n\n`;
    }

    if (toolResults?.osDetection) {
      text += `OS DETECTION:\n${toolResults.osDetection}\n\n`;
      text += `DIAGNOSTICS FOR LIMITATIONS:\n${nmapDiagnostic(scan) || "No issues detected"}\n\n`;
    } else {
      const diag = nmapDiagnostic(scan);
      text += `OS DETECTION: Not detected. ${diag ? diag : "OS fingerprinting may be blocked or inconclusive."}\n\n`;
    }

    text += `\nIMPORTANT: Use the data above as the source for a concise risk summary.\n`;
  }

  if (scan.scanType === "nikto") {
    text += `\n[WEB SERVER SCAN - Nikto]\n`;
    text += `Total Findings: ${toolResults?.totalFindings || 0}\n`;

    if (toolResults?.serverInfo) {
      text += `Server: ${toolResults.serverInfo}\n`;
    }

    if (toolResults?.scanStats) {
      text += `Requests Made: ${toolResults.scanStats.requestsMade || 0}\n`;
      text += `Items Reported: ${toolResults.scanStats.itemsReported || 0}\n`;
    }

    text += `\n`;

    if (toolResults?.findings?.length) {
      text += `FINDINGS:\n${toolResults.findings.slice(0, 10).join("\n")}\n`;
    }

    const diag = niktoDiagnostic(scan);
    if (diag) text += `\nDiagnostics: ${diag}\n`;
  }

  if (scan.scanType === "ssl") {
    text += `\n[SSL/TLS SCAN]\n`;
    text += `Total Issues: ${toolResults?.totalIssues || 0}\n`;

    if (toolResults?.certificateDetails) {
      const cert = toolResults.certificateDetails;
      text += `Certificate Subject: ${cert.subject || "Not available"}\n`;
      text += `Certificate Valid From: ${cert.validFrom || "Not available"}\n`;
      text += `Certificate Valid To: ${cert.validTo || "Not available"}\n`;
    }

    const diag = sslDiagnostic(scan);
    if (diag) text += `\nDiagnostics: ${diag}\n`;
  }

  if (scan.scanType === "sqlmap") {
    text += `\n[SQLMAP SCAN]\n`;
    text += `Vulnerable: ${toolResults?.vulnerable ? "YES" : "NO"}\n`;

    if (toolResults?.details?.dbms) {
      text += `Database Management System: ${toolResults.details.dbms}\n`;
    }

    if (toolResults?.vulnerabilities?.length) {
      text += `Vulnerabilities Found: ${toolResults.vulnerabilities.length}\n`;
    }

    const diag = sqlmapDiagnostic(scan);
    if (diag) text += `\nDiagnostics: ${diag}\n`;
  }

  text += `

INSTRUCTIONS FOR AI:
- Analyze the available data above.
- If fields are missing, use the diagnostics and explain briefly why data may be missing.
- Provide a concise (short) port/service assessment, a risk level, and 3-5 actionable recommendations.
- Return only the analysis text (no JSON or extra metadata).
`;

  return text;
}

//  buildReportContent

function buildReportContent(scan, aiText) {
  return `
WEBSHIELD SECURITY SCAN REPORT

Scan Information
----------------------
Scan ID       : ${scan._id}
Target URL    : ${scan.targetUrl}
Scan Type     : ${String(scan.scanType).toUpperCase()}
Scan Date     : ${new Date(scan.createdAt).toLocaleString()}
Report Date   : ${new Date().toLocaleString()}
Status        : ${String(scan.status).toUpperCase()}

AI Security Analysis
----------------------
${aiText}

Raw Scan Results
----------------------
${buildRawResults(scan)}

END OF REPORT

Generated by WebShield Security Scanner
Report ID: ${scan._id}
© ${new Date().getFullYear()} WebShield
`.trim();
}

// generateAIReportForScan

export const generateAIReportForScan = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;

    const scan = await Scan.findOne({ _id: scanId, userId: userId });
    if (!scan)
      return res.status(404).json({ success: false, error: "Scan not found" });
    if (scan.status !== "completed")
      return res.status(400).json({
        success: false,
        error: "Scan is not completed yet",
        status: scan.status,
      });
    if (scan.reportContent)
      return res.json({
        success: true,
        message: "Report already exists",
        reportGenerated: true,
        generatedAt: scan.reportGeneratedAt,
        scanId: scan._id,
      });
    try {
      ensureNmapStructuredFromRaw(scan);
      // Persist parsed fallback fields so future report generation sees them
      if (scan.results?.nmap) {
        await Scan.findByIdAndUpdate(scan._id, {
          $set: {
            "results.nmap": scan.results.nmap,
            "results.rawOutput":
              scan.results.rawOutput || scan.results.nmap.rawOutput,
          },
        });
      }
    } catch (e) {
      console.warn("[aiReport] nmap fallback parse failed:", e);
    }

    // Build prompt and cap length
    let summaryText = buildSummaryText(scan);
    if (summaryText.length > MAX_PROMPT_CHARS) {
      const head = summaryText.slice(0, Math.floor(MAX_PROMPT_CHARS / 2) - 500);
      const tail = summaryText.slice(-Math.floor(MAX_PROMPT_CHARS / 2) + 500);
      summaryText = `${head}\n\n...TRUNCATED...\n\n${tail}`;
    }

    console.log(`[aiReport] prompt length: ${summaryText.length}`);

    // Call AI
    let aiResp;
    try {
      aiResp = await aiReport(summaryText);
    } catch (err) {
      console.error("[aiReport] error:", err);
      return res
        .status(500)
        .json({ success: false, error: "AI service error" });
    }

    // Normalize aiResp to string
    let aiText = "";
    if (!aiResp) aiText = "AI returned empty response";
    else if (typeof aiResp === "string") aiText = aiResp;
    else if (typeof aiResp === "object")
      aiText =
        aiResp.text ||
        aiResp.content ||
        (aiResp.choices &&
          aiResp.choices[0] &&
          (aiResp.choices[0].message?.content || aiResp.choices[0].text)) ||
        JSON.stringify(aiResp);
    else aiText = String(aiResp);

    // Persist final report and return
    const reportContent = buildReportContent(scan, aiText);
    scan.reportContent = reportContent;
    scan.reportGeneratedAt = new Date();
    await scan.save();

    return res.json({
      success: true,
      message: "Report generated successfully",
      reportGenerated: true,
      generatedAt: scan.reportGeneratedAt,
      scanId: scan._id,
    });
  } catch (err) {
    console.error("Report generation error:", err);
    return res
      .status(500)
      .json({ success: false, error: "Failed to generate report" });
  }
};

// Download & view handlers

export const downloadReport = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const scan = await Scan.findOne({ _id: scanId, userId: userId });
    if (!scan)
      return res.status(404).json({ success: false, error: "Scan not found" });
    if (!scan.reportContent)
      return res.status(404).json({
        success: false,
        error: "Report not generated yet",
        message: "Please generate the report first",
      });

    const domain = new URL(scan.targetUrl).hostname;
    const date = (scan.reportGeneratedAt || new Date())
      .toISOString()
      .split("T")[0];
    const filename = `WebShield_${scan.scanType}_${domain}_${date}.txt`;

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(scan.reportContent);
  } catch (err) {
    console.error("Report download error:", err);
    res
      .status(500)
      .json({ success: false, error: "Failed to download report" });
  }
};

export const viewReport = async (req, res) => {
  try {
    const scanId = req.params.id;
    const userId = req.user?.userId || req.userId;
    const scan = await Scan.findOne({ _id: scanId, userId: userId });
    if (!scan)
      return res.status(404).json({ success: false, error: "Scan not found" });
    if (!scan.reportContent)
      return res.status(404).json({
        success: false,
        error: "Report not generated yet",
        message: "Please generate the report first",
      });

    res.json({
      success: true,
      report: {
        scanId: scan._id,
        targetUrl: scan.targetUrl,
        scanType: scan.scanType,
        scanDate: scan.createdAt,
        generatedAt: scan.reportGeneratedAt,
        content: scan.reportContent,
      },
    });
  } catch (err) {
    console.error("Report view error:", err);
    res
      .status(500)
      .json({ success: false, error: "Failed to retrieve report" });
  }
};
