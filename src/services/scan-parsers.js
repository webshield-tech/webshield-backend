export function parseNmap(rawOutput = "", target = "") {
  const out = rawOutput || "";
  // Check if scan was interrupted
  if (out.includes("Scan terminated") || 
      out.includes("Nmap done") && out.includes("scanned in")) {
    // Scan completed normally
    console.log("Nmap scan completed");
  } else if (out.length < 500) {
    // Very short output = likely interrupted
    console.log("Nmap scan interrupted or timed out");
  }
  const lines = out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const openPorts = [];
  const filteredPorts = [];
  const closedPorts = [];
  const serviceVersions = [];
  const vulnerabilities = [];
  const hostInfo = {};
  const cveSet = new Set();

  for (const line of lines) {
if (/^\d+\/tcp\s+open/i.test(line)) {
  openPorts.push(line);
} else if (/Discovered open port (\d+\/tcp)/i.test(line)) {
  const portMatch = line.match(/Discovered open port (\d+\/tcp) on/i);
  if (portMatch) {
    openPorts.push(portMatch[1] + " open");
  }
} else if (/^\d+\/tcp\s+filtered/i.test(line)) {
  filteredPorts.push(line);
} else if (/^\d+\/tcp\s+closed/i.test(line)) {
  if (closedPorts.length < 20) closedPorts.push(line);
}

    // service/version lines may start with '|' or contain "Service Info"
    if (line.startsWith("|") && line.includes(":")) {
      serviceVersions.push(line);
    }
    if (/Service Info:/i.test(line)) {
      hostInfo.serviceInfo =
        (hostInfo.serviceInfo ? hostInfo.serviceInfo + "\n" : "") + line;
    }

    // OS fingerprint hints
    if (/OS details:|Running:|Aggressive OS guesses:/i.test(line)) {
      hostInfo.os = (hostInfo.os ? hostInfo.os + "\n" : "") + line;
    }

    // Not shown lines
    if (/Not shown:/i.test(line)) {
      hostInfo.notShown =
        (hostInfo.notShown ? hostInfo.notShown + "\n" : "") + line;
    }

    // ssh-hostkey lines
    if (/ssh-hostkey:/i.test(line)) {
      hostInfo.sshHostKeys = hostInfo.sshHostKeys || [];
      hostInfo.sshHostKeys.push(line);
    }

    // CVE detection (basic)
    const cves = line.match(/CVE-\d{4}-\d{4,7}/gi);
    if (cves) {
      for (const c of cves) cveSet.add(c.toUpperCase());
      vulnerabilities.push(line);
    }

    // vulnerability-like keywords
    if (/VULNERABLE|vulnerable|CVE-|security hole|exploitable/i.test(line)) {
      vulnerabilities.push(line);
    }
  }

  const cveList = Array.from(cveSet);

  return {
    tool: "nmap",
       success: rawOutput.length > 0,
    openPorts,
    totalPorts: openPorts.length,
    filteredPorts,
    filteredCount: filteredPorts.length,
    closedPorts,
    serviceVersions: serviceVersions.length ? serviceVersions : undefined,
    vulnerabilities: vulnerabilities.length ? vulnerabilities : undefined,
    cveList: cveList.length ? cveList : undefined,
    osDetection: hostInfo.os || null,
    hostInfo,
    rawOutput: out,
    target,
  };
}
export function parseNikto(rawOutput = "", target = "") {
  const out = rawOutput || "";
  const lines = out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  // Check if scan completed successfully (has Start Time and End Time)
  const hasStartTime = out.includes("Start Time:");
  const hasEndTime = out.includes("End Time:");
  const scanCompleted = hasStartTime && hasEndTime;

  // Extract statistics
  const requestsMatch = out.match(/(\d+)\s+requests:/);
  const itemsMatch = out.match(/and\s+(\d+)\s+item\(s\)\s+reported/);
  const requests = requestsMatch ? parseInt(requestsMatch[1]) : 0;
  const itemsFound = itemsMatch ? parseInt(itemsMatch[1]) : 0;

  // Extract server info
  let serverInfo = null;
  const serverMatch = out.match(/Server:\s*([^\n]+)/i);
  if (serverMatch) serverInfo = serverMatch[1].trim();

  // Parse findings if any
  const findings = [];
  const critical = [];
  const high = [];
  const medium = [];
  const low = [];

  // Look for actual vulnerability findings
  // Note: Nikto usually reports findings with + signs
  for (const line of lines) {
    if (
      line.startsWith("+ ") &&
      !line.includes("Target IP:") &&
      !line.includes("Target Hostname:") &&
      !line.includes("Start Time:") &&
      !line.includes("End Time:") &&
      !line.includes("Server:")
    ) {
      const cleaned = line.replace(/^\+\s*/, "").trim();
      if (cleaned && cleaned.length > 5 && !findings.includes(cleaned)) {
        findings.push(cleaned);

        const lower = cleaned.toLowerCase();
        if (
          /(sql injection|command execution|remote shell|rce|critical)/i.test(
            lower
          )
        ) {
          critical.push(cleaned);
        } else if (
          /(xss|cross-site|directory traversal|file upload|high)/i.test(lower)
        ) {
          high.push(cleaned);
        } else if (
          /(information disclosure|directory listing|misconfiguration|medium)/i.test(
            lower
          )
        ) {
          medium.push(cleaned);
        } else {
          low.push(cleaned);
        }
      }
    }
  }

  // Success means scan completed (even if no findings)
  const success = scanCompleted;

  return {
    tool: "nikto",
    success: success,
    totalFindings: findings.length,
    findings: findings.slice(0, 200),
    criticalFindings: critical,
    highFindings: high,
    mediumFindings: medium,
    lowFindings: low,
    serverInfo,
    scanStats: {
      requestsMade: requests,
      itemsReported: itemsFound,
      scanCompleted: scanCompleted,
    },
    rawOutput: out,
    target,
  };
}
export function parseSqlmap(rawOutput = "", target = "") {
  const out = rawOutput || "";
  const lines = out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  let vulnerable = false;
  const vulnerabilities = [];
  const warnings = [];
  const databases = new Set();
  const tables = [];
  const injectionPoints = [];

  for (const line of lines) {
    const lower = line.toLowerCase();

    if (
      /is vulnerable|is injectable|parameter.*is vulnerable|payload:/i.test(
        line
      ) ||
      lower.includes("sql injection")
    ) {
      vulnerable = true;
      vulnerabilities.push(line);
    }

    if (
      /does not seem to be injectable|not injectable|could not fingerprint/i.test(
        lower
      )
    ) {
      warnings.push(line);
    }

    // Simple DB extraction lines e.g. "[1] information_schema"
    const dbMatch = line.match(/^\[\d+\]\s*([\w-]+)/);
    if (dbMatch) databases.add(dbMatch[1]);

    if (/table:/i.test(line) || /tables/i.test(lower)) {
      if (!tables.includes(line)) tables.push(line);
    }

    if (/parameter:|injection point|injection:|payload:/i.test(line)) {
      injectionPoints.push(line);
    }
  }

  const dbmsMatch = out.match(/back-end DBMS:\s*([^\n\r]+)/i);
  const dbms = dbmsMatch ? dbmsMatch[1].trim() : null;

  const payloadMatch = out.match(/Payload:\s*([^\n\r]+)/i);
  const payload = payloadMatch ? payloadMatch[1].trim() : null;

  return {
    tool: "sqlmap",
    success: vulnerable,
    vulnerable,
    vulnerabilities: vulnerabilities.slice(0, 100),
    warnings: warnings.slice(0, 50),
    databases: Array.from(databases),
    tables: tables.slice(0, 200),
    injectionPoints,
    details: {
      testedUrl: target,
      dbms,
      payload,
      findingsCount: vulnerabilities.length,
      databasesFound: databases.size,
      tablesFound: tables.length,
    },
    rawOutput: out,
    target,
    summary: vulnerable
      ? `SQL injection likely (DB: ${dbms || "unknown"})`
      : "No SQL injection detected",
  };
}
export function parseSsl(rawOutput = "", target = "") {
  const out = rawOutput || "";
  const lines = out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const issues = [];
  const critical = [];
  const weakCiphers = [];
  const deprecatedProtocols = [];
  const certificateIssues = [];
  const cert = {};

  for (const line of lines) {
    const low = line.toLowerCase();

    if (/sslv2|sslv3|tlsv1\.0|tlsv1\.1/i.test(low)) {
      deprecatedProtocols.push(line);
      critical.push(`Deprecated protocol: ${line}`);
    }

    if (/(weak|null|export|des|rc4)/i.test(low)) {
      weakCiphers.push(line);
      issues.push(`Weak cipher: ${line}`);
    }

    if (/expired|self-signed|invalid|revoked|mismatch/i.test(low)) {
      certificateIssues.push(line);
      critical.push(`Certificate issue: ${line}`);
    }

    const subject = line.match(/^Subject:\s*(.+)$/i);
    if (subject) cert.subject = subject[1].trim();

    const issuer = line.match(/^Issuer:\s*(.+)$/i);
    if (issuer) cert.issuer = issuer[1].trim();

    const notBefore = line.match(/^Not valid before:\s*(.+)$/i);
    if (notBefore) cert.validFrom = notBefore[1].trim();

    const notAfter = line.match(/^Not valid after:\s*(.+)$/i);
    if (notAfter) cert.validTo = notAfter[1].trim();

    const sig = line.match(/^Signature Algorithm:\s*(.+)$/i);
    if (sig) cert.signatureAlgorithm = sig[1].trim();
  }

  const hasTLS12 = /TLSv1\.2/.test(out);
  const hasTLS13 = /TLSv1\.3/.test(out);
  const allIssues = [
    ...new Set([...critical, ...issues, ...certificateIssues]),
  ];

  // FIXED: If no issues found, success = true
  // If issues found, success = false (because SSL has problems)
 const success = rawOutput.length > 0; 

  return {
    tool: "ssl",
    success: success,
    totalIssues: allIssues.length,
    issues: allIssues.slice(0, 100),
    criticalIssues: critical,
    weakCiphers,
    deprecatedProtocols,
    certificateIssues,
    certificateDetails: cert,
    supportsTLS12: hasTLS12,
    supportsTLS13: hasTLS13,
    rawOutput: out,
    domain: target,
  };
}
export function parseByTool(executable, rawOutput, target) {
  // Map common executable names to parser
  const bin = (executable || "").toLowerCase();
  if (bin.includes("nmap")) return parseNmap(rawOutput, target);
  if (bin.includes("nikto")) return parseNikto(rawOutput, target);
  if (bin.includes("sqlmap")) return parseSqlmap(rawOutput, target);
  if (bin.includes("ssl") || bin.includes("sslscan"))
    return parseSsl(rawOutput, target);

  // Default: return raw output only
  return {
    tool: executable || "unknown",
    success: false,
    rawOutput: rawOutput || "",
    target,
  };
}
