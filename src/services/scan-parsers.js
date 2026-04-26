export function parseNmap(rawOutput = "", target = "") {
  const out = rawOutput || "";
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
    // Open port lines like "22/tcp open  ssh"
    if (/^\d+\/tcp\s+open/i.test(line)) {
      openPorts.push(line);
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

  let errorMsg = undefined;
  if (/0 hosts up/i.test(out) || /failed to resolve/i.test(out)) {
    errorMsg = "Website URL is wrong, website is down, or does not exist.";
  }

  return {
    tool: "nmap",
    error: errorMsg,
    success:
      openPorts.length > 0 || cveList.length > 0 || vulnerabilities.length > 0,
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
  const testedHostsMatch = out.match(/(\d+)\s+host\(s\)\s+tested/i);
  const testedHosts = testedHostsMatch ? Number(testedHostsMatch[1]) : null;
  const looksLikeNiktoRun =
    /Nikto v|Target Hostname:|Target IP:|Start Time:/i.test(out);
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

  // Consider it successful when nikto actually ran against at least one host,
  // even if it found zero issues.
  const success =
    (scanCompleted || looksLikeNiktoRun) &&
    (testedHosts === null || testedHosts > 0);

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
  let scanRan = false;
  const vulnerabilities = [];
  const warnings = [];
  const databases = new Set();
  const tables = [];
  const injectionPoints = [];
  const injectionTypes = [];

  for (const line of lines) {
    const lower = line.toLowerCase();

    // Detect that sqlmap actually ran against the target
    if (/testing url|testing connection|sqlmap resumed|heuristic|target url/i.test(line)) {
      scanRan = true;
    }

    // Primary injectable detection
    if (
      /is vulnerable|is injectable|parameter.*is vulnerable|parameter.*injectable/i.test(line) ||
      /identified the following injection point/i.test(line) ||
      lower.includes("sql injection") ||
      /type:\s*(boolean|error|time|union|stacked)/i.test(line)
    ) {
      vulnerable = true;
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
    }

    // Injection type classification
    const typeMatch = line.match(/Type:\s*(.+)/i);
    if (typeMatch) {
      injectionTypes.push(typeMatch[1].trim());
      vulnerable = true;
    }

    // Payload lines confirm injection
    if (/Payload:\s*.+/i.test(line)) {
      vulnerable = true;
      injectionPoints.push(line);
    }

    // "Not injectable" warnings
    if (
      /does not seem to be injectable|not injectable|could not fingerprint|parameter .* does not appear/i.test(lower)
    ) {
      warnings.push(line);
    }

    // DB names from "[1] dbname" style output
    const dbMatch = line.match(/^\[\d+\]\s+([\w-]+)/);
    if (dbMatch) databases.add(dbMatch[1]);

    // Also from "available databases [N]:" lines and subsequent entries
    if (/table:/i.test(line) || /tables/i.test(lower)) {
      if (!tables.includes(line)) tables.push(line);
    }

    // Parameter / injection point lines
    if (/parameter:|injection point|injection:|place:/i.test(line)) {
      if (!injectionPoints.includes(line)) injectionPoints.push(line);
    }
  }

  // If sqlmap ran (even without finding injection) mark scan as ran
  if (!scanRan && out.length > 200) scanRan = true;

  const dbmsMatch = out.match(/back-end DBMS:\s*([^\n\r]+)/i);
  const dbms = dbmsMatch ? dbmsMatch[1].trim() : null;

  const payloadMatch = out.match(/Payload:\s*([^\n\r]+)/i);
  const payload = payloadMatch ? payloadMatch[1].trim() : null;

  return {
    tool: "sqlmap",
    success: scanRan,       // scan ran OK (even if nothing found)
    vulnerable,             // actual SQL injection found
    vulnerabilities: vulnerabilities.slice(0, 100),
    injectionTypes,
    warnings: warnings.slice(0, 50),
    databases: Array.from(databases),
    tables: tables.slice(0, 200),
    injectionPoints: injectionPoints.slice(0, 50),
    details: {
      testedUrl: target,
      dbms,
      payload,
      findingsCount: vulnerabilities.length,
      databasesFound: databases.size,
      tablesFound: tables.length,
      injectionTypes,
    },
    rawOutput: out,
    target,
    summary: vulnerable
      ? `SQL injection confirmed (DB: ${dbms || "unknown"}, Types: ${injectionTypes.join(", ") || "detected"})`
      : scanRan
      ? "Scan completed — no SQL injection detected on tested parameters"
      : "Scan did not complete successfully",
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
  const heartbleedVulnerable = [];
  const cert = {};

  // Track whether sslscan actually ran and produced output
  const looksLikeSslscan =
    /SSL\/TLS Protocols|TLSv1|SSLv|Supported Server Cipher|SSL Certificate/i.test(out);

  for (const line of lines) {
    const low = line.toLowerCase();

    // Only flag deprecated protocols that are ENABLED (not disabled/not supported)
    // sslscan output: "TLSv1.0   enabled" or "SSLv2   enabled"
    if (/sslv2|sslv3|tlsv1\.0|tlsv1\.1/i.test(low)) {
      // Exclude lines explicitly saying disabled / not supported
      if (!/disabled|not supported|not enabled/i.test(low)) {
        deprecatedProtocols.push(line);
        critical.push(`Deprecated protocol detected: ${line}`);
      }
    }

    // Weak/null ciphers — only when the cipher is being OFFERED (has key size or "Accepted")
    // sslscan output: "Accepted  TLSv1.2  256 bits  RC4-SHA"
    if (
      /(RC4|NULL|EXPORT|DES|ANON|MD5|3DES)/i.test(line) &&
      /(Accepted|bits|enabled)/i.test(line)
    ) {
      weakCiphers.push(line);
      issues.push(`Weak cipher suite offered: ${line}`);
    }

    // Heartbleed
    if (/heartbleed/i.test(low) && /vulnerable/i.test(low)) {
      heartbleedVulnerable.push(line);
      critical.push(`Heartbleed vulnerability: ${line}`);
    }

    // Certificate issues
    if (/expired|self-signed|invalid|revoked|mismatch/i.test(low)) {
      certificateIssues.push(line);
      critical.push(`Certificate issue: ${line}`);
    }

    // Certificate fields — sslscan indents with spaces, trim() handles that
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

    // Common Name
    const cn = line.match(/CN=([^,\n]+)/i);
    if (cn && !cert.commonName) cert.commonName = cn[1].trim();
  }

  const hasTLS12 = /TLSv1\.2\s+(enabled|Accepted)/i.test(out);
  const hasTLS13 = /TLSv1\.3\s+(enabled|Accepted)/i.test(out);

  const allIssues = [...new Set([...critical, ...issues, ...certificateIssues])];

  // success = scan ran and produced output (true even when vulnerabilities found)
  // hasVulnerabilities = actual security problems found
  const success = looksLikeSslscan || lines.length > 5;
  const hasVulnerabilities = allIssues.length > 0;

  return {
    tool: "ssl",
    success,
    hasVulnerabilities,
    totalIssues: allIssues.length,
    issues: allIssues.slice(0, 100),
    criticalIssues: critical,
    weakCiphers,
    deprecatedProtocols,
    certificateIssues,
    heartbleedVulnerable,
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
