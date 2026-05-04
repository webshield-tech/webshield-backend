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
    if (/testing url|testing connection|sqlmap resumed|heuristic|target url|starting detection/i.test(line)) {
      scanRan = true;
    }

    // "parameter 'id' appears to be '...' injectable"  — SQLMap's primary confirmation line
    if (/parameter\s+.+appears\s+to\s+be.+injectable/i.test(line)) {
      vulnerable = true;
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
    }

    // "is vulnerable" / "is injectable" anywhere
    if (/\bis\s+(?:vulnerable|injectable)\b/i.test(line)) {
      vulnerable = true;
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
    }

    // "identified the following injection point(s)"
    if (/identified the following injection point/i.test(line)) {
      vulnerable = true;
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
    }

    // "sql injection" anywhere
    if (lower.includes("sql injection")) {
      vulnerable = true;
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
    }

    // "parameter.*is vulnerable|parameter.*injectable"
    if (/parameter.*(?:is vulnerable|injectable)/i.test(line)) {
      vulnerable = true;
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
    }

    // Type: boolean-based blind / error-based / time-based / union / stacked / inline
    if (/type:\s*(boolean|error|time|union|stacked|inline)/i.test(line)) {
      vulnerable = true;
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
    }

    // Injection type block inside the summary section: "    Type: boolean-based blind"
    const typeMatch = line.match(/^\s*Type:\s*(.+)$/i);
    if (typeMatch) {
      const t = typeMatch[1].trim();
      if (!injectionTypes.includes(t)) injectionTypes.push(t);
      vulnerable = true;
    }

    // Payload lines always confirm injection
    if (/^\s*Payload:\s*.+/i.test(line)) {
      vulnerable = true;
      if (!injectionPoints.includes(line)) injectionPoints.push(line);
      if (!vulnerabilities.includes(line)) vulnerabilities.push(line);
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

    // Table lines
    if (/table:/i.test(line) || /\btables\b/i.test(lower)) {
      if (!tables.includes(line)) tables.push(line);
    }

    // Parameter / injection point descriptor lines
    if (/^\s*(?:parameter|place|injection point|injection):/i.test(line)) {
      if (!injectionPoints.includes(line)) injectionPoints.push(line);
    }
  }

  // If sqlmap ran (even without finding injection) mark scan as ran
  if (!scanRan && out.length > 200) scanRan = true;

  const dbmsMatch = out.match(/back-end DBMS:\s*([^\n\r]+)/i);
  const dbms = dbmsMatch ? dbmsMatch[1].trim() : null;

  // back-end DBMS identified => sqlmap fingerprinted the database => injection confirmed
  if (dbms) {
    vulnerable = true;
  }

  const payloadMatch = out.match(/Payload:\s*([^\n\r]+)/i);
  const payload = payloadMatch ? payloadMatch[1].trim() : null;

  const uniqueTypes = [...new Set(injectionTypes)];

  return {
    tool: "sqlmap",
    success: scanRan,
    vulnerable,
    vulnerabilities: vulnerabilities.slice(0, 100),
    injectionTypes: uniqueTypes,
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
      injectionTypes: uniqueTypes,
    },
    rawOutput: out,
    target,
    summary: vulnerable
      ? `SQL injection confirmed (DB: ${dbms || "unknown"}, Types: ${uniqueTypes.join(", ") || "detected"})`
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
  const noTlsServiceDetected =
    /connection refused|failed to connect|handshake failed|no route to host|connection reset/i.test(out);

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

  if (noTlsServiceDetected) {
    allIssues.push(
      "HTTPS/TLS service is not reachable on the expected TLS endpoint; traffic may be exposed over plain HTTP."
    );
    critical.push(
      "No reachable TLS endpoint detected. Enforce HTTPS and expose a valid TLS listener (typically port 443)."
    );
  }

  // success = scan ran and produced output (true even when vulnerabilities found)
  // hasVulnerabilities = actual security problems found
  const success = looksLikeSslscan || noTlsServiceDetected || lines.length > 5;
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
export function parseByTool(executable, rawOutput, target, scanType = "") {
  const normalizedType = String(scanType || "").toLowerCase();
  const mappedType = normalizedType === "sslscan" ? "ssl" : normalizedType;

  if (mappedType) {
    if (mappedType === "nmap") return parseNmap(rawOutput, target);
    if (mappedType === "nikto") return parseNikto(rawOutput, target);
    if (mappedType === "sqlmap") return parseSqlmap(rawOutput, target);
    if (mappedType === "ssl") return parseSsl(rawOutput, target);
    if (mappedType === "gobuster") return parseGobuster(rawOutput, target);
    if (mappedType === "ratelimit") return parseRateLimit(rawOutput, target);
    if (mappedType === "ffuf") return parseFfuf(rawOutput, target);
    if (mappedType === "wapiti") return parseWapiti(rawOutput, target);
    if (mappedType === "nuclei") return parseNuclei(rawOutput, target);
    if (mappedType === "dns") return parseDns(rawOutput, target);
    if (mappedType === "whois") return parseWhois(rawOutput, target);
    if (mappedType === "xss") return parseXss(rawOutput, target);
  }

  // Map common executable names to parser
  const bin = (executable || "").toLowerCase();
  if (bin.includes("nmap")) return parseNmap(rawOutput, target);
  if (bin.includes("nikto")) return parseNikto(rawOutput, target);
  if (bin.includes("sqlmap")) return parseSqlmap(rawOutput, target);
  if (bin.includes("ssl") || bin.includes("sslscan"))
    return parseSsl(rawOutput, target);
  if (bin.includes("gobuster")) return parseGobuster(rawOutput, target);
  if (bin.includes("ratelimit")) return parseRateLimit(rawOutput, target);
  if (bin.includes("ffuf")) return parseFfuf(rawOutput, target);
  if (bin.includes("wapiti")) return parseWapiti(rawOutput, target);
  if (bin.includes("nuclei")) return parseNuclei(rawOutput, target);
  if (bin.includes("dns")) return parseDns(rawOutput, target);
  if (bin.includes("whois")) return parseWhois(rawOutput, target);
  if (bin.includes("xss") || bin.includes("xss-csrf")) return parseXss(rawOutput, target);

  // Default: return raw output only
  return {
    tool: executable || "unknown",
    success: false,
    rawOutput: rawOutput || "",
    target,
  };
}
export function parseGobuster(rawOutput = "", target = "") {
  const out = rawOutput || "";
  const lines = out.split("\n").map(l => l.trim()).filter(Boolean);
  const directories = [];
  const protectedPaths = [];

  for (const line of lines) {
    // Parse status code from gobuster output format: /path  (Status: 200) [Size: 1234]
    const match = line.match(/(\/[^\s]+).*\(Status:\s*(\d+)\)/);
    if (!match) continue;
    const [, dirPath, code] = match;
    const status = parseInt(code, 10);
    if ([200, 301, 302].includes(status)) {
      directories.push({ path: dirPath, status });
    } else if ([403, 401].includes(status)) {
      protectedPaths.push({ path: dirPath, status, note: status === 403 ? "Forbidden (sensitive/protected path)" : "Authentication required" });
    }
  }

  const success = directories.length > 0 || protectedPaths.length > 0;
  return {
    tool: "gobuster",
    success,
    directories,
    protectedPaths,
    count: directories.length,
    total: directories.length + protectedPaths.length,
    summary: success
      ? `Found ${directories.length} accessible and ${protectedPaths.length} protected path(s) on ${target}`
      : `No directories discovered on ${target}`,
    rawOutput: out,
    target,
  };
}

export function parseRateLimit(rawOutput = "", target = "") {
  const out = rawOutput || "";
  const lines = out.split("\n").map(l => l.trim()).filter(Boolean);
  
  const apiActive = out.includes("RESULT: API_ACTIVE");
  const rateLimitActive = out.includes("RESULT: RATE_LIMIT_ACTIVE");
  const requestLimiterActive = out.includes("RESULT: REQUEST_LIMITER_ACTIVE");
  const noLimiter = out.includes("RESULT: NO_LIMITER_DETECTED");

  const findings = [];
  if (apiActive) {
    const apiMatch = out.match(/Found \d+ endpoints: ([^\)]+)/);
    findings.push(`API Endpoints detected: ${apiMatch ? apiMatch[1] : "Multiple paths identified"}`);
  } else {
    findings.push("No standard API endpoints detected at the base URL.");
  }

  if (rateLimitActive) {
    findings.push("Rate Limiter is ACTIVE (HTTP 429 detected). The server successfully throttled excessive requests.");
  } else if (requestLimiterActive) {
    findings.push("Request Limiter/WAF is ACTIVE (HTTP 403 detected). The security layer blocked the burst test.");
  } else if (noLimiter) {
    findings.push("VULNERABILITY: No rate or request limiting detected. The server accepted 100 concurrent requests without throttling.");
  }

  return {
    tool: "ratelimit",
    success: true,
    vulnerable: noLimiter,
    apiActive,
    rateLimitActive,
    requestLimiterActive,
    findings,
    rawOutput: out,
    target
  };
}

export function parseFfuf(rawOutput = "", target = "") {
  const lines = rawOutput.split("\n");
  const findings = [];
  const protectedPaths = [];

  for (const line of lines) {
    const statusMatch = line.match(/\[Status:\s*(\d+)/);
    if (!statusMatch) continue;
    const status = parseInt(statusMatch[1], 10);
    const wordMatch = line.match(/\*\s*FUZZ:\s*(.+?)\s*\[/);
    const word = wordMatch ? wordMatch[1].trim() : line.trim();
    if ([200, 301, 302].includes(status)) {
      findings.push({ path: word, status });
    } else if ([403, 401].includes(status)) {
      protectedPaths.push({ path: word, status, note: "Protected resource" });
    }
  }

  const success = findings.length > 0 || protectedPaths.length > 0;
  return {
    tool: "ffuf",
    success,
    findings,
    protectedPaths,
    count: findings.length,
    total: findings.length + protectedPaths.length,
    summary: success
      ? `FFUF found ${findings.length} endpoint(s) and ${protectedPaths.length} protected path(s) on ${target}`
      : `No endpoints found on ${target}`,
    rawOutput,
    target,
  };
}

export function parseWapiti(rawOutput = "", target = "") {
  const vulnerabilities = [];
  let parsed = null;

  // Wapiti can output structured JSON when invoked with -f json
  try {
    const jsonMatch = rawOutput.match(/\{[\s\S]+\}/);
    if (jsonMatch) parsed = JSON.parse(jsonMatch[0]);
  } catch { /* not JSON mode, fall back to text parsing */ }

  if (parsed?.vulnerabilities) {
    for (const [type, items] of Object.entries(parsed.vulnerabilities)) {
      if (Array.isArray(items) && items.length > 0) {
        for (const item of items) {
          vulnerabilities.push({
            type,
            path: item.path || item.url || "unknown",
            method: item.method || "GET",
            info: item.info || "",
            level: item.level ?? 1,
          });
        }
      }
    }
  } else {
    // Fallback plain-text: look for [+] vulnerability sections
    const vulnMatches = rawOutput.matchAll(/\[\+\]\s+([^\n]+)/g);
    for (const m of vulnMatches) {
      if (!m[1].toLowerCase().includes('no vulnerability')) {
        vulnerabilities.push({ type: m[1].trim(), info: m[1].trim() });
      }
    }
  }

  const success = vulnerabilities.length > 0;
  return {
    tool: "wapiti",
    success,
    vulnerabilities,
    total: vulnerabilities.length,
    summary: success
      ? `Wapiti found ${vulnerabilities.length} vulnerability type(s) on ${target}`
      : `Wapiti completed — no web vulnerabilities detected on ${target}`,
    rawOutput,
    target,
  };
}

export function parseNuclei(rawOutput = "", target = "") {
  const lines = rawOutput.split("\n").filter(l => l.trim().startsWith("["));
  return {
    tool: "nuclei",
    success: lines.length > 0,
    findings: lines,
    count: lines.length,
    rawOutput,
    target
  };
}

export function parseDns(rawOutput = "", target = "") {
  try {
    const data = JSON.parse(rawOutput);
    return {
      tool: "dns",
      success: true,
      records: data,
      rawOutput,
      target
    };
  } catch (e) {
    return {
      tool: "dns",
      success: false,
      error: "Failed to parse DNS data",
      rawOutput,
      target
    };
  }
}

export function parseXss(rawOutput = "", target = "") {
  const xssFindings = [];
  const csrfFindings = [];

  for (const line of rawOutput.split("\n")) {
    const t = line.trim();
    if (t.startsWith("XSS_FOUND:")) {
      try { xssFindings.push(JSON.parse(t.slice(10))); } catch { xssFindings.push({ raw: t }); }
    } else if (t.startsWith("CSRF_FOUND:")) {
      try { csrfFindings.push(JSON.parse(t.slice(11))); } catch { csrfFindings.push({ raw: t }); }
    }
  }

  const xssVulnerable = rawOutput.includes("RESULT: XSS_VULNERABLE") || xssFindings.length > 0;
  const csrfVulnerable = rawOutput.includes("RESULT: CSRF_VULNERABLE") || csrfFindings.length > 0;
  const success = xssVulnerable || csrfVulnerable;

  return {
    tool: "xss",
    success,
    xssVulnerable,
    csrfVulnerable,
    xssFindings,
    csrfFindings,
    total: xssFindings.length + csrfFindings.length,
    summary: success
      ? `XSS/CSRF scanner detected issues on ${target}: XSS=${xssVulnerable ? 'VULNERABLE' : 'Safe'}, CSRF=${csrfVulnerable ? 'VULNERABLE' : 'Safe'}`
      : `XSS/CSRF scanner completed — no injection or CSRF vulnerabilities found on ${target}`,
    rawOutput,
    target,
  };
}
