

import { spawn } from "child_process";

function ensureTestUrl(url) {
  // If no query params, add one for testing
  if (url.includes("?")) return url;
  return url.replace(/\/$/, "") + "/?id=1";
}

export async function scanWithSqlmap(targetUrl) {
  try {
    let testUrl = targetUrl.trim();
    testUrl = ensureTestUrl(testUrl);

    const args = [
      "-u",
      testUrl,
      "--batch",
      "--smart",
      "--level",
      "5",
      "--risk",
      "3",
      "--technique",
      "BEUSTQ",
      "--dbs",
      "--tables",
      "--random-agent",
      "--tamper",
      "space2comment",
      "--threads",
      "3",
      "--no-cast",
      "--disable-coloring",
    ];

    return await new Promise((resolve) => {
      const child = spawn("sqlmap", args, { stdio: ["ignore", "pipe", "pipe"] });

      let stdout = "";
      let stderr = "";
      const MAX_STD = 10000;

      const TIMEOUT_MS = 185000;
      const timer = setTimeout(() => {
        try {
          child.kill("SIGTERM");
        } catch {}
      }, TIMEOUT_MS);

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
        if (stdout.length > MAX_STD) stdout = stdout.slice(-MAX_STD);
      });

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
        if (stderr.length > MAX_STD) stderr = stderr.slice(-MAX_STD);
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({
          tool: "sqlmap",
          success: false,
          error: err.message,
          rawOutput: stderr || stdout,
          target: testUrl,
        });
      });

      child.on("close", () => {
        clearTimeout(timer);
        const lines = stdout.split("\n").map((l) => l.trim()).filter(Boolean);

        let vulnerable = false;
        const vulnerabilities = [];
        const warnings = [];
        const databases = [];
        const tables = [];
        const injectionPoints = [];

        lines.forEach((line) => {
          const low = line.toLowerCase();
          if (low.includes("is injectable") || /parameter.*injectable/i.test(line) || low.includes("payload:")) {
            vulnerabilities.push(line);
            vulnerable = true;
          }

          if (low.includes("does not seem to be injectable") || low.includes("not injectable")) {
            warnings.push(line);
          }

          // Simple DB extraction: lines like "[1] information_schema"
          const dbMatch = line.match(/^\[\d+\]:\s*([A-Za-z0-9_-]+)/);
          if (dbMatch) databases.push(dbMatch[1]);

          if (line.toLowerCase().includes("table")) {
            tables.push(line);
          }

          if (line.toLowerCase().includes("parameter:") || line.toLowerCase().includes("injection point")) {
            injectionPoints.push(line);
          }
        });

        // backend DBMS detection
        const dbmsMatch = stdout.match(/back-end DBMS:\s*([^\n\r]+)/i);
        const dbms = dbmsMatch ? dbmsMatch[1].trim() : null;

        // payload extraction
        const payloadMatch = stdout.match(/Payload:\s*([^\n\r]+)/i);
        const payload = payloadMatch ? payloadMatch[1].trim() : null;

        resolve({
          tool: "sqlmap",
          success: true,
          vulnerable,
          vulnerabilities: vulnerable ? vulnerabilities.slice(0, 20) : [],
          warnings: warnings.slice(0, 10),
          databases: [...new Set(databases)],
          tables,
          injectionPoints,
          details: {
            testedUrl: testUrl,
            dbms,
            payload,
            findingsCount: vulnerabilities.length,
            databasesFound: databases.length,
            tablesFound: tables.length,
          },
          rawOutput: stdout,
          target: testUrl,
          summary: vulnerable ? `SQL injection detected (DB: ${dbms || "unknown"})` : "No SQL injection detected",
        });
      });
    });
  } catch (err) {
    return {
      tool: "sqlmap",
      success: false,
      error: err.message || "Unexpected error",
      vulnerable: false,
      vulnerabilities: [],
      warnings: [],
      databases: [],
      tables: [],
      injectionPoints: [],
      rawOutput: "",
      target: targetUrl,
    };
  }
}
