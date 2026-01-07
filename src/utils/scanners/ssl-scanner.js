import { spawn } from "child_process";

function extractDomain(targetUrl) {
  try {
    return new URL(targetUrl).hostname;
  } catch {
    return targetUrl
      .replace(/^https?:\/\//i, "")
      .replace(/\/.*$/, "")
      .replace(/^www\./i, "");
  }
}

function isValidDomain(d) {
  return /^[a-zA-Z0-9.-]+$/.test(d) && d.length >= 3;
}

export async function scanWithSsl(targetUrl) {
  try {
    const domain = extractDomain(targetUrl);

    if (!isValidDomain(domain)) {
      return {
        tool: "sslscan",
        success: false,
        error: "Invalid domain",
        domain,
      };
    }

    const args = [
  "--no-colour",
  // REMOVE THIS: "--show-client-cas",  // This makes output huge!
  domain,
];

    return await new Promise((resolve) => {
      const child = spawn("sslscan", args, {
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      const MAX_RAW = 10000;
      const TIMEOUT_MS = 180000;
      const timer = setTimeout(() => {
        try {
          child.kill("SIGTERM");
        } catch {}
      }, TIMEOUT_MS);

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
        if (stdout.length > MAX_RAW) stdout = stdout.slice(-MAX_RAW);
      });

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
        if (stderr.length > MAX_RAW) stderr = stderr.slice(-MAX_RAW);
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({
          tool: "sslscan",
          success: false,
          error: err.message,
          rawOutput: stderr || stdout,
          domain,
        });
      });

      child.on("close", () => {
        clearTimeout(timer);

        const lines = stdout
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean);
        const issues = [];
        const critical = [];
        const weakCiphers = [];
        const deprecatedProtocols = [];
        const certificateIssues = [];

        const cert = {};

        lines.forEach((line) => {
          const low = line.toLowerCase();

          if (
            low.includes("sslv2") ||
            low.includes("sslv3") ||
            low.includes("tlsv1.0") ||
            low.includes("tlsv1.1")
          ) {
            deprecatedProtocols.push(line);
            critical.push(`Deprecated protocol: ${line}`);
          }

          if (
            low.includes("weak") ||
            low.includes("null") ||
            low.includes("export") ||
            low.includes("des") ||
            low.includes("rc4")
          ) {
            weakCiphers.push(line);
            issues.push(`Weak cipher: ${line}`);
          }

          if (
            low.includes("expired") ||
            low.includes("self-signed") ||
            low.includes("invalid") ||
            low.includes("revoked") ||
            low.includes("mismatch")
          ) {
            certificateIssues.push(line);
            critical.push(`Certificate issue: ${line}`);
          }

          // Extract certificate metadata if present
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
        });

        const hasTLS12 = stdout.includes("TLSv1.2");
        const hasTLS13 = stdout.includes("TLSv1.3");

        const allIssues = [...critical, ...issues, ...certificateIssues];
        if (allIssues.length === 0 && (hasTLS12 || hasTLS13)) {
          allIssues.push("No security issues detected - TLS 1.2/1.3 supported");
        }

        resolve({
          tool: "sslscan",
          success: true,
          totalIssues: allIssues.length,
          issues: allIssues.slice(0, 50),
          criticalIssues: critical,
          weakCiphers,
          deprecatedProtocols,
          certificateIssues,
          certificateDetails: cert,
          supportsTLS12: hasTLS12,
          supportsTLS13: hasTLS13,
          rawOutput: stdout,
          domain,
        });
      });
    });
  } catch (err) {
    return {
      tool: "sslscan",
      success: false,
      error: err.message || "Unexpected error",
      rawOutput: "",
      domain: targetUrl,
    };
  }
}
