import { promisify } from "util";
import { exec } from "child_process";
const execAsync = promisify(exec);

export async function scanWithNmap(targetUrl) {
  try {
    console.log("Starting Nmap Scan for:  ", targetUrl);

    // Extract hostname from URL
    let hostname = targetUrl;
    try {
      const urlObj = new URL(targetUrl);
      hostname = urlObj.hostname;
      console.log("Extracted hostname:", hostname);
    } catch (err) {
      console.log("Using original target as hostname:", hostname);
    }

    console.log("start scanning nmap for", hostname);

    const command = `timeout 180 nmap -Pn -T4 -sV -sC -O -v --top-ports 1000 --max-retries 1 --host-timeout 240s ${hostname}`;

    console.log("Running Nmap command:", command);

    // Execute Nmap scan
    const { stdout, stderr } = await execAsync(command, {
      maxBuffer: 1024 * 1024 * 10,
    });

    console.log("Nmap scan completed.  Output length:", stdout.length);

    // Parse Nmap output
    const openPorts = [];
    const serviceVersions = [];
    const vulnerabilities = [];
    const cveList = [];
    const lines = stdout.split("\n");

    lines.forEach((line) => {
      const trimmed = line.trim();

      if (/^\d+\/tcp\s+open/i.test(trimmed)) {
        openPorts.push(trimmed);
      }

      if (trimmed.startsWith("|") && trimmed.includes(":")) {
        serviceVersions.push(trimmed);
      }

      // CVE detection
      const cves = trimmed.match(/CVE-\d{4}-\d{4,7}/gi);
      if (cves) {
        cves.forEach((cve) => {
          if (!cveList.includes(cve.toUpperCase())) {
            cveList.push(cve.toUpperCase());
          }
        });
        vulnerabilities.push(trimmed);
      }

      // Other vulnerability indicators
      if (/VULNERABLE|vulnerable|security hole|exploitable/i.test(trimmed)) {
        vulnerabilities.push(trimmed);
      }
    });

    // Extract OS detection
    let osDetection = null;
    for (const line of lines) {
      if (/OS details:|Running:|Aggressive OS guesses:/i.test(line)) {
        osDetection = line;
        break;
      }
    }

    console.log(`Nmap scan found ${openPorts.length} open ports`);

    return {
      tool: "nmap",
      success: openPorts.length > 0 || cveList.length > 0,
      openPorts: openPorts.slice(0, 50),
      totalPorts: openPorts.length,
      serviceVersions: serviceVersions.slice(0, 50),
      vulnerabilities: vulnerabilities.slice(0, 50),
      cveList: cveList.slice(0, 20),
      osDetection: osDetection,
      rawOutput: stdout.substring(0, 5000),
      target: hostname,
    };
  } catch (error) {
    console.error("Nmap scan error:", error.message);

    if (error.killed) {
      return {
        tool: "nmap",
        success: false,
        error: "Scan timed out after 3 minutes",
        openPorts: [],
        totalPorts: 0,
        rawOutput: error.stdout || "Scan timed out",
        target: targetUrl,
      };
    }

    return {
      tool: "nmap",
      success: false,
      error: error.message,
      openPorts: [],
      totalPorts: 0,
      rawOutput: error.stdout || error.stderr || "No output",
      target: targetUrl,
    };
  }
}
