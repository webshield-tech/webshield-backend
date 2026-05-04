import axios from "axios";
import https from "https";
import { randomUUID } from "crypto";
import path from "path";
import fs from "fs";
import { exec } from "child_process";
import util from "util";
import dns from "dns/promises";
import { Scan } from "../models/scans-mongoose.js";
import { User } from "../models/users-mongoose.js";
import {
  startProcess,
  killProcess,
  hasProcess,
} from "../services/scan-runner.js";
import { refundFailedScanQuota } from "../services/scan-quota.js";
import { validateHostname } from "../utils/validations/hostname-validation.js";
import { urlValidation } from "../utils/validations/url-validation.js";
import { detectPlatform } from "../utils/platform-detector.js";
import { extractReconData } from "../utils/reconDataExtractor.js";
import { decideScanPlan } from "../utils/scanDecisionEngine.js";
import { ensureDailyScanReset } from "../utils/daily-scan-reset.js";

const execPromise = util.promisify(exec);

const ALLOWED_SCANS = ["nmap", "nikto", "ssl", "sqlmap", "gobuster", "ratelimit", "ffuf", "wapiti", "nuclei", "dns", "whois", "xss"];
const DAILY_PER_TOOL_LIMIT = 10;
const DAILY_AUTO_LIMIT = 5;

async function checkBinaryAvailable(binaryName) {
  try {
    await execPromise(`command -v ${binaryName}`);
    return true;
  } catch {
    return false;
  }
}

async function computeToolAvailability() {
  const byTool = {};

  const binaryChecks = {
    nmap: "nmap",
    nikto: "nikto",
    sqlmap: "sqlmap",
    sslscan: "sslscan",
    gobuster: "gobuster",
    ffuf: "ffuf",
    wapiti: "wapiti",
    nuclei: "nuclei",
    whois: "whois",
  };

  for (const [tool, bin] of Object.entries(binaryChecks)) {
    byTool[tool] = await checkBinaryAvailable(bin);
  }

  // Alias for scanType "ssl" used in auto scans
  byTool.ssl = byTool.sslscan === true;

  const nodeAvailable = await checkBinaryAvailable("node");
  const scriptChecks = {
    ratelimit: path.join(process.cwd(), "src", "utils", "ratelimit-test.js"),
    dns: path.join(process.cwd(), "src", "utils", "dns-verify.js"),
    xss: path.join(process.cwd(), "src", "utils", "xss-csrf-scanner.js"),
  };

  for (const [tool, scriptPath] of Object.entries(scriptChecks)) {
    byTool[tool] = nodeAvailable && fs.existsSync(scriptPath);
  }

  const available = Object.entries(byTool)
    .filter(([, ok]) => ok)
    .map(([tool]) => tool);
  const missing = Object.entries(byTool)
    .filter(([, ok]) => !ok)
    .map(([tool]) => tool);

  return { byTool, available, missing };
}

export async function getToolAvailability(req, res) {
  try {
    const { byTool, available, missing } = await computeToolAvailability();

    return res.json({
      success: true,
      availability: {
        byTool,
        available,
        missing,
      },
    });
  } catch (error) {
    console.error("[getToolAvailability] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to check tool availability" });
  }
}

/**
 * MANUAL PING CHECK: Endpoint to let user check if target is alive
 */
export async function pingTarget(req, res) {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: "URL is required" });

    const validation = urlValidation(url);
    if (!validation.valid) return res.status(400).json({ success: false, error: validation.error });
    
    // Extract host and port
    let targetHost;
    let targetPort;
    try {
      const parsed = new URL(validation.url);
      targetHost = parsed.hostname;
      targetPort = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
    } catch (e) {
      const parts = validation.url.replace(/^https?:\/\//, '').split('/')[0].split(':');
      targetHost = parts[0];
      targetPort = parts[1] || '80';
    }

    // Attempt ICMP Ping first
    try {
      await execPromise(`ping -c 1 -W 2 ${targetHost}`);
      return res.json({ 
        success: true, 
        message: "Target is reachable and alive.", 
        host: targetHost,
        method: "icmp",
        url: validation.url,
      });
    } catch (icmpError) {
      console.log(`[pingTarget] ICMP ping failed for ${targetHost}, falling back to HTTP probes...`);
    }

    const httpsAgent = new https.Agent({ rejectUnauthorized: false });
    const probeConfig = {
      timeout: 8000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: {
        "User-Agent": "WebShield-Availability-Check/1.0",
        Accept: "*/*",
      },
      responseType: "text",
    };

    const probeUrls = [];
    try {
      const parsedUrl = new URL(validation.url);
      probeUrls.push(parsedUrl.href);
      const alternate = new URL(parsedUrl.href);
      alternate.protocol = parsedUrl.protocol === "https:" ? "http:" : "https:";
      if (!probeUrls.includes(alternate.href)) {
        probeUrls.push(alternate.href);
      }

      // If backend runs in Docker, localhost may point to the container itself.
      // Probe common host bridge aliases as fallback so local DVWA can still be detected.
      const isLoopback = ["localhost", "127.0.0.1", "::1"].includes(parsedUrl.hostname);
      if (isLoopback) {
        const bridgeHosts = ["host.docker.internal", "172.17.0.1"];
        for (const bridgeHost of bridgeHosts) {
          const bridgePrimary = new URL(parsedUrl.href);
          bridgePrimary.hostname = bridgeHost;
          if (!probeUrls.includes(bridgePrimary.href)) {
            probeUrls.push(bridgePrimary.href);
          }

          const bridgeAlternate = new URL(bridgePrimary.href);
          bridgeAlternate.protocol = bridgePrimary.protocol === "https:" ? "http:" : "https:";
          if (!probeUrls.includes(bridgeAlternate.href)) {
            probeUrls.push(bridgeAlternate.href);
          }
        }
      }
    } catch {
      probeUrls.push(validation.url);
    }

    const probeViaHttp = async (candidateUrl, method) => {
      try {
        const response = await axios.request({
          method,
          url: candidateUrl,
          ...probeConfig,
          ...(candidateUrl.startsWith("https:") ? { httpsAgent } : {}),
        });
        return { ok: true, status: response.status };
      } catch (error) {
        return { ok: false, error };
      }
    };

    let successfulProbe = null;
    let methodUsed = "http-get";

    for (const candidateUrl of probeUrls) {
      const headProbe = await probeViaHttp(candidateUrl, "HEAD");
      if (headProbe.ok) {
        successfulProbe = candidateUrl;
        methodUsed = candidateUrl.startsWith("https:") ? "https-head" : "http-head";
        break;
      }

      const getProbe = await probeViaHttp(candidateUrl, "GET");
      if (getProbe.ok) {
        successfulProbe = candidateUrl;
        methodUsed = candidateUrl.startsWith("https:") ? "https-get" : "http-get";
        break;
      }
    }

    if (successfulProbe) {
      return res.json({ 
        success: true, 
        message: "Target is reachable and alive.", 
        host: targetHost,
        method: methodUsed,
        url: successfulProbe,
      });
    } else {
      console.error(`[pingTarget] Host ${targetHost} failed HTTP reachability probes.`);
      return res.status(503).json({ 
        success: false, 
        error: `Target Unreachable: ${targetHost} did not respond to ICMP or HTTP reachability probes on port ${targetPort}.` 
      });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: "Ping failed" });
  }
}

function getUserIdFromRequest(req) {
  return req.userId || req.user?.userId;
}

function buildSqlmapTarget(url) {
  if (url.includes("?")) return url;
  return `${url.replace(/\/+$/, "")}?id=1`;
}

function resolveHostname(url) {
  const parsed = new URL(url);
  const hostname = parsed.hostname;
  validateHostname(hostname, { port: parsed.port || (parsed.protocol === "https:" ? "443" : "80") });
  return hostname;
}

function resolveSslTarget(url) {
  const parsed = new URL(url);
  validateHostname(parsed.hostname, { port: parsed.port || (parsed.protocol === "https:" ? "443" : "80") });
  // For http targets, scan default TLS endpoint on 443.
  // For https targets with explicit port, honor that port.
  if (parsed.protocol === "https:" && parsed.port) {
    return `${parsed.hostname}:${parsed.port}`;
  }
  return parsed.hostname;
}

function extractDvwaToken(html = "") {
  const match = String(html).match(/name=['"]user_token['"]\s+value=['"]([^'"]+)['"]/i);
  return match ? match[1] : "";
}

function applySetCookie(cookieJar, setCookieHeaders = []) {
  for (const cookieLine of setCookieHeaders || []) {
    const kv = String(cookieLine).split(";")[0];
    const idx = kv.indexOf("=");
    if (idx <= 0) continue;
    const key = kv.slice(0, idx).trim();
    const val = kv.slice(idx + 1).trim();
    if (key) cookieJar[key] = val;
  }
}

function buildCookieHeader(cookieJar) {
  return Object.entries(cookieJar)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

async function prepareDvwaSqlmapContext(finalUrl) {
  const parsed = new URL(finalUrl);
  const origin = `${parsed.protocol}//${parsed.host}`;
  const localHost = ["localhost", "127.0.0.1"].includes(parsed.hostname);
  if (!localHost) return null;

  const cfg = {
    timeout: 12000,
    validateStatus: () => true,
    maxRedirects: 2,
  };

  const probe = await axios.get(`${origin}/login.php`, cfg);
  if (!/Damn Vulnerable Web Application/i.test(String(probe.data || ""))) {
    return null;
  }

  const jar = {};

  // 1) setup/reset DB
  const setupPage = await axios.get(`${origin}/setup.php`, cfg);
  applySetCookie(jar, setupPage.headers?.["set-cookie"] || []);
  const setupToken = extractDvwaToken(setupPage.data);
  if (setupToken) {
    const setupResp = await axios.post(
      `${origin}/setup.php`,
      new URLSearchParams({
        create_db: "Create / Reset Database",
        user_token: setupToken,
      }).toString(),
      {
        ...cfg,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: buildCookieHeader(jar),
        },
      }
    );
    applySetCookie(jar, setupResp.headers?.["set-cookie"] || []);
  }

  // 2) login with default DVWA creds
  const loginPage = await axios.get(`${origin}/login.php`, {
    ...cfg,
    headers: { Cookie: buildCookieHeader(jar) },
  });
  applySetCookie(jar, loginPage.headers?.["set-cookie"] || []);
  const loginToken = extractDvwaToken(loginPage.data);
  if (loginToken) {
    const loginResp = await axios.post(
      `${origin}/login.php`,
      new URLSearchParams({
        username: "admin",
        password: "password",
        Login: "Login",
        user_token: loginToken,
      }).toString(),
      {
        ...cfg,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: buildCookieHeader(jar),
        },
      }
    );
    applySetCookie(jar, loginResp.headers?.["set-cookie"] || []);
  }

  // 3) set security to low
  const securityPage = await axios.get(`${origin}/security.php`, {
    ...cfg,
    headers: { Cookie: buildCookieHeader(jar) },
  });
  applySetCookie(jar, securityPage.headers?.["set-cookie"] || []);
  const secToken = extractDvwaToken(securityPage.data);
  if (secToken) {
    const secResp = await axios.post(
      `${origin}/security.php`,
      new URLSearchParams({
        security: "low",
        seclev_submit: "Submit",
        user_token: secToken,
      }).toString(),
      {
        ...cfg,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: buildCookieHeader(jar),
        },
      }
    );
    applySetCookie(jar, secResp.headers?.["set-cookie"] || []);
  }

  const cookieHeader = buildCookieHeader(jar);
  return {
    sqlmapTarget: `${origin}/vulnerabilities/sqli/?id=1&Submit=Submit`,
    cookies: cookieHeader || "",
  };
}

function shouldEnableNmapOsDetection() {
  const forceEnable = String(process.env.NMAP_ENABLE_OS_DETECTION || "")
    .trim()
    .toLowerCase();
  if (["1", "true", "yes", "on"].includes(forceEnable)) return true;

  if (typeof process.getuid === "function") {
    return process.getuid() === 0;
  }
  return false;
}

function isRunningAsRoot() {
  if (typeof process.getuid === "function") {
    return process.getuid() === 0;
  }
  return false;
}

async function getScanCommand(scanType, finalUrl, cookies = "", scanMode = "quick", sqlmapUrl = "") {
  const hostname = resolveHostname(finalUrl);

  if (scanType === "nmap") {
    let args = [];
    if (scanMode === "full") {
      args = [
        "-p-",
        "-sV",
        "-sC",
        "--script",
        "vuln",
        "-v",
        "--max-retries",
        "1",
        "--host-timeout",
        "600s",
        hostname,
      ];
    } else {
      args = [
        "-p",
        "80,443,8080",
        "-sV",
        "-v",
        "--max-retries",
        "1",
        "--host-timeout",
        "240s",
        hostname,
      ];
    }

    if (shouldEnableNmapOsDetection()) {
      const osFlags = isRunningAsRoot() ? ["-O"] : ["--privileged", "-O"];
      args.splice(args.indexOf("-sV"), 0, ...osFlags);
    }

    return {
      executable: "nmap",
      args,
      opts: { timeoutMs: scanMode === "full" ? 900000 : 360000, maxRaw: 800000 },
    };
  }

  if (scanType === "nikto") {
    // Nikto sometimes fails to resolve localhost (IPv6 ::1 issues). Force 127.0.0.1.
    const niktoUrl = finalUrl.replace(/^https?:\/\/localhost(:\d+)?/i, (match, port) => {
      return match.replace("localhost", "127.0.0.1");
    });
    let args = ["-h", niktoUrl, "-maxtime", scanMode === "full" ? "300s" : "120s", "-nointeractive"];
    if (scanMode === "quick") {
      args.push("-Tuning", "b");
    }
    return {
      executable: "nikto",
      args,
      opts: { timeoutMs: scanMode === "full" ? 360000 : 180000 },
    };
  }

  if (scanType === "ssl") {
    const sslArgs =
      scanMode === "full"
        ? ["--no-colour", "--show-certificate", "--heartbleed", resolveSslTarget(finalUrl)]
        : ["--no-colour", resolveSslTarget(finalUrl)];

    return {
      executable: "sslscan",
      args: sslArgs,
      opts: { timeoutMs: 120000, maxRaw: 200000 },
    };
  }

  if (scanType === "sqlmap") {
    // Use provided sqlmapUrl if available, otherwise fall back to auto-construction
    let sqlmapTarget = sqlmapUrl || buildSqlmapTarget(finalUrl);
    let sqlmapCookies = cookies || "";

    // Local DVWA convenience: auto-login to fetch cookies
    if (!sqlmapCookies) {
      try {
        const dvwa = await prepareDvwaSqlmapContext(finalUrl);
        if (dvwa?.cookies) {
          sqlmapCookies = dvwa.cookies;
          // Only auto-construct the target if the user didn't explicitly provide one
          if (!sqlmapUrl && !finalUrl.includes("?")) {
            sqlmapTarget = dvwa.sqlmapTarget;
          }
        }
      } catch (dvwaErr) {
        console.warn("[sqlmap] DVWA context prep skipped:", dvwaErr?.message || dvwaErr);
      }
    }

    const level = scanMode === "full" ? "5" : "3";
    const risk  = scanMode === "full" ? "3" : "2";

    // Unique output dir per scan prevents cached "not injectable" sessions
    // from a previous run poisoning the results of this one.
    const outputDir = `/tmp/sqlmap-${Date.now()}`;

    const args = [
      "-u", sqlmapTarget,
      "--batch",
      "--level", level,
      "--risk",  risk,
      "--threads", "4",
      "--timeout", "30",
      "--retries", "2",
      "--random-agent",
      "--technique", "BEUST",
      "--flush-session",   // always start fresh — never resume a stale cache
      "--disable-coloring",
      "--output-dir", outputDir,
    ];

    if (scanMode === "full") {
      args.push("--dump-all");
      if (!sqlmapTarget.includes("?")) args.push("--forms", "--crawl", "3");
    } else {
      if (!sqlmapTarget.includes("?")) args.push("--forms", "--crawl", "1");
    }

    if (sqlmapCookies) {
      args.push("--cookie", sqlmapCookies);
    }

    return {
      executable: "sqlmap",
      args,
      opts: {
        timeoutMs: scanMode === "full" ? 600000 : 240000,
        maxRaw: 500000,
      },
    };
  }

  if (scanType === "gobuster") {
    const wordlistPath = path.join(process.cwd(), "wordlist.txt");
    const args = ["dir", "-u", finalUrl, "-w", wordlistPath, "-t", "20", "-z", "--no-error"];
    if (scanMode === "quick") args.push("--limit", "50");

    return {
      executable: "gobuster",
      args,
      opts: { timeoutMs: 300000 },
    };
  }

  if (scanType === "ratelimit") {
    const scriptPath = path.join(process.cwd(), "src", "utils", "ratelimit-test.js");
    return {
      executable: "node",
      args: [scriptPath, finalUrl],
      opts: { timeoutMs: 120000 },
    };
  }

  if (scanType === "ffuf") {
    const wordlistPath = path.join(process.cwd(), "wordlist.txt");
    const args = ["-u", `${finalUrl}/FUZZ`, "-w", wordlistPath, "-t", "20", "-c"];
    if (scanMode === "quick") args.push("-mc", "200,301");
    
    return {
      executable: "ffuf",
      args,
      opts: { timeoutMs: 300000 },
    };
  }

  if (scanType === "wapiti") {
    const args = ["-u", finalUrl, "-m", "common", "-n", "10"];
    if (scanMode === "full") args.push("--level", "1");
    
    return {
      executable: "wapiti",
      args,
      opts: { timeoutMs: 600000 },
    };
  }

  if (scanType === "nuclei") {
    const args = ["-u", finalUrl, "-silent", "-no-color"];
    if (scanMode === "quick") args.push("-tags", "cve,exposure");
    
    return {
      executable: "nuclei",
      args,
      opts: { timeoutMs: 600000 },
    };
  }

  if (scanType === "dns") {
    const scriptPath = path.join(process.cwd(), "src", "utils", "dns-verify.js");
    const hostname = new URL(finalUrl).hostname;
    return {
      executable: "node",
      args: [scriptPath, hostname],
      opts: { timeoutMs: 30000 },
    };
  }

  if (scanType === "whois") {
    const hostname = new URL(finalUrl).hostname;
    // Get base domain (e.g., example.com from sub.example.com)
    const domainParts = hostname.split(".");
    const baseDomain = domainParts.slice(-2).join(".");
    
    return {
      executable: "whois",
      args: [baseDomain],
      opts: { timeoutMs: 30000 },
    };
  }

  if (scanType === "xss") {
    const scriptPath = path.join(process.cwd(), "src", "utils", "xss-csrf-scanner.js");
    return {
      executable: "node",
      args: [scriptPath, finalUrl],
      opts: { timeoutMs: 180000, maxRaw: 300000 },
    };
  }

  throw new Error("Unsupported scan type");
}

async function launchScanInBackground(scanId, finalUrl, scanType, cookies = "", scanMode = "quick", sqlmapUrl = "") {
  try {
    if (hasProcess(scanId)) {
      return { success: false, error: "Already running" };
    }

    console.log(`[SCAN_SERVICE] Starting ${scanType} scan (Mode: ${scanMode}) for: ${finalUrl} (ID: ${scanId})`);

    // ROBUST PLATFORM DETECTION
    try {
      const detection = await detectPlatform(finalUrl);
      const platformResult = `${detection.platform} (${detection.os})`;
      await Scan.findByIdAndUpdate(scanId, {
        platform: platformResult,
        "results.serverInfo": detection.server,
        "results.techStack": detection.tech,
        "results.platformDetection": detection
      });
    } catch (e) {
      console.warn("[SCAN_SERVICE] Platform detection failed:", e.message);
    }

    const command = await getScanCommand(scanType, finalUrl, cookies, scanMode, sqlmapUrl);
    if (command?.opts) command.opts.scanType = scanType;

    return new Promise((resolve) => {
      command.opts.onComplete = (id, status, parsed) => {
        resolve({ success: status === "completed", status, parsed });
      };

      startProcess(scanId, command.executable, command.args, command.opts)
        .then((started) => {
          if (!started.started) {
            throw new Error(started.error || "Failed to start scan process");
          }
        })
        .catch(async (error) => {
          console.error("[SCAN_SERVICE] Runtime error:", error?.message || error);
          const existingScan = await Scan.findById(scanId).lean();
          const mergedResults = {
            ...(existingScan?.results || {}),
            error: error?.message || "Scan failed to start"
          };
          await Scan.findByIdAndUpdate(scanId, {
            status: "failed",
            results: mergedResults,
            updatedAt: new Date(),
            completedAt: new Date(),
          });
          await refundFailedScanQuota(scanId);
          resolve({ success: false, error: error?.message });
        });
    });
  } catch (error) {
    console.error("[SCAN_SERVICE] Critical error:", error?.message || error);
    try {
      const existingScan = await Scan.findById(scanId).lean();
      await Scan.findByIdAndUpdate(scanId, {
        status: "failed",
        results: { ...(existingScan?.results || {}), error: error?.message || "Scan failed" },
        updatedAt: new Date(),
        completedAt: new Date(),
      });
      await refundFailedScanQuota(scanId);
    } catch (dbErr) {
      console.error("[SCAN_SERVICE] DB cleanup error:", dbErr);
    }
    return { success: false, error: error?.message };
  }
}

async function getTodayScanStats(userId) {
  await ensureDailyScanReset(userId);

  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const scansToday = await Scan.find({
    userId,
    createdAt: { $gte: startOfDay },
  })
    .select("scanType results.batchId results.mode")
    .lean();

  const byTool = { 
    nmap: 0, nikto: 0, ssl: 0, sqlmap: 0, gobuster: 0, 
    ratelimit: 0, ffuf: 0, wapiti: 0, nuclei: 0, dns: 0, whois: 0, xss: 0
  };
  const autoBatchIds = new Set();

  for (const scan of scansToday) {
    const type = String(scan.scanType || "");
    const isAutoMode = scan?.results?.mode === "all-tools";
    if (isAutoMode && scan?.results?.batchId) {
      autoBatchIds.add(String(scan.results.batchId));
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(byTool, type)) {
      byTool[type] += 1;
    }
  }

  // Sum ALL tools (not just the original 4)
  const singleUsed = Object.values(byTool).reduce((a, b) => a + b, 0);
  const totalUsed = singleUsed + autoBatchIds.size;
  return {
    byTool,
    autoUsed: autoBatchIds.size,
    singleUsed,
    totalUsed,
    singleLimit: DAILY_PER_TOOL_LIMIT * ALLOWED_SCANS.length,
  };
}

async function checkScanQuota(userId, scanType) {
  await ensureDailyScanReset(userId);

  const user = await User.findById(userId)
    .select("scanLimit usedScan")
    .lean();

  if (!user) {
    return { ok: false, code: 404, error: "User not found" };
  }

  const stats = await getTodayScanStats(userId);
  const dailyLimit = Number(user.scanLimit || 0);
  const atTotalLimit = dailyLimit > 0 && stats.totalUsed >= dailyLimit;

  if (atTotalLimit) {
    return {
      ok: false,
      code: 403,
      error: `Daily scan limit reached (${dailyLimit}/${dailyLimit}).`,
      quota: { ...stats, dailyLimit },
    };
  }

  if (scanType === "all") {
    if (stats.autoUsed >= DAILY_AUTO_LIMIT) {
      return {
        ok: false,
        code: 403,
        error: `Daily Auto Full Scan limit reached (${DAILY_AUTO_LIMIT}/${DAILY_AUTO_LIMIT}).`,
        quota: { ...stats, dailyLimit },
      };
    }
    return { ok: true, quota: { ...stats, dailyLimit } };
  } else {
    const usedForTool = Number(stats.byTool[scanType] || 0);
    if (usedForTool >= DAILY_PER_TOOL_LIMIT) {
      return {
        ok: false,
        code: 403,
        error: `Daily ${scanType.toUpperCase()} limit reached (${DAILY_PER_TOOL_LIMIT}/${DAILY_PER_TOOL_LIMIT}).`,
        quota: { ...stats, dailyLimit },
      };
    }
    return { ok: true, quota: { ...stats, dailyLimit } };
  }
}

function inferImpact(scan) {
  const r = scan.results || {};
  let score = 0;
  const evidence = [];

  if (scan.scanType === "sqlmap") {
    if (r.vulnerable) {
      score = 92;
      evidence.push("SQL injection indicators were detected.");
    } else {
      score = 10;
      evidence.push("No SQL injection indicators were detected.");
    }
  }

  if (scan.scanType === "nikto") {
    const critical = Number((r.criticalFindings || []).length);
    const high = Number((r.highFindings || []).length);
    const total = Number(r.totalFindings || 0);
    score = Math.min(20 + critical * 20 + high * 12 + total, 88);

    if (critical > 0)
      evidence.push(`${critical} critical web findings were reported.`);
    if (high > 0) evidence.push(`${high} high-severity web findings were reported.`);
    if (total === 0) evidence.push("Nikto completed with no findings.");
  }

  if (scan.scanType === "nmap") {
    const portsArray = Array.isArray(r.openPorts) ? r.openPorts : [];
    const cveCount = Number((r.cveList || []).length);

    // Standard web ports are expected — they should not inflate risk
    const STANDARD_WEB_PORTS = new Set([80, 443]);
    const nonStandardPorts = portsArray.filter((p) => {
      const match = String(p).match(/^(\d+)\//);
      const portNum = match ? parseInt(match[1], 10) : NaN;
      return !STANDARD_WEB_PORTS.has(portNum);
    });

    const onlyStandardPorts =
      portsArray.length > 0 && nonStandardPorts.length === 0;

    if (portsArray.length === 0) {
      score = 5;
      evidence.push("No open ports were detected.");
    } else if (onlyStandardPorts && cveCount === 0) {
      // Check if standard ports are leaking version info (e.g. Apache/2.4.7)
      const hasVersions = portsArray.some(p => /\d+\.\d+/.test(p) && !p.toLowerCase().includes("cloudflare"));
      const hasCloudflare = portsArray.some(p => p.toLowerCase().includes("cloudflare") || p.toLowerCase().includes("proxy"));

      if (hasVersions) {
        score = 40; // Medium risk if version headers are exposed
        evidence.push("Standard web ports are open but are exposing specific service version information, which is a security risk.");
      } else if (hasCloudflare) {
        score = 5;
        evidence.push("Cloudflare/Proxy protection detected. Target is shielded by a security layer.");
      } else {
        score = 10;
        evidence.push("Only standard web ports (80, 443) are open — expected behaviour for a web server.");
      }
    } else {
      score = Math.min(nonStandardPorts.length * 10 + cveCount * 15, 85);
      if (nonStandardPorts.length > 0)
        evidence.push(
          `${nonStandardPorts.length} non-standard port(s) are exposed.`
        );
      if (onlyStandardPorts)
        evidence.push("Standard web ports (80, 443) are open.");
      if (cveCount > 0)
        evidence.push(`${cveCount} CVE references were found in output.`);
    }
  }

  if (scan.scanType === "ssl") {
    const critical = Number((r.criticalIssues || []).length);
    const total = Number(r.totalIssues || 0);
    score = Math.min(critical * 18 + total * 5 + 20, 84);

    if (critical > 0)
      evidence.push(`${critical} critical TLS/certificate issues were detected.`);
    if (total === 0) evidence.push("No TLS issues were detected.");
  }

  let level = "low";
  if (score >= 80) level = "critical";
  else if (score >= 60) level = "high";
  else if (score >= 35) level = "medium";

  return {
    score,
    level,
    evidence,
    safeDemoSteps: [
      "Show the original scanner evidence and timestamp in the dashboard.",
      "Confirm written user consent before any impact demonstration action.",
      "Run only non-invasive validation checks on your own demo target.",
      "Explain business impact with CVSS-style severity and remediation plan.",
      "Do not execute payloads or exploit code in this platform.",
    ],
  };
}

export async function startScan(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { targetUrl, scanType, cookies, scanMode = "quick", sqlmapUrl } = req.body || {};
    if (!targetUrl || !scanType) {
      return res.status(400).json({ success: false, error: "targetUrl and scanType are required" });
    }

    if (scanType !== "all" && !ALLOWED_SCANS.includes(scanType)) {
      return res.status(400).json({ success: false, error: "Invalid scanType" });
    }

    const validation = urlValidation(targetUrl);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }
    const finalUrl = validation.url;

    // Validate sqlmapUrl if provided
    let finalSqlmapUrl = sqlmapUrl;
    if (sqlmapUrl) {
      const sqlmapValidation = urlValidation(sqlmapUrl);
      if (!sqlmapValidation.valid) {
        return res.status(400).json({ success: false, error: "Invalid SQLMap URL: " + sqlmapValidation.error });
      }
      finalSqlmapUrl = sqlmapValidation.url;
    }

    // Domain Blacklist Check - Protect major public infrastructure
    const hostname = new URL(finalUrl).hostname.toLowerCase();
    
    // Explicitly allow localhost and local testing ips
    const isLocal = hostname === 'localhost' || hostname === '127.0.0.1' || hostname.startsWith('192.168.') || hostname.startsWith('10.');

    if (!isLocal) {
      // Common, gov, social media, and major tech websites
      const strictlyProhibited = [
        'netflix.com', 'amazon.com', 'apple.com', 'microsoft.com', 'google.com', 'facebook.com', 
        'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'github.com', 'youtube.com',
        'yahoo.com', 'bing.com', 'fbi.gov', 'gov', 'mil', 'edu'
      ];
      
      const isProhibited = strictlyProhibited.some(domain => 
        hostname === domain || hostname.endsWith(`.${domain}`)
      );
      
      // Additional TLD check for gov/mil/edu
      const isProhibitedTld = hostname.endsWith('.gov') || hostname.endsWith('.mil') || hostname.endsWith('.edu');

      if (isProhibited || isProhibitedTld) {
        return res.status(403).json({ 
          success: false, 
          error: "Ethical boundaries: Scanning major public infrastructure, government, or social media websites is strictly prohibited. If you want to test vulnerabilities, please use authorized testing websites like http://testphp.vulnweb.com/ or a local DVWA container." 
        });
      }

      // DNS Verification System: ensure domain actually resolves
      try {
        await dns.lookup(hostname);
      } catch (dnsError) {
        return res.status(400).json({ 
          success: false, 
          error: `DNS Verification Failed: The domain '${hostname}' could not be resolved. Please enter a valid and active website.` 
        });
      }
    }

    const quota = await checkScanQuota(userId, scanType);
    if (!quota.ok) {
      return res.status(quota.code).json({
        success: false,
        error: quota.error,
        quota: quota.quota,
      });
    }

    const duplicateQuery = {
      userId,
      targetUrl: finalUrl,
      status: { $in: ["pending", "running"] },
      scanType: scanType === "all" ? { $in: ALLOWED_SCANS } : scanType,
    };

    const existing = await Scan.findOne(duplicateQuery).lean();
    if (existing) {
      return res.status(409).json({
        success: false,
        error: "A scan for this target is already pending/running",
        scanId: existing._id,
        status: existing.status,
      });
    }

    if (scanType === "all") {
      const batchId = randomUUID();
      
      // 1. SMART SCAN INTELLIGENCE LAYER: Run lightweight recon
      let reconData;
      const providedDetection = req.body?.options?.detectionData;
      try {
        if (providedDetection && typeof providedDetection === "object") {
          reconData = {
            hasLoginForm: Boolean(providedDetection.hasLoginForm),
            hasInputForms: Boolean(providedDetection.hasInputForms),
            hasSSL: Boolean(providedDetection.hasSSL),
            platform: providedDetection.platform || null,
            technologies: Array.isArray(providedDetection.technologies) ? [...providedDetection.technologies] : [],
            openPorts: Array.isArray(providedDetection.openPorts) ? [...providedDetection.openPorts] : [],
            isAlive: Boolean(providedDetection.isAlive),
            isStaticFrontend: Boolean(providedDetection.isStaticFrontend),
            evidence: {
              headers: providedDetection.evidence?.headers || {},
              htmlIndicators: Array.isArray(providedDetection.evidence?.htmlIndicators) ? [...providedDetection.evidence.htmlIndicators] : [],
              formCount: Number(providedDetection.evidence?.formCount || 0),
            },
          };
        } else {
          reconData = await extractReconData(finalUrl);
        }
      } catch (reconError) {
        console.warn("[SCAN_ORCHESTRATOR] Recon failed, falling back:", reconError?.message || reconError);
        reconData = { isAlive: false, openPorts: [], evidence: { htmlIndicators: [] } };
      }

      // 2. Generate Scan Plan based on recon.
      // Auto-scan should use the full smart sequence on normal websites, while
      // frontend-only targets are trimmed to the frontend-safe toolset.
      const decisionMode = scanMode === "full" ? "deep" : scanMode;
      const executionPlan = decideScanPlan(reconData, decisionMode || "quick");
      const availability = await computeToolAvailability();
      const availableRun = executionPlan.run.filter((tool) => availability.byTool[tool] !== false);
      const missingRun = executionPlan.run.filter((tool) => availability.byTool[tool] === false);
      const mergedSkip = Array.from(new Set([...(executionPlan.skip || []), ...missingRun]));
      const planDetails = { ...executionPlan.details };

      for (const tool of missingRun) {
        planDetails[tool] = {
          decision: "skip",
          reason: "Tool unavailable on server",
          confidence: 1,
          evidence: ["Binary or script missing"],
        };
      }

      const scanPlan = {
        run: ["platform", ...availableRun],
        skip: mergedSkip,
        details: {
          platform: {
            decision: "run",
            reason: reconData.isAlive
              ? "Detect website type before the security tools run"
              : "Host was not confirmed reachable, so the fallback scan plan is used",
            confidence: 1,
            evidence: reconData.evidence?.htmlIndicators || [],
          },
          ...planDetails,
        },
      };
      
      // We only insert documents for the tools we decided to RUN
      const scanDocs = availableRun.map((tool) => ({
        userId,
        targetUrl: finalUrl,
        scanType: tool,
        status: "pending",
        scanPlan: {
          run: scanPlan.run,
          skip: scanPlan.skip,
          details: scanPlan.details
        },
        results: {
          batchId,
          mode: "all-tools",
          scanMode,
        },
      }));

      const createdScans = await Scan.insertMany(scanDocs);
      
      await User.findByIdAndUpdate(userId, {
        $inc: { usedScan: 1 },
      });

      res.status(201).json({
        success: true,
        message: "Smart batch scan started",
        mode: "all-tools",
        batchId,
        scanPlan, // Send transparency data to the frontend immediately
        scans: createdScans.map((s) => ({
          _id: s._id,
          scanType: s.scanType,
          targetUrl: s.targetUrl,
          status: s.status,
        })),
        quota: quota.quota,
      });

      // Launch tools sequentially in background
      (async () => {
        try {
          for (const scan of createdScans) {
            try {
              await Scan.findByIdAndUpdate(scan._id, { status: "running", startedAt: new Date() });
              // Sequential execution ensures we don't saturate the server resources
              const toolSpecificSqlmapUrl = scan.scanType === "sqlmap" ? finalSqlmapUrl : "";
              await launchScanInBackground(String(scan._id), finalUrl, scan.scanType, cookies, scanMode, toolSpecificSqlmapUrl);
            } catch (toolError) {
              console.error(`[SCAN_ORCHESTRATOR] Tool ${scan.scanType} failed to launch:`, toolError);
              await Scan.findByIdAndUpdate(scan._id, {
                status: "failed",
                results: { ...(scan.results || {}), error: "Tool launch failed" },
                updatedAt: new Date(),
                completedAt: new Date(),
              });
            }
          }
        } catch (bgError) {
          console.error("[SCAN_ORCHESTRATOR] Critical failure in background loop:", bgError);
        }
      })();

      return;
    }

      const scanDoc = await Scan.create({
      userId,
      targetUrl: finalUrl,
      scanType,
      status: "running",
      startedAt: new Date(),
      results: { scanMode },
    });

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $inc: { usedScan: 1 } },
      { new: true }
    )
      .select("usedScan scanLimit")
      .lean();

    res.status(201).json({
      success: true,
      message: "Scan started",
      scanId: scanDoc._id,
      scan: {
        _id: scanDoc._id,
        targetUrl: finalUrl,
        scanType,
        status: scanDoc.status,
      },
      user: updatedUser
        ? {
            usedScan: updatedUser.usedScan,
            scanLimit: updatedUser.scanLimit,
          }
        : undefined,
      quota: quota.quota,
    });

    launchScanInBackground(String(scanDoc._id), finalUrl, scanType, cookies, scanMode, finalSqlmapUrl);
  } catch (error) {
    console.error("[startScan] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to start scan" });
  }
}

export async function getScanHistory(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const scans = await Scan.find({ userId }).sort({ createdAt: -1 });
    return res.json({ success: true, scans });
  } catch (error) {
    console.error("[getScanHistory] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to fetch scan history" });
  }
}

export async function getScanResultsById(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    const scanId = req.params.id;

    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const scan = await Scan.findOne({ _id: scanId, userId });
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    return res.json({ success: true, scan });
  } catch (error) {
    console.error("[getScanResultsById] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to fetch scan result" });
  }
}

export async function getBatchResults(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    const batchId = req.params.batchId;

    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const scans = await Scan.find({
      userId,
      "results.batchId": batchId,
    }).sort({ createdAt: -1 });

    if (!scans.length) {
      return res.status(404).json({ success: false, error: "Batch not found" });
    }

    return res.json({
      success: true,
      batchId,
      total: scans.length,
      scans,
    });
  } catch (error) {
    console.error("[getBatchResults] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to fetch batch results" });
  }
}

export async function cancelScan(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    const scanId = req.params.id;

    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const scan = await Scan.findOne({ _id: scanId, userId });
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    if (["completed", "failed", "cancelled"].includes(scan.status)) {
      return res.json({ success: true, message: `Scan already ${scan.status}` });
    }

    const batchId = scan?.results?.batchId;
    if (batchId) {
      const batchScans = await Scan.find({
        userId,
        "results.batchId": batchId,
        status: { $in: ["pending", "running"] },
      }).select("_id status");

      let cancelledCount = 0;
      for (const batchScan of batchScans) {
        const killResult = await killProcess(String(batchScan._id), `Cancelled by user ${userId}`);
        if (!killResult.killed) {
          await Scan.findByIdAndUpdate(batchScan._id, {
            status: "cancelled",
            results: {
              cancelled: true,
              error: "Cancelled by user (no active process found)",
            },
            updatedAt: new Date(),
            completedAt: new Date(),
          });
        }
        cancelledCount += 1;
      }

      return res.json({
        success: true,
        message: `Cancelled ${cancelledCount} scan(s) in this batch`,
        batchId,
      });
    }

    const result = await killProcess(scanId, `Cancelled by user ${userId}`);
    if (result.killed) {
      return res.json({ success: true, message: "Scan cancelled successfully" });
    }

    await Scan.findByIdAndUpdate(scanId, {
      status: "cancelled",
      results: {
        ...(scan.results || {}),
        cancelled: true,
        error: "Cancelled by user (no active process found)",
      },
      updatedAt: new Date(),
      completedAt: new Date(),
    });

    return res.json({ success: true, message: "Scan marked cancelled" });
  } catch (error) {
    console.error("[cancelScan] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to cancel scan" });
  }
}

export async function startImpactDemo(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    const scanId = req.params.id;
    const { consent } = req.body || {};

    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    if (consent !== true) {
      return res.status(400).json({ success: false, error: "User consent is required" });
    }

    const scan = await Scan.findOne({ _id: scanId, userId });
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    if (scan.status !== "completed") {
      return res.status(400).json({ success: false, error: "Scan is not completed yet" });
    }

    const impact = inferImpact(scan);
    const impactPayload = {
      enabled: true,
      consentGiven: true,
      generatedAt: new Date(),
      riskLevel: impact.level,
      criticalityScore: impact.score,
      evidence: impact.evidence,
      safeDemoSteps: impact.safeDemoSteps,
      note: "This platform provides non-invasive impact simulation only.",
    };

    scan.results = {
      ...(scan.results || {}),
      impactSimulation: impactPayload,
    };

    await scan.save();

    return res.json({ success: true, message: "Impact demonstration prepared", impact: impactPayload });
  } catch (error) {
    console.error("[startImpactDemo] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to generate impact demonstration" });
  }
}

export async function getImpactDemo(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    const scanId = req.params.id;

    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const scan = await Scan.findOne({ _id: scanId, userId }).lean();
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    const impact = scan.results?.impactSimulation;
    if (!impact) {
      return res.status(404).json({ success: false, error: "Impact demonstration not generated yet" });
    }

    return res.json({ success: true, impact });
  } catch (error) {
    console.error("[getImpactDemo] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to fetch impact demonstration" });
  }
}

export async function getTodayStats(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }
    const stats = await getTodayScanStats(userId);
    return res.json({ success: true, stats });
  } catch (error) {
    console.error("[getTodayStats] Error:", error);
    return res.status(500).json({ success: false, error: "Failed to fetch scan stats" });
  }
}

/**
 * Runs lightweight recon on the target and returns website type detection
 * Used by the frontend to show what kind of website it is before scanning
 */
export async function detectWebsite(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    if (!userId) return res.status(401).json({ success: false, error: "Unauthorized" });

    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: "URL is required" });

    const validation = urlValidation(url);
    if (!validation.valid) return res.status(400).json({ success: false, error: validation.error });

    const finalUrl = validation.url;
    const { extractReconData } = await import("../utils/reconDataExtractor.js");
    const { decideScanPlan } = await import("../utils/scanDecisionEngine.js");

    let reconData;
    try {
      reconData = await extractReconData(finalUrl);
    } catch (e) {
      reconData = { isAlive: false, openPorts: [], evidence: { htmlIndicators: [] } };
    }

    const quickPlan = decideScanPlan(reconData, "quick");
    const deepPlan  = decideScanPlan(reconData, "deep");

    let siteType = "Unknown";
    if (!reconData.isAlive) {
      siteType = "Unreachable";
    } else if (reconData.isStaticFrontend) {
      siteType = "Frontend Only";
    } else if (reconData.hasLoginForm || reconData.hasInputForms) {
      siteType = "Full Stack (Backend + Forms Detected)";
    } else {
      siteType = "Web Server (No Forms Detected)";
    }

    return res.json({
      success: true,
      detection: {
        isAlive: reconData.isAlive,
        siteType,
        hasSSL: reconData.hasSSL,
        hasInputForms: reconData.hasInputForms,
        hasLoginForm: reconData.hasLoginForm,
        isStaticFrontend: reconData.isStaticFrontend,
        platform: reconData.platform,
        technologies: reconData.technologies,
        evidence: reconData.evidence,
      },
      quickPlan: { run: quickPlan.run, skip: quickPlan.skip, details: quickPlan.details },
      deepPlan:  { run: deepPlan.run,  skip: deepPlan.skip,  details: deepPlan.details },
    });
  } catch (error) {
    console.error("[detectWebsite] Error:", error);
    return res.status(500).json({ success: false, error: "Detection failed" });
  }
}

/**
 * Runs a DNS lookup synchronously and returns results inline (no scan pipeline)
 * Used by the frontend DNS Lookup inline tool - no progress page needed
 */
export async function dnsLookupInline(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    if (!userId) return res.status(401).json({ success: false, error: "Unauthorized" });

    const { hostname } = req.body;
    if (!hostname || !hostname.trim()) {
      return res.status(400).json({ success: false, error: "Hostname is required" });
    }

    const clean = hostname.trim().replace(/^https?:\/\//i, "").split("/")[0];

    const scriptPath = path.join(process.cwd(), "src", "utils", "dns-verify.js");
    try {
      const { stdout } = await execPromise(`node ${JSON.stringify(scriptPath)} ${JSON.stringify(clean)}`, { timeout: 15000 });
      // dns-verify.js outputs JSON.stringify(results)
      let records = {};
      const match = stdout.match(/\{[\s\S]+\}/);
      if (match) {
        try { records = JSON.parse(match[0]); } catch { records = { raw: stdout }; }
      } else {
        records = { raw: stdout };
      }
      return res.json({ success: true, hostname: clean, records });
    } catch (execErr) {
      return res.status(500).json({ success: false, error: `DNS lookup failed: ${execErr.message}` });
    }
  } catch (error) {
    console.error("[dnsLookupInline] Error:", error);
    return res.status(500).json({ success: false, error: "DNS lookup failed" });
  }
}

/**
 * Runs a WHOIS lookup synchronously and returns results inline
 */
export async function whoisLookupInline(req, res) {
  try {
    const userId = getUserIdFromRequest(req);
    if (!userId) return res.status(401).json({ success: false, error: "Unauthorized" });

    const { hostname } = req.body;
    if (!hostname || !hostname.trim()) {
      return res.status(400).json({ success: false, error: "Hostname is required" });
    }

    const clean = hostname.trim().replace(/^https?:\/\//i, "").split("/")[0];
    const domainParts = clean.split(".");
    const baseDomain = domainParts.slice(-2).join(".");

    try {
      const { stdout } = await execPromise(`whois ${JSON.stringify(baseDomain)}`, { timeout: 15000 });
      return res.json({ success: true, hostname: clean, baseDomain, data: stdout.slice(0, 6000) });
    } catch (execErr) {
      return res.status(500).json({ success: false, error: `WHOIS lookup failed: ${execErr.message}` });
    }
  } catch (error) {
    console.error("[whoisLookupInline] Error:", error);
    return res.status(500).json({ success: false, error: "WHOIS lookup failed" });
  }
}
