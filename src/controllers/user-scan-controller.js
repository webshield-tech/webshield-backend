import axios from "axios";
import https from "https";
import { randomUUID } from "crypto";
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

const ALLOWED_SCANS = ["nmap", "nikto", "ssl", "sqlmap"];
const DAILY_PER_TOOL_LIMIT = 10;
const DAILY_AUTO_LIMIT = 5;

/**
 * MANUAL PING CHECK: Endpoint to let user check if target is alive
 */
export async function pingTarget(req, res) {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: "URL is required" });

    const validation = urlValidation(url);
    if (!validation.valid) return res.status(400).json({ success: false, error: validation.error });
    
    // Extract clean domain/hostname to ensure we are checking the target's availability, not a specific path
    let domain;
    try {
      domain = new URL(validation.url).hostname;
    } catch (e) {
      domain = validation.url.replace(/^https?:\/\//, '').split('/')[0];
    }

    const finalUrl = `http://${domain}`; // We use HTTP as a baseline availability check
    const fallbackUrl = `https://${domain}`;
    try {
      // Use a common browser User-Agent to avoid being blocked by WAFs during ping
      const config = {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 5,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      };

      try {
        await axios.get(finalUrl, config);
      } catch (getErr) {
        try {
          // If HTTP fails, try HTTPS
          await axios.get(fallbackUrl, config);
        } catch (httpsErr) {
          // If both GETs fail, try one last HEAD request on HTTPS
          await axios.head(fallbackUrl, config);
        }
      }
      
      return res.json({ success: true, message: "Target is reachable and alive.", domain });
    } catch (error) {
      console.error(`[pingTarget] Host ${domain} is unreachable:`, error.message);
      return res.status(503).json({ 
        success: false, 
        error: `Target Unreachable: ${domain} is not responding. Ensure the domain is correct.` 
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
  const hostname = new URL(url).hostname;
  validateHostname(hostname);
  return hostname;
}

function resolveSslTarget(url) {
  const parsed = new URL(url);
  validateHostname(parsed.hostname);
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

async function getScanCommand(scanType, finalUrl, cookies = "", scanMode = "quick") {
  const hostname = resolveHostname(finalUrl);

  if (scanType === "nmap") {
    let args = [];
    if (scanMode === "full") {
      args = ["-p-", "-sV", "-sC", "-v", "--max-retries", "1", "--host-timeout", "600s", hostname];
    } else {
      args = ["-F", "-sV", "-v", "--max-retries", "1", "--host-timeout", "240s", hostname];
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
    let args = ["-h", finalUrl, "-maxtime", scanMode === "full" ? "300s" : "120s", "-nointeractive"];
    if (scanMode === "quick") {
      args.push("-Tuning", "x"); 
    }
    return {
      executable: "nikto",
      args,
      opts: { timeoutMs: scanMode === "full" ? 360000 : 180000 },
    };
  }

  if (scanType === "ssl") {
    return {
      executable: "sslscan",
      args: ["--no-colour", "--show-certificate", resolveSslTarget(finalUrl)],
      opts: { timeoutMs: 120000, maxRaw: 200000 },
    };
  }

  if (scanType === "sqlmap") {
    let sqlmapTarget = buildSqlmapTarget(finalUrl);
    let sqlmapCookies = cookies || "";

    // Local DVWA convenience: auto-login and use SQLi endpoint if user passed only base URL.
    if (!sqlmapCookies && !finalUrl.includes("?")) {
      try {
        const dvwa = await prepareDvwaSqlmapContext(finalUrl);
        if (dvwa?.sqlmapTarget) {
          sqlmapTarget = dvwa.sqlmapTarget;
          sqlmapCookies = dvwa.cookies || "";
        }
      } catch (dvwaErr) {
        console.warn("[sqlmap] DVWA context prep skipped:", dvwaErr?.message || dvwaErr);
      }
    }

    const level = scanMode === "full" ? "5" : "2";
    const risk  = scanMode === "full" ? "3" : "1";

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
      "--disable-coloring",
      "--output-dir", "/tmp/sqlmap-output",
    ];

    if (scanMode === "full") {
      args.push("--forms", "--crawl", "3", "--dump-all");
    } else {
      args.push("--forms", "--crawl", "1");
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

  throw new Error("Unsupported scan type");
}

function launchScanInBackground(scanId, finalUrl, scanType, cookies = "", scanMode = "quick") {
  return new Promise(async (resolve) => {
    try {
      if (hasProcess(scanId)) {
        return resolve({ success: false, error: "Already running" });
      }

      console.log(`[SCAN_SERVICE] Starting ${scanType} scan (Mode: ${scanMode}) for: ${finalUrl} (ID: ${scanId})`);

      const command = await getScanCommand(scanType, finalUrl, cookies, scanMode);
      
      command.opts.onComplete = (id, status, parsed) => {
        resolve({ success: status === "completed", status, parsed });
      };

      const started = await startProcess(
        scanId,
        command.executable,
        command.args,
        command.opts
      );

      if (!started.started) {
        throw new Error(started.error || "Failed to start scan process");
      }
    } catch (error) {
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
    }
  });
}

async function getTodayScanStats(userId) {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const scansToday = await Scan.find({
    userId,
    createdAt: { $gte: startOfDay },
  })
    .select("scanType results.batchId results.mode")
    .lean();

  const byTool = { nmap: 0, nikto: 0, ssl: 0, sqlmap: 0 };
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

  const singleUsed = byTool.nmap + byTool.nikto + byTool.ssl + byTool.sqlmap;
  return {
    byTool,
    autoUsed: autoBatchIds.size,
    singleUsed,
    singleLimit: DAILY_PER_TOOL_LIMIT * ALLOWED_SCANS.length,
  };
}

async function checkScanQuota(userId, scanType) {
  const user = await User.findById(userId)
    .select("scanLimit usedScan")
    .lean();

  if (!user) {
    return { ok: false, code: 404, error: "User not found" };
  }

  const stats = await getTodayScanStats(userId);

  if (scanType === "all") {
    if (stats.autoUsed >= DAILY_AUTO_LIMIT) {
      return {
        ok: false,
        code: 403,
        error: `Daily Auto Full Scan limit reached (${DAILY_AUTO_LIMIT}/${DAILY_AUTO_LIMIT}).`,
        quota: stats,
      };
    }
    return { ok: true, quota: stats };
  } else {
    const usedForTool = Number(stats.byTool[scanType] || 0);
    if (usedForTool >= DAILY_PER_TOOL_LIMIT) {
      return {
        ok: false,
        code: 403,
        error: `Daily ${scanType.toUpperCase()} limit reached (${DAILY_PER_TOOL_LIMIT}/${DAILY_PER_TOOL_LIMIT}).`,
        quota: stats,
      };
    }
    return { ok: true, quota: stats };
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
    const openPorts = Number((r.openPorts || []).length);
    const cveCount = Number((r.cveList || []).length);
    score = Math.min(openPorts * 8 + cveCount * 15 + 15, 85);

    if (openPorts > 0) evidence.push(`${openPorts} open ports are exposed.`);
    if (cveCount > 0)
      evidence.push(`${cveCount} CVE references were found in output.`);
    if (openPorts === 0) evidence.push("No open ports were detected.");
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

    const { targetUrl, scanType, cookies, scanMode = "quick" } = req.body || {};
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

    // Domain Blacklist Check - Protect major public infrastructure
    const hostname = new URL(finalUrl).hostname.toLowerCase();
    const strictlyProhibited = ['netflix.com', 'amazon.com', 'apple.com', 'microsoft.com'];
    if (strictlyProhibited.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
      return res.status(403).json({ 
        success: false, 
        error: "Ethical boundaries: Scanning major public infrastructure is strictly prohibited." 
      });
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
      const scanDocs = ALLOWED_SCANS.map((tool) => ({
        userId,
        targetUrl: finalUrl,
        scanType: tool,
        status: "pending",
        results: {
          batchId,
          mode: "all-tools",
          scanMode,
        },
      }));

      const createdScans = await Scan.insertMany(scanDocs);
      
      await User.findByIdAndUpdate(userId, {
        $set: { usedScan: quota.quota.singleUsed },
      });

      res.status(201).json({
        success: true,
        message: "All tools scan started",
        mode: "all-tools",
        batchId,
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
            await Scan.findByIdAndUpdate(scan._id, { status: "running", startedAt: new Date() });
            // Sequential execution ensures we don't saturate the server resources
            await launchScanInBackground(String(scan._id), finalUrl, scan.scanType, cookies, scanMode);
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
      { $set: { usedScan: quota.quota.singleUsed + 1 } },
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

    launchScanInBackground(String(scanDoc._id), finalUrl, scanType, cookies, scanMode);
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
