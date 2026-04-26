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

function getScanCommand(scanType, finalUrl, cookies = "", scanMode = "quick") {
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
      args.push("-Tuning", "x"); // Quick tuning
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
      args: ["--no-colour", "--show-certificate", hostname],
      opts: { timeoutMs: 120000, maxRaw: 200000 },
    };
  }

  if (scanType === "sqlmap") {
    const level = scanMode === "full" ? "5" : "2";
    const risk  = scanMode === "full" ? "3" : "1";

    // Core args that work reliably on real test sites (testphp.vulnweb.com etc.)
    const args = [
      "-u", buildSqlmapTarget(finalUrl),
      "--batch",              // non-interactive
      "--level", level,
      "--risk",  risk,
      "--threads", "4",
      "--timeout", "30",      // per-request timeout in seconds
      "--retries", "2",       // retry on connection error
      "--random-agent",       // randomise User-Agent (helps bypass WAFs)
      "--technique", "BEUST", // Boolean, Error, Union, Stack, Time-based
      "--disable-coloring",
      "--output-dir", "/tmp/sqlmap-output",
    ];

    // For deep scan also crawl forms
    if (scanMode === "full") {
      args.push("--forms", "--crawl", "3", "--dump-all");
    } else {
      // Quick: scan forms and crawl 1 level to find forms/params on landing pages
      args.push("--forms", "--crawl", "1");
    }

    if (cookies) {
      args.push("--cookie", cookies);
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

      const command = getScanCommand(scanType, finalUrl, cookies, scanMode);
      
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
        console.error(`[SCAN_SERVICE] Failed to start process: ${started.error}`);
        throw new Error(started.error || "Failed to start scan process");
      }

      console.log(`[SCAN_SERVICE] Process initiated successfully for ID: ${scanId}`);
    } catch (error) {
      console.error("[SCAN_SERVICE] Runtime error:", error?.message || error);
      await Scan.findByIdAndUpdate(scanId, {
        status: "failed",
        results: { error: error?.message || "Scan failed to start" },
        updatedAt: new Date(),
        completedAt: new Date(),
      });
      await refundFailedScanQuota(scanId);
      resolve({ success: false, error: error?.message });
    }
  });
}

async function checkScanQuota(userId, requestedScans) {
  const user = await User.findById(userId)
    .select("scanLimit usedScan")
    .lean();

  if (!user) {
    return { ok: false, code: 404, error: "User not found" };
  }

  const used = Number(user.usedScan || 0);
  const limit = Number(user.scanLimit || 0);
  const remaining = Math.max(limit - used, 0);

  if (requestedScans > remaining) {
    return {
      ok: false,
      code: 403,
      error: `Daily scan limit reached (${limit}). Buy Premium to run more scans.`,
      remaining,
      scanLimit: limit,
      usedScan: used,
    };
  }

  return { ok: true, remaining, scanLimit: limit, usedScan: used };
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
      return res
        .status(400)
        .json({ success: false, error: "targetUrl and scanType are required" });
    }

    if (scanType !== "all" && !ALLOWED_SCANS.includes(scanType)) {
      return res.status(400).json({ success: false, error: "Invalid scanType" });
    }

    const validation = urlValidation(targetUrl);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }
    const finalUrl = validation.url;

    // Domain Blacklist Check (Ethical Boundaries)
    const hostname = new URL(finalUrl).hostname.toLowerCase();
    const blacklistedDomains = ['netflix.com', 'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com'];
    if (blacklistedDomains.some(domain => hostname.includes(domain))) {
      return res.status(403).json({ 
        success: false, 
        error: "Ethical boundaries breached: Scanning major public infrastructure like Netflix or Google is strictly prohibited." 
      });
    }

    const requestedScans = scanType === "all" ? ALLOWED_SCANS.length : 1;
    const quota = await checkScanQuota(userId, requestedScans);
    if (!quota.ok) {
      return res.status(quota.code).json({
        success: false,
        error: quota.error,
        remaining: quota.remaining,
        scanLimit: quota.scanLimit,
        usedScan: quota.usedScan,
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
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $inc: { usedScan: ALLOWED_SCANS.length } },
        { new: true }
      )
        .select("usedScan scanLimit")
        .lean();

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
        user: updatedUser
          ? {
              usedScan: updatedUser.usedScan,
              scanLimit: updatedUser.scanLimit,
            }
          : undefined,
      });

      // Run sequentially in background
      (async () => {
        for (const scan of createdScans) {
          await Scan.findByIdAndUpdate(scan._id, { status: "running", startedAt: new Date() });
          await launchScanInBackground(String(scan._id), finalUrl, scan.scanType, cookies, scanMode);
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
    return res
      .status(500)
      .json({ success: false, error: "Failed to fetch scan history" });
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
    return res
      .status(500)
      .json({ success: false, error: "Failed to fetch scan result" });
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
    return res
      .status(500)
      .json({ success: false, error: "Failed to fetch batch results" });
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
      return res.json({
        success: true,
        message: `Scan already ${scan.status}`,
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

    return res.json({
      success: true,
      message: "Scan marked cancelled (no active process found)",
    });
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
      return res.status(400).json({
        success: false,
        error: "User consent is required before impact demonstration",
      });
    }

    const scan = await Scan.findOne({ _id: scanId, userId });
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    if (scan.status !== "completed") {
      return res.status(400).json({
        success: false,
        error: "Scan is not completed yet",
        status: scan.status,
      });
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
      note: "This platform provides non-invasive impact simulation only. No active exploitation is executed.",
    };

    scan.results = {
      ...(scan.results || {}),
      impactSimulation: impactPayload,
    };

    await scan.save();

    return res.json({
      success: true,
      message: "Impact demonstration prepared",
      impact: impactPayload,
    });
  } catch (error) {
    console.error("[startImpactDemo] Error:", error);
    return res
      .status(500)
      .json({ success: false, error: "Failed to generate impact demonstration" });
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
      return res.status(404).json({
        success: false,
        error: "Impact demonstration not generated yet",
      });
    }

    return res.json({ success: true, impact });
  } catch (error) {
    console.error("[getImpactDemo] Error:", error);
    return res
      .status(500)
      .json({ success: false, error: "Failed to fetch impact demonstration" });
  }
}
