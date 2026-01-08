import { Scan } from "../models/scans-mongoose.js";
import { User } from "../models/users-mongoose.js";
import { urlValidation } from "../utils/validations/url-validation.js";
import {
  startProcess,
  killProcess,
  hasProcess,
} from "../services/scan-runner.js";
import { validateHostname } from "../utils/validations/hostname-validation.js";

const ALLOWED_SCANS = ["nmap", "nikto", "ssl", "sqlmap"];

// START NEW SCAN 
export async function startScan(req, res) {
  try {
    const userId = req.userId || req.user?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { targetUrl, scanType } = req.body || {};

    if (!targetUrl || !scanType) {
      return res
        .status(400)
        .json({ success: false, error: "targetUrl and scanType are required" });
    }

    // Validate scanType
    if (!ALLOWED_SCANS.includes(scanType)) {
      return res
        .status(400)
        .json({ success: false, error: "Invalid scanType" });
    }

    // Validate URL
    const validation = urlValidation(targetUrl);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }
    const finalUrl = validation.url;

    // Prevent duplicate concurrent scans for same user+target+type
    const existing = await Scan.findOne({
      userId,
      targetUrl: finalUrl,
      scanType,
      status: { $in: ["pending", "running"] },
    }).lean();

    if (existing) {
      // If there is an in-memory process for that scan id, return that info
      if (hasProcess(String(existing._id))) {
        return res.status(409).json({
          success: false,
          error: "A scan for this target and type is already running",
          scanId: existing._id,
          status: existing.status,
        });
      }

      // No in-memory process found but DB has pending/running - return conflict to avoid duplicate
      return res.status(409).json({
        success: false,
        error: "A scan for this target and type is already pending/running",
        scanId: existing._id,
        status: existing.status,
      });
    }

    // Create scan document with status pending
    const scanDoc = new Scan({
      userId,
      targetUrl: finalUrl,
      scanType,
      status: "pending",
      results: {},
    });

    const savedScan = await scanDoc.save();

    // Atomically increment user's usedScan and get updated user
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $inc: { usedScan: 1 } },
      { new: true }
    ).select("-password");

    // Mark scan as running and attach startedat
    await Scan.findByIdAndUpdate(savedScan._id, {
      status: "running",
      updatedAt: new Date(),
      startedAt: new Date(),
    });

    // Respond immediately with scanId
    res.status(201).json({
      success: true,
      message: "Scan started",
      scanId: savedScan._id,
      scan: {
        _id: savedScan._id,
        targetUrl: finalUrl,
        scanType,
        status: "running",
      },
      user: updatedUser
        ? {
            _id: updatedUser._id,
            usedScan: updatedUser.usedScan,
            scanLimit: updatedUser.scanLimit,
          }
        : undefined,
    });

    // Launch scanner in background using scan-runner
    (async () => {
      const scanId = savedScan._id.toString();
      try {
        // if process is already tracke, don't start another
        if (hasProcess(scanId)) {
          console.warn(
            `[startScan][background] process already exists for scan ${scanId}`
          );
          return;
        }

        let hostname;
        try {
          hostname = new URL(finalUrl).hostname;
          validateHostname(hostname);
        } catch (e) {
          // Fallback for non-URL inputs
          hostname = finalUrl
            .replace(/^https?:\/\//, "")
            .replace(/\/.*$/, "")
            .replace(/^www\./, "");
          validateHostname(hostname);
        }

        // Build executable + args for each scan type
        switch (scanType) {
          case "nmap": {
            const args = [
              "-Pn",
              "-T4",
              "-sV",
              "-sC",
              "-O",
              "-v",
              "--top-ports",
              "1000",
              "--max-retries",
              "1",
              "--host-timeout",
              "240s",
              hostname,
            ];
            await startProcess(scanId, "nmap", args, {
              timeoutMs: 360000,
              maxRaw: 400000,
            });
            break;
          }
          case "nikto": {
            const args = [
              "-h",
              hostname,
              "-port",
              "80",
              "-Tuning",
              "b", 
              "-maxtime",
              "120s",
              "-nointeractive",
            ];

            await startProcess(scanId, "nikto", args, { timeoutMs: 180000 });
            break;
          }
          case "ssl": {
            const args = ["--no-colour", hostname];
            await startProcess(scanId, "sslscan", args, {
              timeoutMs: 0, // No timeout (dangerous!)
              maxRaw: 10000,
            });
            break;
          } // Make sure to test with URLs that have parameters
     case "sqlmap": {
  // If there is already a parameter, just scan as is.
  if (finalUrl.includes("?")) {
    const args = [
      "-u",
      finalUrl,
      "--batch",
      "--smart",
      "--level", "5",
      "--risk", "3",
      "--threads", "3",
      "--forms",
      "--crawl", "3",
      "--no-cast",
      "--disable-coloring",
    ];
    await startProcess(scanId, "sqlmap", args, { timeoutMs: 185000 });
    break;
  }

  // If no parameter, try common parameter names!
  const commonParams = [
    "id", "userid", "user", "cat", "category", "pid", "prod", "product",
    "page", "q", "search", "type", "item", "order"
  ];

  // Schedule scans for each param, plus the original url with --crawl/forms
  for (const param of commonParams) {
    const guessedUrl = finalUrl.replace(/\/+$/, "") + `?${param}=1`;
    const args = [
      "-u",
      guessedUrl,
      "--batch",
      "--smart",
      "--level", "5",
      "--risk", "3",
      "--threads", "3",
      "--forms",
      "--crawl", "3",
      "--no-cast",
      "--disable-coloring",
    ];
    // You may want to record (or merge) the scan results!
    // For demo: await startProcess for first param only, or queue/merge results as desired.
    await startProcess(scanId, "sqlmap", args, { timeoutMs: 185000 });
    // BREAK after first for demo, or let it scan all params: remove break for advanced use.
    break;
  }

  // Also scan the base with crawl/forms as fallback (already included in args above!)
  break;
}
          default: {
            // should not happen
            await Scan.findByIdAndUpdate(scanId, {
              status: "failed",
              results: { error: "Unsupported scan type" },
              updatedAt: new Date(),
            });
          }
        }
        //scan-runner will update DB to completed/failed/cancelled on child close.
      } catch (err) {
        console.error(
          "[startScan][background] scan runner error:",
          err?.message || err
        );
        try {
          await Scan.findByIdAndUpdate(savedScan._id, {
            status: "failed",
            results: { error: err?.message || "Scan runner failed to start" },
            updatedAt: new Date(),
          });
        } catch (e) {
          console.error("[startScan][background] DB update error:", e);
        }
      }
    })();
  } catch (error) {
    console.error("[startScan] Error:", error);
    res.status(500).json({ success: false, error: "Failed to start scan" });
  }
}

//  GET USER SCAN HISTORY 
export async function getScanHistory(req, res) {
  try {
    const userId = req.userId || req.user?.userId;
    if (!userId)
      return res.status(401).json({ success: false, error: "Unauthorized" });

    const scans = await Scan.find({ userId }).sort({ createdAt: -1 });
    res.json({ success: true, scans });
  } catch (error) {
    console.error("[getScanHistory] Error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch scan history" });
  }
}

// GET SCAN RESULTS BY ID 
export async function getScanResultsById(req, res) {
  try {
    const userId = req.userId || req.user?.userId;
    const scanId = req.params.id;

    if (!userId)
      return res.status(401).json({ success: false, error: "Unauthorized" });

    const scan = await Scan.findOne({ _id: scanId, userId: userId });

    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    res.json({ success: true, scan });
  } catch (error) {
    console.error("[getScanResultsById] Error:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch scan result" });
  }
}

// CANCEL SCAN 
export async function cancelScan(req, res) {
  try {
    const userId = req.userId || req.user?.userId;
    const scanId = req.params.id;

    if (!userId)
      return res.status(401).json({ success: false, error: "Unauthorized" });

    const scan = await Scan.findOne({ _id: scanId, userId: userId });

    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    // If scan is already completed/failed/cancelled
    if (["completed", "failed", "cancelled"].includes(scan.status)) {
      return res.json({
        success: true,
        message: `Scan already ${scan.status}`,
      });
    }

    // Attempt to kill an active process (if exists)
    try {
      const result = await killProcess(scanId, `Cancelled by user ${userId}`);
      if (result.killed) {
        return res.json({
          success: true,
          message: "Scan cancelled successfully",
        });
      } else {
        // No running process found, still mark cancelled
        await Scan.findByIdAndUpdate(scanId, {
          status: "cancelled",
          results: {
            cancelled: true,
            error: "Cancelled by user (no active process found)",
          },
          updatedAt: new Date(),
        });
        return res.json({
          success: true,
          message: "Scan marked cancelled (no active process found)",
        });
      }
    } catch (err) {
      console.error("[cancelScan] killProcess error:", err);
      // fallback: mark cancelled in DB
      await Scan.findByIdAndUpdate(scanId, {
        status: "cancelled",
        results: {
          cancelled: true,
          error: "Cancelled by user (kill attempt failed)",
        },
        updatedAt: new Date(),
      });
      return res
        .status(500)
        .json({ success: false, error: "Failed to cancel scan process" });
    }
  } catch (error) {
    console.error("[cancelScan] Error:", error);
    res.status(500).json({ success: false, error: "Failed to cancel scan" });
  }
}
