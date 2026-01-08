import { spawn } from "child_process";
import { Scan } from "../models/scans-mongoose.js";
import { parseByTool } from "./scan-parsers.js";

const processes = new Map();

export function hasProcess(scanId) {
  return processes.has(scanId);
}

export async function startProcess(scanId, executable, args = [], opts = {}) {
  if (processes.has(scanId)) {
    return { started: false, error: "Process already running for this scan" };
  }

  const maxRaw = opts.maxRaw || 200_000;
  const timeoutMs = opts.timeoutMs || 300_000;
  const logIntervalMs = opts.logIntervalMs || 2000;
  const maxPartial = opts.maxPartial || 50_000;

  try {
    const child = spawn(executable, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });

    const buffers = { stdout: "", stderr: "" };
    let timeoutTimer = null;
    let logInterval = null;

    timeoutTimer = setTimeout(() => {
      try {
        child.kill("SIGTERM");
      } catch (e) {}
    }, timeoutMs);

    // Periodic partial log writer
    logInterval = setInterval(async () => {
      try {
        const partial = buffers.stdout ? buffers.stdout.slice(-maxPartial) : "";
        if (partial) {
          await Scan.findByIdAndUpdate(scanId, {
            $set: { "results.partialOutput": partial, updatedAt: new Date() },
          });
        }
      } catch (e) {
        console.error("[scan-runner] partial log write failed:", e);
      }
    }, logIntervalMs);

  processes.set(scanId, {
  child,
  buffers,
  timeoutTimer,
  logInterval,
  executable,
  args,
  maxPartial,
  maxRaw,
  timeoutMs,
  logIntervalMs,
});
    child.stdout.on("data", (chunk) => {
      buffers.stdout += chunk.toString();
      if (buffers.stdout.length > maxRaw)
        buffers.stdout = buffers.stdout.slice(-maxRaw);
    });

    child.stderr.on("data", (chunk) => {
      buffers.stderr += chunk.toString();
      if (buffers.stderr.length > maxRaw)
        buffers.stderr = buffers.stderr.slice(-maxRaw);
    });

    child.on("close", async (code, signal) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (logInterval) clearInterval(logInterval);

      const procEntry = processes.get(scanId);
      const out =
        (procEntry && procEntry.buffers && procEntry.buffers.stdout) || "";
      const err =
        (procEntry && procEntry.buffers && procEntry.buffers.stderr) || "";

      processes.delete(scanId);

      try {
        if (signal === "SIGTERM") {
          const mp = procEntry?.maxPartial || 50000;
          await Scan.findByIdAndUpdate(scanId, {
            status: "cancelled",
            results: {
              cancelled: true,
              error: "Process terminated (SIGTERM)",
              rawOutput: out || err,
              partialOutput: out ? out.slice(-mp) : err.slice(-mp),
            },
            updatedAt: new Date(),
            completedAt: new Date(),
          });
          return;
        }

        const guessedTarget = procEntry?.args?.slice(-1)?.[0] || "";
        const parsed = parseByTool(executable, out || err, guessedTarget);

        let status = "completed";

if ((out || err).trim().length > 0) {
  status = "completed";
} else {
  status = "failed";
}

        await Scan.findByIdAndUpdate(scanId, {
          status: status,
          results: parsed,
          updatedAt: new Date(),
          completedAt: new Date(),
        });
      } catch (dbErr) {
        console.error("[scan-runner] DB update error on close:", dbErr);
        try {
          const mp = (procEntry && procEntry.maxPartial) || 50000;
          await Scan.findByIdAndUpdate(scanId, {
            status: "failed",
            results: {
              rawOutput: out || err,
              partialOutput: (out || err).slice(-mp),
              error: "DB update failed: " + (dbErr.message || "unknown"),
            },
            updatedAt: new Date(),
            completedAt: new Date(),
          });
        } catch (finalErr) {
          console.error("[scan-runner] Final DB update error:", finalErr);
        }
      }
    });

    child.on("error", async (err) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (logInterval) clearInterval(logInterval);
      processes.delete(scanId);
      try {
        const mp = processes.get(scanId)?.maxPartial || maxPartial;
        await Scan.findByIdAndUpdate(scanId, {
          status: "failed",
          results: {
            error: err.message,
            rawOutput: buffers.stdout || buffers.stderr,
            partialOutput: (buffers.stdout || buffers.stderr).slice(-mp),
          },
          updatedAt: new Date(),
          completedAt: new Date(),
        });
      } catch (dbErr) {
        console.error("[scan-runner] DB update error on spawn error:", dbErr);
      }
    });

    return { started: true, pid: child.pid };
  } catch (error) {
    return {
      started: false,
      error: error.message || "Failed to spawn process",
    };
  }
}

export async function killProcess(scanId, reason = "Killed by user") {
  const entry = processes.get(scanId);
  if (!entry) {
    try {
      await Scan.findByIdAndUpdate(scanId, {
        status: "cancelled",
        results: {
          cancelled: true,
          error: reason,
        },
        updatedAt: new Date(),
        completedAt: new Date(),
      });
    } catch (dbErr) {
      console.error(
        "[scan-runner] DB update error when killProcess had no entry:",
        dbErr
      );
    }
    return { killed: false, msg: "No running process found" };
  }

  try {
    if (entry.timeoutTimer) clearTimeout(entry.timeoutTimer);
    if (entry.logInterval) clearInterval(entry.logInterval);

    const mp = entry.maxPartial || 50000;

    entry.child.kill("SIGTERM");
    processes.delete(scanId);

    try {
      await Scan.findByIdAndUpdate(scanId, {
        status: "cancelled",
        results: {
          cancelled: true,
          error: reason,
          partialOutput: (entry.buffers?.stdout || "").slice(-mp),
        },
        updatedAt: new Date(),
        completedAt: new Date(),
      });
    } catch (dbErr) {
      console.error("[scan-runner] DB update error after kill:", dbErr);
    }

    return { killed: true };
  } catch (err) {
    return { killed: false, error: err.message || "Failed to kill process" };
  }
}

/**
 * Kill all running processes (used during graceful shutdown)
 */
export async function killAllProcesses() {
  const entries = Array.from(processes.keys());
  for (const scanId of entries) {
    try {
      await killProcess(scanId, "Server shutting down - killed");
    } catch (e) {
      console.error("[scan-runner] error killing during shutdown:", e);
    }
  }
  return entries.length;
}