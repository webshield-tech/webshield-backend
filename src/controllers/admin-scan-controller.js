import { User } from "../models/users-mongoose.js";
import { Scan } from "../models/scans-mongoose.js";
import { killProcess } from "../services/scan-runner.js";

// ALL SCANS HISTORY FOR ADMIN 
export async function getAllScanHistory(req, res) {
  try {
    const allScans = await Scan.find({}).sort({ createdAt: -1 }).lean();

    return res.json({
      success: true,
      message: "All scan history retrieved",
      totalScans: allScans.length,
      scans: allScans,
    });
  } catch (error) {
    console.error("[admin] getAllScanHistory error:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Failed to fetch scan history",
    });
  }
}

//  USER SCAN HISTORY BY ID FROM ADMIN 
export async function getUserScanHistoryAdmin(req, res) {
  try {
    const userId = req.params.userId;
    if (!userId) {
      return res
        .status(400)
        .json({ success: false, error: "userId is required" });
    }

    const scans = await Scan.find({ userId }).sort({ createdAt: -1 }).lean();
    const user = await User.findById(userId)
      .select("username email role scanLimit createdAt")
      .lean();

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    return res.json({
      success: true,
      user: {
        userId: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        scanLimit: user.scanLimit,
        createdAt: user.createdAt,
      },
      totalScans: scans.length,
      scans,
    });
  } catch (error) {
    console.error("[admin] getUserScanHistoryAdmin error:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Failed to fetch user scan history",
    });
  }
}

//  DELETING A SCAN (FOR ADMIN) 
export async function removeScan(req, res) {
  try {
    const scanId = req.params.id;
    if (!scanId) {
      return res
        .status(400)
        .json({ success: false, error: "scanId is required" });
    }

    const scan = await Scan.findById(scanId);
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    // If running, attempt to kill the underlying process first
    if (scan.status === "running") {
      try {
        await killProcess(scanId, "Deleted by admin");
      } catch (e) {
        console.error("[admin] removeScan - killProcess error:", e);
        // continue to deletion even if kill failed - we log the error
      }
    }

    // Delete DB record
    await Scan.findByIdAndDelete(scanId);

    return res.json({
      success: true,
      message: "Scan deleted successfully",
      deletedScanId: scanId,
    });
  } catch (error) {
    console.error("[admin] removeScan error:", error);
    return res
      .status(500)
      .json({
        success: false,
        error: error.message || "Failed to delete scan",
      });
  }
}

//  UPGRADING USER'S SCAN LIMIT (FOR ADMIN) 
export async function upgradeUserScan(req, res) {
  try {
    const { userId, scanLimit } = req.body;

    if (!userId) {
      return res
        .status(400)
        .json({ success: false, error: "User ID is required" });
    }

    if (typeof scanLimit !== "number" || scanLimit < 0) {
      return res
        .status(400)
        .json({
          success: false,
          error: "scanLimit must be a non-negative number",
        });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: { scanLimit: scanLimit } },
      { new: true }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    return res.json({
      success: true,
      message: "User scan limit updated successfully",
      user: {
        userId: updatedUser._id,
        username: updatedUser.username,
        newScanLimit: updatedUser.scanLimit,
      },
    });
  } catch (error) {
    console.error("[admin] upgradeUserScan error:", error);
    return res
      .status(500)
      .json({
        success: false,
        error: error.message || "Failed to update user scan limit",
      });
  }
}

/* ADMIN STATS */
export async function getAdminStats(req, res) {
  try {
    // Basic counts
    const totalUsers = await User.countDocuments();
    const totalScans = await Scan.countDocuments();
    const activeScans = await Scan.countDocuments({
      status: { $in: ["pending", "running"] },
    });

    // Recent users and scans (limit to last 5 each to avoid huge payloads)
    const recentUsers = await User.find()
  .sort({ createdAt: -1 })
  .limit(5)
  .select("username email role createdAt")
  .lean();

    const recentScans = await Scan.find()
      .sort({ createdAt: -1 })
      .limit(20)
      .select("targetUrl scanType status createdAt userId")
      .populate({ path: "userId", select: "username email" })
      .lean();

    return res.json({
      success: true,
      totalUsers,
      totalScans,
      activeScans,
      recentUsers,
      recentScans,
    });
  } catch (error) {
    console.error("[admin] getAdminStats error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to fetch admin statistics",
    });
  }
}
