import { Scan } from "../models/scans-mongoose.js";
import { User } from "../models/users-mongoose.js";

export async function refundFailedScanQuota(scanId) {
  try {
    const scan = await Scan.findOne({
      _id: scanId,
      quotaRefunded: { $ne: true },
    })
      .select("userId results.mode")
      .lean();

    if (!scan?.userId) return;
    if (scan?.results?.mode === "all-tools") return;

    const markResult = await Scan.updateOne(
      { _id: scanId, quotaRefunded: { $ne: true } },
      { $set: { quotaRefunded: true } }
    );

    if (!markResult.modifiedCount) return;

    await User.updateOne(
      { _id: scan.userId, usedScan: { $gt: 0 } },
      { $inc: { usedScan: -1 } }
    );
  } catch (error) {
    console.error("[scan-quota] failed to refund usedScan:", error);
  }
}
