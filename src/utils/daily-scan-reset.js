import { Notification } from "../models/notifications-mongoose.js";
import { User } from "../models/users-mongoose.js";

const RESET_TITLE = "Daily scan limits reset";
const RESET_MESSAGE = "Your scan limits have reset for today. You can start new scans now.";

function getStartOfDay() {
  // Use UTC midnight to ensure consistent reset across all server timezones
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
}

export async function ensureDailyScanReset(userId) {
  if (!userId) {
    return { resetApplied: false, user: null };
  }

  const startOfDay = getStartOfDay();
  const user = await User.findById(userId)
    .select("usedScan scanLimit lastScanQuotaResetAt")
    .lean();

  if (!user) {
    return { resetApplied: false, user: null };
  }

  const lastReset = user.lastScanQuotaResetAt ? new Date(user.lastScanQuotaResetAt) : null;
  const needsReset = !lastReset || lastReset < startOfDay;

  if (!needsReset) {
    return { resetApplied: false, user };
  }

  await User.updateOne(
    { _id: userId },
    {
      $set: {
        usedScan: 0,
        lastScanQuotaResetAt: startOfDay,
      },
    }
  );

  if ((user.usedScan || 0) > 0) {
    const existingNotification = await Notification.findOne({
      userId,
      type: "info",
      title: RESET_TITLE,
      createdAt: { $gte: startOfDay },
    }).lean();

    if (!existingNotification) {
      await Notification.create({
        userId,
        type: "info",
        title: RESET_TITLE,
        message: RESET_MESSAGE,
        read: false,
      });
    }
  }

  return {
    resetApplied: true,
    user: {
      ...user,
      usedScan: 0,
      lastScanQuotaResetAt: startOfDay,
    },
  };
}