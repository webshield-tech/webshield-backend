import { Notification } from "../models/notifications-mongoose.js";
import { User } from "../models/users-mongoose.js";

const RESET_TITLE = "Daily scan limits reset";
const RESET_MESSAGE = "Your daily scan limit has been reset. You can start new scans again.";

// Reset policy: reset exactly 24 hours after the start of the user quota window.
// The field `lastScanQuotaResetAt` stores the timestamp when the current quota window began.
// - If `lastScanQuotaResetAt` is null => initialize it to now (first scan moment) and do NOT reset counters.
// - If now >= lastScanQuotaResetAt + 24h => reset usedScan to 0 and set lastScanQuotaResetAt = now and notify user.

export async function ensureDailyScanReset(userId) {
  if (!userId) {
    return { resetApplied: false, user: null };
  }

  const user = await User.findById(userId)
    .select("usedScan scanLimit lastScanQuotaResetAt")
    .lean();

  if (!user) {
    return { resetApplied: false, user: null };
  }

  const now = new Date();
  const lastWindow = user.lastScanQuotaResetAt ? new Date(user.lastScanQuotaResetAt) : null;

  // If never initialized, set the window start to now and do not reset counters
  if (!lastWindow) {
    await User.updateOne(
      { _id: userId },
      { $set: { lastScanQuotaResetAt: now } }
    );
    return { resetApplied: false, user: { ...user, lastScanQuotaResetAt: now } };
  }

  const msIn24h = 24 * 60 * 60 * 1000;
  const elapsed = now.getTime() - lastWindow.getTime();

  // Not yet 24 hours => nothing to do
  if (elapsed < msIn24h) {
    return { resetApplied: false, user };
  }

  // It's been >=24h since the quota window started -> reset counters and start a new window
  await User.updateOne(
    { _id: userId },
    {
      $set: {
        usedScan: 0,
        lastScanQuotaResetAt: now,
      },
    }
  );

  // Notify the user only if they consumed any scans in the previous window
  if ((user.usedScan || 0) > 0) {
    const existingNotification = await Notification.findOne({
      userId,
      type: "info",
      title: RESET_TITLE,
      // ensure we don't duplicate notifications within a short period
      createdAt: { $gte: new Date(now.getTime() - 60 * 60 * 1000) },
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
      lastScanQuotaResetAt: now,
    },
  };
}