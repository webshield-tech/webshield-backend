import { Notification } from "../models/notifications-mongoose.js";
import { User } from "../models/users-mongoose.js";

/**
 * Get all notifications for the current user
 */
export async function getNotifications(req, res) {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Unauthorized" });
    }

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    const unreadCount = await Notification.countDocuments({
      userId,
      read: false,
    });

    return res.json({
      success: true,
      notifications,
      unreadCount,
    });
  } catch (error) {
    console.error("[notification] getNotifications error:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Failed to fetch notifications",
    });
  }
}

/**
 * Mark all notifications as read
 */
export async function markAllNotificationsRead(req, res) {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Unauthorized" });
    }

    const result = await Notification.updateMany(
      { userId, read: false },
      { $set: { read: true } }
    );

    return res.json({
      success: true,
      message: "All notifications marked as read",
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("[notification] markAllNotificationsRead error:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Failed to mark notifications as read",
    });
  }
}

/**
 * Delete a specific notification
 */
export async function deleteNotification(req, res) {
  try {
    const userId = req.user?.userId;
    const notificationId = req.params.notificationId;

    if (!userId) {
      return res
        .status(401)
        .json({ success: false, error: "Unauthorized" });
    }

    if (!notificationId) {
      return res.status(400).json({
        success: false,
        error: "notificationId is required",
      });
    }

    const notification = await Notification.findById(notificationId);
    if (!notification) {
      return res.status(404).json({
        success: false,
        error: "Notification not found",
      });
    }

    // Verify ownership
    if (notification.userId.toString() !== userId) {
      return res.status(403).json({
        success: false,
        error: "Forbidden",
      });
    }

    await Notification.findByIdAndDelete(notificationId);
    return res.json({
      success: true,
      message: "Notification deleted",
    });
  } catch (error) {
    console.error("[notification] deleteNotification error:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Failed to delete notification",
    });
  }
}

/**
 * (ADMIN) Send announcement to specific users or all users
 */
export async function sendAnnouncement(req, res) {
  try {
    const adminRole = req.user?.role;
    if (adminRole !== "admin" && adminRole !== "superadmin") {
      return res.status(403).json({
        success: false,
        error: "Admin access required",
      });
    }

    const { title, message, type = "info", recipientUserIds = null } = req.body;

    if (!title || !message) {
      return res.status(400).json({
        success: false,
        error: "title and message are required",
      });
    }

    let targetUsers;
    if (recipientUserIds && Array.isArray(recipientUserIds) && recipientUserIds.length > 0) {
      targetUsers = await User.find({ _id: { $in: recipientUserIds } }).select("_id").lean();
    } else {
      // Send to all users
      targetUsers = await User.find({}).select("_id").lean();
    }

    if (!targetUsers.length) {
      return res.status(400).json({
        success: false,
        error: "No target users found",
      });
    }

    const notificationDocs = targetUsers.map((user) => ({
      userId: user._id,
      type,
      title,
      message,
      read: false,
    }));

    const created = await Notification.insertMany(notificationDocs);

    console.log(
      `[admin] Sent announcement to ${created.length} users: "${title}"`
    );

    return res.json({
      success: true,
      message: `Announcement sent to ${created.length} users`,
      notificationCount: created.length,
    });
  } catch (error) {
    console.error("[notification] sendAnnouncement error:", error);
    return res.status(500).json({
      success: false,
      error: error.message || "Failed to send announcement",
    });
  }
}
