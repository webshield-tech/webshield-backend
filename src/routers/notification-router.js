import { Router } from "express";
import {
  getNotifications,
  markAllNotificationsRead,
  deleteNotification,
  sendAnnouncement,
} from "../controllers/notification-controller.js";
import { checkAuth } from "../middlewares/user-auth.js";
import { checkAdmin } from "../middlewares/admin-auth.js";

export const notificationRouter = Router();

// User endpoints (require authentication)
notificationRouter.get("/", checkAuth, getNotifications);
notificationRouter.post("/read-all", checkAuth, markAllNotificationsRead);
notificationRouter.delete("/:notificationId", checkAuth, deleteNotification);

// Admin endpoints (require admin auth)
notificationRouter.post("/announce", checkAuth, checkAdmin, sendAnnouncement);

export default notificationRouter;
