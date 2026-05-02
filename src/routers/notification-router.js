import { Router } from "express";
import {
  getNotifications,
  markAllNotificationsRead,
  deleteNotification,
  sendAnnouncement,
} from "../controllers/notification-controller.js";
import { checkUserAuth } from "../middlewares/user-auth.js";
import { checkAdmin } from "../middlewares/admin-auth.js";

export const notificationRouter = Router();

// User endpoints (require authentication)
notificationRouter.get("/", checkUserAuth, getNotifications);
notificationRouter.post("/read-all", checkUserAuth, markAllNotificationsRead);
notificationRouter.delete("/:notificationId", checkUserAuth, deleteNotification);

// Admin endpoints (require admin auth)
notificationRouter.post("/announce", checkAdmin, sendAnnouncement);

export default notificationRouter;
