import express from "express";
import { checkAuth } from "../middlewares/user-auth.js";
import {
  startScan,
  getScanHistory,
  getScanResultsById,
  cancelScan,
} from "../controllers/user-scan-controller.js";
import {
  generateAIReportForScan,
  downloadReport,
  viewReport,
} from "../controllers/aiReport-controller.js";

const scanRouter = express.Router();
scanRouter.use(checkAuth);

scanRouter.post(
  "/start",
  async (req, res, next) => {
    console.log("=== SCAN START ===");
    console.log("User ID:", req.userId);
    console.log("Cookies:", req.cookies);
    next();
  },
  startScan,
);
scanRouter.get("/history", getScanHistory);
scanRouter.get("/:id", getScanResultsById);
scanRouter.post("/:id/cancel", cancelScan);

scanRouter.post("/:id/report/generate", generateAIReportForScan);
scanRouter.get("/:id/report/download", downloadReport);
scanRouter.get("/:id/report/view", viewReport);

export default scanRouter;
