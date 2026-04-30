import express from "express";
import { getLatestExploits } from "../controllers/data-controller.js";

const router = express.Router();

// Public route to get latest exploits for the Learn section
router.get("/latest", getLatestExploits);

export default router;
