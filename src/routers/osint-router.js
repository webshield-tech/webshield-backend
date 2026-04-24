import express from "express";
import { generateOsint } from "../controllers/osint-controller.js";
import { checkAuth } from "../middlewares/user-auth.js";

const router = express.Router();

router.post("/", checkAuth, generateOsint);

export default router;
