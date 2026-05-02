import express from "express";
import dotenv from "dotenv";
import { connectDB } from "./config/database.js";
import userRouter from "./routers/users-router.js";
import cookieParser from "cookie-parser";
import scanRouter from "./routers/scans-router.js";
import authRouter from "./routers/auth-router.js";
import adminRouter from "./routers/admin-router.js";
import dataRouter from "./routers/data-router.js";
import notificationRouter from "./routers/notification-router.js";
import cors from "cors";
import rateLimit from "express-rate-limit";

import { seedAdmin } from "./utils/seed-admin.js";
import { killAllProcesses } from "./services/scan-runner.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;
app.set("trust proxy", 1);
const configuredFrontendUrl = process.env.FRONTEND_URL;
const allowAllCors = String(process.env.CORS_ALLOW_ALL || "").toLowerCase() === "true";
const envAllowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const allowedOrigins = [
  "https://www.webshield.tech",
  "https://webshield.tech",
  "https://api.webshield.tech",
  "https://webshield-frontend.vercel.app",
  "http://localhost:5173",
  configuredFrontendUrl,
  ...envAllowedOrigins,
].filter(Boolean);

const isAllowedOrigin = (origin) => {
  if (!origin) return true;
  if (allowAllCors) return true;

  return (
    allowedOrigins.includes(origin) ||
    origin.endsWith(".webshield.tech") ||
    origin === "https://webshield.tech" ||
    origin === "https://www.webshield.tech"
  );
};

const corsOptions = {
  origin: function (origin, callback) {
    console.log(`[CORS Check] Origin: ${origin}`);
    if (isAllowedOrigin(origin)) {
      callback(null, true);
    } else {
      console.warn(`[CORS Blocked] Origin not allowed: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie", "X-Requested-With"],
};

// 1. CORS FIRST
app.use(cors(corsOptions));

// 2. PARSERS
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(cookieParser());

// 3. RATE LIMITING
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per 15 mins
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests from this IP. Please try again after 15 minutes." },
});
app.use(globalLimiter);

// 4. DATABASE
connectDB().then(() => {
  seedAdmin();
});

// 5. ROUTES
app.use("/user", userRouter);
app.use("/scan", scanRouter);
app.use("/auth", authRouter);
app.use("/admin", adminRouter);
app.use("/api/exploit", dataRouter);
app.use("/notifications", notificationRouter);

app.get("/", (req, res) => {
  res.json({ message: "Vuln Spectra Backend server is running" });
});

// 6. GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res.status(500).json({
    success: false,
    error: "Internal server error",
  });
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Allowed Frontend: ${process.env.FRONTEND_URL || "Not configured"}`);
  console.log(`CORS allow all: ${allowAllCors ? "enabled" : "disabled"}`);
});

process.on("SIGTERM", async () => {
  console.log("SIGTERM signal received: closing HTTP server");
  await killAllProcesses();
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
});
