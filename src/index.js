import express from "express";
import dotenv from "dotenv";
import { connectDB } from "./config/database.js";
import userRouter from "./routers/users-router.js";
import cookieParser from "cookie-parser";
import scanRouter from "./routers/scans-router.js";
import authRouter from "./routers/auth-router.js";
import adminRouter from "./routers/admin-router.js";
import exploitRouter from "./routers/exploit-router.js";
import cors from "cors";

import { seedAdmin } from "./utils/seed-admin.js";
import { killAllProcesses } from "./services/scan-runner.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;
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

const webshieldDomainPattern = /^https:\/\/([a-z0-9-]+\.)?webshield\.tech$/i;
const corsOptions = {
  origin(origin, callback) {
    // Allow non-browser calls (curl, health checks)
    if (!origin) return callback(null, true);

    if (allowAllCors) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin) || webshieldDomainPattern.test(origin)) {
      return callback(null, true);
    }

    return callback(new Error(`CORS blocked for origin: ${origin}`), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

app.use(cookieParser());

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

connectDB().then(() => {
  seedAdmin();
});

app.use("/user", userRouter);
app.use("/scan", scanRouter);
app.use("/auth", authRouter);
app.use("/admin", adminRouter);
app.use("/api/exploit", exploitRouter);

app.get("/", (req, res) => {
  res.json({ message: "Vuln Spectra Backend server is running" });
});

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
  console.log(
    `Database:  ${process.env.DB_URL ? "Configured" : "Not configured"}`
  );
});

// Graceful shutdown for PM2 / AWS
const shutdown = async (signal) => {
  console.log(`\n[${signal}] Shutting down gracefully...`);
  const killedCount = await killAllProcesses();
  console.log(`Terminated ${killedCount} active scan processes.`);
  server.close(() => {
    console.log("Server closed. Exiting process.");
    process.exit(0);
  });
};

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
