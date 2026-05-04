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
import rateLimit from "express-rate-limit";
import { injectionDetector } from "./middlewares/security.js";
import helmet from "helmet";
import mongoSanitize from "express-mongo-sanitize";
import cors from "cors";

import { seedAdmin } from "./utils/seed-admin.js";
import { killAllProcesses } from "./services/scan-runner.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;
app.set("trust proxy", 1);

// Security headers — must be first middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false, // CSP managed at CDN/Vercel level
}));

// Sanitize req.body / req.params / req.query to prevent NoSQL injection
app.use((req, res, next) => {
  if (req.body) mongoSanitize.sanitize(req.body);
  if (req.query) mongoSanitize.sanitize(req.query);
  if (req.params) mongoSanitize.sanitize(req.params);
  if (req.headers) mongoSanitize.sanitize(req.headers);
  next();
});
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
  "http://127.0.0.1:5173",
  "http://0.0.0.0:5173",
  configuredFrontendUrl,
  ...envAllowedOrigins,
].filter(Boolean);

const normalizeOrigin = (origin) => String(origin || "").replace(/\/+$/, "");
const normalizedAllowedOrigins = allowedOrigins.map((origin) => normalizeOrigin(origin));

const isAllowedOrigin = (origin) => {
  if (!origin) return true;
  if (allowAllCors) return true;

  const normalized = normalizeOrigin(origin);
  const isLocalhost =
    normalized.startsWith("http://localhost:") ||
    normalized.startsWith("http://127.0.0.1:") ||
    normalized.startsWith("http://0.0.0.0:");

  return (
    normalizedAllowedOrigins.includes(normalized) ||
    (normalized && normalized.endsWith && normalized.endsWith(".webshield.tech")) ||
    normalized === "https://webshield.tech" ||
    normalized === "https://www.webshield.tech" ||
    isLocalhost
  );
};

const corsOptions = {
  origin: (origin, callback) => {
    console.log(`[CORS Check] Origin: ${origin}`);
    if (!origin) return callback(null, true);
    if (allowAllCors) return callback(null, true);
    if (isAllowedOrigin(origin)) return callback(null, true);
    console.warn(`[CORS Blocked] Origin not allowed: ${origin}`);
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie", "X-Requested-With"],
};

app.use(cors(corsOptions));
app.options("*path", cors(corsOptions));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(cookieParser());
app.use(injectionDetector);

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests from this IP. Please try again after 15 minutes." },
});
app.use(globalLimiter);

connectDB().then(() => {
  seedAdmin();
});

// Mount API routes under a base path. Frontend may auto-add `/api/v1`.
const apiBase = process.env.API_BASE_PATH || "/api/v1";

// Log the API base so deployments surface the effective path in logs.
console.log(`[API BASE] Using API base path: ${apiBase}`);

// Backwards-compat: mount routes both at root and under the api base.
// This avoids 404s when a proxy rewrites/strips prefixes or when an
// older frontend/backend expects the legacy paths.
app.use("/user", userRouter);
app.use(`${apiBase}/user`, userRouter);

app.use("/scan", scanRouter);
app.use(`${apiBase}/scan`, scanRouter);

app.use("/auth", authRouter);
app.use(`${apiBase}/auth`, authRouter);

app.use("/admin", adminRouter);
app.use(`${apiBase}/admin`, adminRouter);

app.use("/api/exploit", dataRouter);
app.use(`${apiBase}/exploit`, dataRouter);

app.use("/notifications", notificationRouter);
app.use(`${apiBase}/notifications`, notificationRouter);

// Provide a health route at the api base so requests to `/api/v1/` return 200.
app.get(`${apiBase}/`, (req, res) => {
  res.json({ message: "Vuln Spectra API base is reachable", base: apiBase });
});

app.get("/", (req, res) => res.json({ message: "Vuln Spectra Backend server is running" }));

app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res.status(500).json({ success: false, error: "Internal server error" });
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Allowed Frontend: ${process.env.FRONTEND_URL || "Not configured"}`);
  console.log(`CORS allow all: ${allowAllCors ? "enabled" : "disabled"}`);
});

const gracefulShutdown = async (signal) => {
  console.log(`${signal} signal received: closing HTTP server`);
  await killAllProcesses();
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT",  () => gracefulShutdown("SIGINT"));
