import express from "express";
import dotenv from "dotenv";
import { connectDB } from "./config/database.js";
import userRouter from "./routers/users-router.js";
import cookieParser from "cookie-parser";
import scanRouter from "./routers/scans-router.js";
import authRouter from "./routers/auth-router.js";
import adminRouter from "./routers/admin-router.js";
import cors from "cors";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;

// FIXED CORS configuration:
const allowedOrigins = [
  'http://localhost:5173', // Local development
  'https://webshield.tech', // Your custom domain
  'https://www.webshield.tech', // WWW version
  'https://webshield-frontend.vercel.app', // Vercel URL
  process.env.FRONTEND_URL // Keep for env variable
].filter(Boolean); // Remove any undefined values

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, curl, or server-to-server)
      if (!origin) {
        return callback(null, true);
      }
      
      // Check if origin is in allowed list
      if (allowedOrigins.includes(origin)) {
        return callback(null, true); // FIXED: Return true, not origin
      } else {
        // Log blocked origins for debugging
        console.log('CORS blocked origin:', origin);
        return callback(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  })
);

app.use(cookieParser());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Connect to database
connectDB();

// Routes
app.use("/user", userRouter);
app.use("/scan", scanRouter);
app.use("/auth", authRouter);
app.use("/admin", adminRouter);

// Health check route
app.get("/", (req, res) => {
  res.json({ message: "WebShield Backend server is running" });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found"
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  
  // Handle CORS errors specifically
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      error: "CORS policy violation: Origin not allowed"
    });
  }
  
  res.status(500).json({
    success: false,
    error: "Internal server error",
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`Frontend URL: http://localhost:5173`);
  console.log(
    `Database:  ${process.env.DB_URL ? "Connected" : "Not configured"}`
  );
});