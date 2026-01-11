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
app.set('trust proxy', 1);

// CORS configuration
const allowedOrigins = [
  'http://localhost:5173', 
  'https://webshield.tech', 
  'https://www.webshield.tech', 
  'https://webshield-frontend.vercel.app',
  'https://webshield-frontend.vercel.app', 
 
  process.env.FRONTEND_URL 
].filter(Boolean);

console.log('Allowed origins:', allowedOrigins);

// Debug middleware - ADD THIS
app.use((req, res, next) => {
  console.log(`\n=== REQUEST ${req.method} ${req.url} ===`);
  console.log('Origin:', req.headers.origin);
  console.log('Host:', req.headers.host);
  console.log('Cookies:', req.cookies);
  console.log('=====================\n');
  next();
});

// Create CORS options
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl requests)
    if (!origin) {
      console.log('No origin header, allowing request');
      return callback(null, true);
    }
    
    // Check if origin is in allowed origins
    if (allowedOrigins.includes(origin)) {
      console.log('Origin allowed:', origin);
      return callback(null, true);
    }
    
    // Allow all vercel.app subdomains (for preview deployments)
    if (origin.includes('.vercel.app')) {
      console.log('Vercel origin allowed:', origin);
      return callback(null, true);
    }
    
    // Allow all railway.app subdomains (for backend)
    if (origin.includes('.railway.app')) {
      console.log('Railway origin allowed:', origin);
      return callback(null, true);
    }
    
    console.log('CORS blocked origin:', origin);
    return callback(new Error('Not allowed by CORS'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With'],
  exposedHeaders: ['Set-Cookie']
};

// Apply CORS to all routes
app.use(cors(corsOptions));

// Handle OPTIONS preflight requests separately
app.options(/.*/, (req, res) => {
  const origin = req.headers.origin;
  
  console.log('OPTIONS preflight request from:', origin);
  
  if (origin) {
    // Check if origin is allowed
    const isAllowed = allowedOrigins.includes(origin) || 
                      origin.includes('.vercel.app') || 
                      origin.includes('.railway.app');
    
    if (isAllowed) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Requested-With');
  res.sendStatus(200);
});

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

// Health check routes
app.get("/", (req, res) => {
  res.json({ 
    message: "WebShield Backend server is running",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get("/health", (req, res) => {
  res.json({ 
    status: "ok", 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get("/api/health", (req, res) => {
  res.json({ 
    status: "ok", 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// 404 handler
app.use((req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.url}`);
  res.status(404).json({
    success: false,
    error: "Route not found",
    path: req.url,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  
  // Handle CORS errors specifically
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      error: "CORS policy violation: Origin not allowed",
      allowedOrigins: allowedOrigins
    });
  }
  
  res.status(500).json({
    success: false,
    error: "Internal server error",
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Allowed origins: ${allowedOrigins.join(', ')}`);
});