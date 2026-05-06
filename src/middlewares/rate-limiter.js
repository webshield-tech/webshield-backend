
import rateLimit, { ipKeyGenerator } from "express-rate-limit";

const isProduction = process.env.NODE_ENV === "production";

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skipSuccessfulRequests: true, // don't count successful logins
  skip: (req) => {
    // Skip rate limiting in development mode for easier testing
    return process.env.NODE_ENV !== "production" && process.env.SKIP_RATE_LIMIT !== "false";
  },
  handler: (req, res /*, next */) => {
    return res.status(429).json({
      success: false,
      error: "Too many login attempts. Try again later.",
    });
  },
});

export const scanLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  // Use userId from request, fall back to IP
  keyGenerator: (req) => {
    const userId = req.userId || req.user?.userId || req.user?.id;
    if (userId) {
      return `user_${userId}`;
    }
    return ipKeyGenerator(req);
  },
  skip: (req) => {
    // Skip rate limiting in development mode for easier testing
    return process.env.NODE_ENV !== "production" && process.env.SKIP_RATE_LIMIT !== "false";
  },
  handler: (req, res /*, next */) => {
    return res.status(429).json({
      success: false,
      error: "Too many scans. Please wait a few minutes and try again.",
    });
  },
});