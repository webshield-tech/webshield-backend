import rateLimit from "express-rate-limit";

const isProduction = process.env.NODE_ENV === "production";

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    return res.status(429).json({
      success: false,
      error: "Too many login attempts. Try again later.",
    });
  },
});
