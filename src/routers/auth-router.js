import express from 'express';
import rateLimit from 'express-rate-limit';
import { forgotPassword, resetPassword } from '../controllers/auth-controller.js';

const authRouter = express.Router();

// ✅ SECURITY FIX: Rate limiting on password reset endpoints
const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per IP
  message: "Too many password reset attempts, please try again later",
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  skip: (req) => process.env.NODE_ENV !== "production", // Skip in development
});

authRouter.post('/forgot-password', passwordResetLimiter, forgotPassword);
authRouter.post('/reset-password', passwordResetLimiter, resetPassword);

export default authRouter;
