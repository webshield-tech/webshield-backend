import express from "express";
import {
  loginValidation,
  signUpValidation,
} from "../utils/validations/user-validation.js";
import { loginUser, signupUser, addUser } from "../controllers/users-controller.js";
import { checkAuth } from "../middlewares/user-auth.js";
import { User } from "../models/users-mongoose.js";
import dotenv from "dotenv";
import { loginLimiter } from "../middlewares/rate-limiter.js";
dotenv.config();

const userRouter = express.Router();

// ✅ FIXED: Use signupUser function
userRouter.post("/signup", signUpValidation, signupUser);

// ✅ FIXED: Use loginUser function
userRouter.post("/login", loginValidation, loginLimiter, loginUser);

// GET USER PROFILE
userRouter.get('/profile', checkAuth, async (req, res) => {
  try {
    const userId = req.userId;
    
    const user = await User.findById(userId).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    res.json({
      success: true,
      user: {
        _id: user._id,
        userId: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        scanLimit: user.scanLimit,
        usedScan: user.usedScan,
        agreedToTerms: user.agreedToTerms || false,  
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get profile'
    });
  }
});

// LOGOUT ROUTE
userRouter.post('/logout', async (req, res) => {
  try {
    console.log('[Logout] Clearing cookie');
    
    res.clearCookie('token', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
      domain: '.railway.app',
    });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('[Logout] Error:', error);
    res.status(500).json({
      success: false,
      error: 'Logout failed'
    });
  }
});

// Accept terms route
userRouter.post("/accept-terms", checkAuth, async (req, res) => {
  try {
    const userId = req.userId;

    const userIP = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    await User.findByIdAndUpdate(userId, {
      agreedToTerms: true,
      termsAcceptedAt: new Date(),
      termsAcceptedIP: userIP,
    });

    console.log(`User ${userId} accepted terms from IP ${userIP}`);

    res.json({
      success: true,
      message: "Terms accepted successfully",
    });
  } catch (error) {
    console.error("Error accepting terms:", error);
    res.status(500).json({
      success: false,
      error: "Failed to accept terms",
    });
  }
});

export default userRouter;