import express from "express";
import {
  loginValidation,
  signUpValidation,
} from "../utils/validations/user-validation.js";
import { checkUser, addUser } from "../controllers/users-controller.js";
import { checkAuth } from "../middlewares/user-auth.js";
import { User } from "../models/users-mongoose.js";
import dotenv from "dotenv";
import { loginLimiter } from "../middlewares/rate-limiter.js";
dotenv.config();



const userRouter = express.Router();

// SIGNUP ROUTE
userRouter.post("/signup", signUpValidation, async (req, res) => {
  try {
    const user = req.body;

    console.log("=== SIGNUP REQUEST ===");
    console.log("Username:", user.username);
    console.log("Email:", user.email);

    const response = await addUser(user);

    // Check if signup failed
    if (response.error) {
      console.log("Signup failed:", response.error);
      return res.status(400).json({
        success: false,
        error: response.error,
      });
    }

    console.log("Signup successful for:", response.username);

    res.status(201).json({
      success: true,
      message: "Account created successfully",
      data: {
        username: response.username,
        email: response.email,
      },
    });
  } catch (error) {
    console.error("Signup error:", error.message);
    res.status(500).json({
      success: false,
      error: "Failed to create account",
    });
  }
});

// LOGIN ROUTE
userRouter.post("/login", loginValidation,loginLimiter, async (req, res) => {
  try {
    const user = req.body;

    console.log("=== LOGIN REQUEST ===");
    console.log("Email/Username:", user.email || user.emailOrUsername);
    console.log("Request origin:", req.headers.origin);
    console.log("Request host:", req.headers.host);

    const response = await checkUser(user);

    if (!response.success || response.error) {
      console.log("Login failed:", response.error);
      return res.status(401).json({
        success: false,
        error: response.error,
      });
    }

const isProduction = process.env.NODE_ENV === 'production';
const cookieOptions = {
  httpOnly: true,
  secure: isProduction, 
  sameSite: isProduction ? 'strict' : 'lax', 
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: "/",
};
    res.cookie("token", response.token, cookieOptions);

    console.log("Login successful");
    console.log(
      " Cookie set:",
      "token=" + response.token.substring(0, 20) + "..."
    );
    console.log(" Cookie options:", JSON.stringify(cookieOptions));

    res.json({
      success: true,
      message: "Logged in successfully",
      user: {
        _id: response.user._id || response.user.userId,
        userId: response.user.userId || response.user._id,
        username: response.user.username,
        email: response.user.email,
        role: response.user.role,
        scanLimit: response.user.scanLimit,
        usedScan: response.user.usedScan || 0,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      success: false,
      error: "Login failed",
    });
  }
});

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
        username: user. username,
        email: user. email,
        role: user. role,
        scanLimit: user.scanLimit,
        usedScan: user.usedScan,
        agreedToTerms: user.agreedToTerms || false,  
        createdAt: user. createdAt
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      error:  'Failed to get profile'
    });
  }
});

// LOGOUT ROUTE
userRouter.post('/logout', async (req, res) => {
  try {
    console.log('[Logout] Clearing cookie');
    
    
   const isProduction = process.env.NODE_ENV === 'production';
res.clearCookie('token', {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? 'strict' : 'lax',
  path: '/',
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

    // Get user's IP
    const userIP =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    // Update user
    await User.findByIdAndUpdate(userId, {
      agreedToTerms: true,
      termsAcceptedAt: new Date(),
      termsAcceptedIP: userIP,
    });

    console.log(` User ${userId} accepted terms from IP ${userIP}`);

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