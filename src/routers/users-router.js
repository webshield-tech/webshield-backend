import express from "express";
import {
  loginValidation,
  signUpValidation,
} from "../utils/validations/user-validation.js";
import {
  loginUser,
  signupUser,
  logoutUser,
  getUserProfile,
} from "../controllers/users-controller.js";
import { checkAuth } from "../middlewares/user-auth.js";
import { User } from "../models/users-mongoose.js";
import dotenv from "dotenv";
import { loginLimiter } from "../middlewares/rate-limiter.js";
dotenv.config();

const userRouter = express.Router();

//  signupUser function
userRouter.post("/signup", signUpValidation, signupUser);

// loginUser function
userRouter.post("/login", loginValidation, loginLimiter, loginUser);

// GET USER PROFILE
userRouter.get("/profile", checkAuth, getUserProfile);

// LOGOUT ROUTE
userRouter.post("/logout", logoutUser);

// Accept terms route
userRouter.post("/accept-terms", checkAuth, async (req, res) => {
  try {
    const userId = req.userId;

    const userIP =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;

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
