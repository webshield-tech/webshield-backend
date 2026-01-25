import { verifyUser, createUser } from "../models/users-model.js";
import { User } from "../models/users-mongoose.js";
import jwt from "jsonwebtoken";
import { verifyEmailExistence } from "../utils/email-verifier.js";

// Add new user
export async function addUser(user) {
  try {
    // Verify email before checking existing users
    console.log(`Verifying email for addUser: ${user.email}`);
    const isEmailValid = await verifyEmailExistence(user.email);

    if (!isEmailValid) {
      return {
        error:
          "Please provide a valid, deliverable email address. Temporary/disposable emails are not allowed.",
      };
    }

    const existingUser = await User.findOne({
      $or: [{ email: user.email }, { username: user.username }],
    });

    if (existingUser) {
      return {
        error:
          existingUser.email === user.email
            ? "Email already registered"
            : "Username already taken",
      };
    }

    const newUser = await createUser({
      username: user.username,
      email: user.email,
      password: user.password,
      role: "user",
      scanLimit: 10,
      usedScan: 0,
    });

    const token = jwt.sign(
      {
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        userId: newUser._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    return {
      username: newUser.username,
      email: newUser.email,
      token: token,
      user: {
        _id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        scanLimit: newUser.scanLimit,
        usedScan: 0,
      },
    };
  } catch (error) {
    return { error: error.message };
  }
}

// Login handler with cookie
export async function loginUser(req, res) {
  try {
    const { email, password, emailOrUsername } = req.body;

    console.log("=== LOGIN REQUEST ===");
    console.log("Email/Username:", email || emailOrUsername);
    console.log("Password length:", password ? password.length : "missing");

    const result = await verifyUser({
      email: email || emailOrUsername,
      emailOrUsername: emailOrUsername || email,
      password,
    });

    if (!result.success) {
      console.log("Login failed:", result.error);
      return res.status(401).json({
        success: false,
        error: result.error,
      });
    }

    // CREATE TOKEN - THIS WAS MISSING
    const token = jwt.sign(
      {
        username: result.user.username,
        email: result.user.email,
        role: result.user.role,
        userId: result.user._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    // Set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    console.log("Login successful for:", result.user.username);
    console.log("User ID in token:", result.user._id);
    console.log("Cookie set with domain: .webshield.tech");

    res.json({
      success: true,
      message: result.message,
      user: result.user,
      token: result.token || token,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed",
    });
  }
}

// Signup handler with cookie setting
export async function signupUser(req, res) {
  try {
    const { username, email, password } = req.body;

    console.log("=== SIGNUP REQUEST ===");
    console.log("Username:", username);
    console.log("Email:", email);
    console.log("Password length:", password ? password.length : "missing");

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: "All fields are required",
      });
    }

    //  Verify email existence with API
    console.log(`Verifying email: ${email}`);
    const isEmailValid = await verifyEmailExistence(email);

    if (!isEmailValid) {
      console.log(`Email verification failed for: ${email}`);
      return res.status(400).json({
        success: false,
        error:
          "Please provide a valid, deliverable email address. Temporary/disposable emails are not allowed.",
      });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error:
          existingUser.email === email
            ? "Email already registered"
            : "Username already taken",
      });
    }

    const newUser = await createUser({
      username,
      email,
      password: password,
      role: "user",
      scanLimit: 10,
      usedScan: 0,
    });

    console.log("User created with ID:", newUser._id);

    const token = jwt.sign(
      {
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        userId: newUser._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    // Set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    console.log("Signup successful for:", newUser.username);
    console.log("Token generated with user ID:", newUser._id);

    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        _id: newUser._id,
        userId: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        scanLimit: newUser.scanLimit,
        usedScan: 0,
      },
      token: token,
    });
  } catch (error) {
    console.error("Signup error:", error.message);
    res.status(500).json({
      success: false,
      error: "Signup failed: " + error.message,
    });
  }
}

// Logout handler
export async function logoutUser(req, res) {
  try {
    console.log("LOGOUT REQUEST");

    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });

    console.log("Logout successful");

    res.json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({
      success: false,
      error: "Logout failed",
    });
  }
}

// Get user profile
export async function getUserProfile(req, res) {
  try {
    const userId = req.user.userId;

    console.log("=== GET PROFILE REQUEST ===");
    console.log("User ID from token:", userId);

    const user = await User.findById(userId).select("-password");

    if (!user) {
      console.log("User not found for ID:", userId);
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    console.log("Profile fetched for:", user.username);

    res.json({
      success: true,
      user: {
        _id: user._id,
        userId: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        scanLimit: user.scanLimit,
        usedScan: user.usedScan || 0,
        createdAt: user.createdAt,
        agreedToTerms: user.agreedToTerms,
      },
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch profile",
    });
  }
}
