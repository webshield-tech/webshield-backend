import { createUser } from "../models/users-model.js";
import { User } from "../models/users-mongoose.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { verifyEmailExistence } from "../utils/email-verifier.js";

function getCookieOptions() {
  const isProduction = process.env.NODE_ENV === "production";
  const domain = process.env.COOKIE_DOMAIN || (isProduction ? ".webshield.tech" : "localhost");
  
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
    domain: isProduction ? domain : undefined
  };
}

export async function addUser(user) {
  const { username, email, password } = user || {};

  if (!username || !email || !password) {
    return { error: "All fields are required" };
  }

  // Bypassed for development/competition demo to allow `.io` and fake emails
  /*
  const isEmailValid = await verifyEmailExistence(email);
  if (!isEmailValid) {
    return {
      error:
        "Please provide a valid, deliverable email address. Temporary/disposable emails are not allowed.",
    };
  }
  */

  const existingUser = await User.findOne({
    $or: [{ email }, { username }],
  }).lean();

  if (existingUser) {
    return {
      error:
        existingUser.email === email
          ? "Email already registered"
          : "Username already taken",
    };
  }

  const newUser = await createUser({
    username,
    email,
    password,
    role: "user",
    scanLimit: 10,
    usedScan: 0,
  });

  return newUser;
}

export async function signupUser(req, res) {
  try {
    const created = await addUser(req.body);

    if (created.error) {
      return res.status(400).json({
        success: false,
        error: created.error,
      });
    }

    // Generate token
    const token = jwt.sign(
      {
        username: created.username,
        email: created.email,
        role: created.role,
        userId: created._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, getCookieOptions());

    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        _id: created._id,
        userId: created._id,
        username: created.username,
        email: created.email,
        role: created.role,
        scanLimit: created.scanLimit,
        usedScan: 0,
        agreedToTerms: created.agreedToTerms || false,
      },
      token: token,
    });
  } catch (error) {
    console.error(" Signup error:", error);
    res.status(500).json({
      success: false,
      error: "Signup failed",
    });
  }
}

export async function checkUser(user) {
  try {
    const rawIdentifier = user.emailOrUsername || user.email || user.username;
    const identifier = String(rawIdentifier || "").trim().toLowerCase();
    const password = user.password;

    if (!identifier) {
      return {
        success: false,
        error: "Email or username is required",
      };
    }

    if (!password) {
      return {
        success: false,
        error: "Password is required",
      };
    }

    const userExists = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });

    if (!userExists) {
      console.log(`[AUTH] User not found: "${identifier}"`);
      return {
        success: false,
        error: "User does not exist",
      };
    }

    if (userExists.isBlocked) {
      return {
        success: false,
        error: "ACCOUNT_SUSPENDED: Your access to Vuln Spectra has been revoked due to ethical violations.",
      };
    }

    const isPasswordValid = await bcrypt.compare(password, userExists.password);

    if (!isPasswordValid) {
      console.log(`[AUTH] Password mismatch for: ${identifier}`);
      return {
        success: false,
        error: "Your password is incorrect",
      };
    }

    const token = jwt.sign(
      {
        username: userExists.username,
        email: userExists.email,
        role: userExists.role,
        userId: userExists._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return {
      success: true,
      message: "You are logged in",
      token: token,
      user: {
        _id: userExists._id,
        userId: userExists._id,
        username: userExists.username,
        email: userExists.email,
        role: userExists.role,
        scanLimit: userExists.scanLimit,
        usedScan: userExists.usedScan || 0,
        agreedToTerms: userExists.agreedToTerms || false,
      },
    };
  } catch (error) {
    console.error("Error verifying user:", error);
    return {
      success: false,
      error: "Internal server error during verification",
    };
  }
}

// loginUser function
export async function loginUser(req, res) {
  try {
    const { email, password, emailOrUsername } = req.body;

    console.log("=== LOGIN REQUEST ===");
    console.log("Email/Username:", email || emailOrUsername);

    const result = await checkUser({
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

    res.cookie("token", result.token, getCookieOptions());

    console.log(" Login successful, cookie set for:", result.user.username);

    res.json({
      success: true,
      message: result.message,
      user: result.user,
      token: result.token,
    });
  } catch (error) {
    console.error(" Login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed",
    });
  }
}

// Keep logoutUser function
export async function logoutUser(req, res) {
  try {
    console.log("LOGOUT REQUEST");
    res.clearCookie("token", getCookieOptions());
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

// ✅ Keep getUserProfile function
export async function getUserProfile(req, res) {
  try {
    const userId = req.user.userId;
    console.log("=== GET PROFILE REQUEST ===");
    console.log("User ID:", userId);
    const user = await User.findById(userId).select("-password");
    if (!user) {
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
        agreedToTerms: user.agreedToTerms || false,
        createdAt: user.createdAt,
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
