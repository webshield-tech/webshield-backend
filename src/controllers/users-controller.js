import { createUser } from "../models/users-model.js";
import { User } from "../models/users-mongoose.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { verifyEmailExistence } from "../utils/email-verifier.js";
import admin from "../config/firebase-admin.js";
import { sendVerificationEmail } from "../utils/email-service.js";
import crypto from "crypto";

export async function firebaseLogin(req, res) {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, error: "Firebase token is required" });
    }

    // Verify token with Firebase Admin
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(token);
    } catch (err) {
      console.error("Firebase token verification failed:", err.message);
      return res.status(401).json({ success: false, error: "Invalid social login token" });
    }

    const { email, name, picture, uid } = decodedToken;

    // Find or create user
    let user = await User.findOne({ email });

    if (!user) {
      // Create new user for social login
      const username = name ? name.replace(/\s+/g, "").toLowerCase() + Math.floor(Math.random() * 1000) : email.split("@")[0] + Math.floor(Math.random() * 1000);
      
      user = new User({
        username,
        email,
        password: bcrypt.hashSync(Math.random().toString(36), 10), // Random password
        role: "user",
        scanLimit: 15,
        usedScan: 0,
        agreedToTerms: true, // Social login users usually bypass initial disclaimer if they come from trusted provider
        lastIp: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
        firebaseUid: uid,
        avatar: picture
      });
      await user.save();
      console.log(`[SocialAuth] Created new user: ${email}`);
    } else {
      // Update existing user IP
      user.lastIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
      if (!user.firebaseUid) user.firebaseUid = uid;
      await user.save();
      console.log(`[SocialAuth] Logged in existing user: ${email}`);
    }

    // Generate our platform JWT
    const platformToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    const isProduction = process.env.NODE_ENV === "production";
    const domain = process.env.COOKIE_DOMAIN || (isProduction ? ".webshield.tech" : "localhost");
    
    res.cookie("token", platformToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
      domain: isProduction ? domain : undefined
    });

    return res.json({
      success: true,
      token: platformToken,
      user: {
        _id: user._id,
        userId: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        scanLimit: user.scanLimit,
        usedScan: user.usedScan,
        agreedToTerms: user.agreedToTerms,
      }
    });

  } catch (error) {
    console.error("Firebase Login Controller Error:", error);
    return res.status(500).json({ success: false, error: "Internal server error during social login" });
  }
}


function getCookieOptions() {
  const isProduction = process.env.NODE_ENV === "production";
  
  return {
    httpOnly: true,
    secure: true, 
    sameSite: "none",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  };
}

export async function addUser(user) {
  const { username, email, password, lastIp } = user || {};

  if (!username || !email || !password) {
    return { error: "All fields are required" };
  }

  const isEmailValid = await verifyEmailExistence(email);
  if (!isEmailValid) {
    return {
      error:
        "Please provide a valid, deliverable email address. Temporary/disposable emails are not allowed.",
    };
  }

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

  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  const verificationCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

  const newUser = await createUser({
    username,
    email,
    password,
    role: "user",
    scanLimit: 10,
    usedScan: 0,
    lastIp,
    isVerified: false,
    verificationCode,
    verificationCodeExpires,
  });

  if (newUser && !newUser.error) {
    await sendVerificationEmail(email, verificationCode);
  }

  return newUser;
}

export async function signupUser(req, res) {
  try {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const created = await addUser({ ...req.body, lastIp: clientIp });

    if (created.error) {
      return res.status(400).json({
        success: false,
        error: created.error,
      });
    }

    res.status(201).json({
      success: true,
      message: "Registration successful. Please check your email for the verification code.",
      email: created.email,
      userId: created._id
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

    if (!userExists.isVerified && !userExists.firebaseUid) {
      return {
        success: false,
        error: "EMAIL_NOT_VERIFIED: Please verify your email address to continue.",
        email: userExists.email
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

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await User.findByIdAndUpdate(result.user._id, { lastIp: clientIp });

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
export async function verifyEmail(req, res) {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ success: false, error: "Email and code are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ success: false, error: "Account is already verified" });
    }

    if (user.verificationCode !== code || user.verificationCodeExpires < Date.now()) {
      return res.status(400).json({ success: false, error: "Invalid or expired verification code" });
    }

    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationCodeExpires = undefined;
    await user.save();

    // Generate token since they are now verified
    const token = jwt.sign(
      { userId: user._id, role: user.role, username: user.username, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, getCookieOptions());

    return res.json({
      success: true,
      message: "Email verified successfully!",
      token,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        agreedToTerms: user.agreedToTerms
      }
    });
  } catch (error) {
    console.error("[VerifyEmail Error]:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
}

export async function resendVerificationCode(req, res) {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ success: false, error: "Account already verified" });
    }

    const newCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.verificationCode = newCode;
    user.verificationCodeExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendVerificationEmail(email, newCode);

    return res.json({ success: true, message: "New verification code sent!" });
  } catch (error) {
    console.error("[ResendCode Error]:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
}
