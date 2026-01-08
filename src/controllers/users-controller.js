import { verifyUser, createUser } from "../models/users-model.js";
import { User } from "../models/users-mongoose.js";
import jwt from "jsonwebtoken";

// Add new user
export async function addUser(user) {
  try {
    const existingUser = await User.findOne({
      $or: [{ email: user.email }, { username: user.username }]
    });

    if (existingUser) {
      return {
        error: existingUser.email === user.email
          ? "Email already registered"
          : "Username already taken"
      };
    }

    // ✅ REMOVED: Don't hash here, createUser will hash
    const newUser = await createUser({
      username: user.username,
      email: user.email,
      password: user.password,  // ← Plain password
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
      { expiresIn: "7d" }
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
      }
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

    res.cookie("token", result.token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
      domain: '.railway.app' 
    });

    console.log("✅ Login successful, cookie set for:", result.user.username);

    res.json({
      success: true,
      message: result.message,
      user: result.user,
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

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: existingUser.email === email
          ? "Email already registered"
          : "Username already taken",
      });
    }

    // ✅ REMOVED: No hashing here!
    // const hashedPassword = await bcrypt.hash(password, 10); ← DELETE THIS LINE
    
    const newUser = await createUser({
      username,
      email,
      password: password,  // ← Plain password! createUser will hash it
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
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
      domain: '.railway.app'
    });

    console.log("✅ Signup successful, cookie set for:", newUser.username);

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
      domain: '.railway.app'
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