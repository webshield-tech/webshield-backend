import bcrypt from "bcrypt";
import { User } from "./users-mongoose.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export async function createUser(user) {
  try {
    const existingUser = await User.findOne({
      $or: [{ username: user.username }, { email: user.email }],
    });

    if (existingUser) {
      if (existingUser.username === user.username) {
        throw new Error("Username already exists");
      }
      if (existingUser.email === user.email) {
        throw new Error("Email already exists");
      }
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(user.password, salt);

    const newUser = new User({
      username: user.username,
      email: user.email,
      password: hashedPass,
      role: user.role || "user",
      scanLimit: user.scanLimit != null ? user.scanLimit : 15,
      usedScan: user.usedScan != null ? user.usedScan : 0,
    });

    const savedUser = await newUser.save();
    return savedUser;
  } catch (error) {
    console.error("Error saving User:", error.message);
    throw error;
  }
}

export async function verifyUser(user) {
  try {
    const identifier = user.emailOrUsername;
    const password = user.password;

    const userExists = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });

    if (!userExists) {
      return {
        error: "User does not exist",
      };
    }

    const isPasswordValid = await bcrypt.compare(password, userExists.password);

    if (isPasswordValid) {
      const token = jwt.sign(
        {
          username: userExists.username,
          email: userExists.email,
          role: userExists.role,
          userId: userExists._id,
        },
        process.env.JWT_SECRET,
        { expiresIn: "2d" }
      );
      return {
        success: true,
        message: "You are logged in",
        token: token,
        user: {
          // ✅ COMPLETE USER DATA:
          _id: userExists._id,
          userId: userExists._id,
          username: userExists.username,
          email: userExists.email,
          role: userExists.role,
          scanLimit: userExists.scanLimit,
          usedScan: userExists.usedScan || 0,
        },
      };
    } else {
      return {
        success: false,
        error: "Your password is incorrect",
      };
    }
  } catch (error) {
    console.error("Error verifying user:", error);
    return {
      error: "Internal server error during verification",
    };
  }
}