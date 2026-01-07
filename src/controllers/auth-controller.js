import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { User } from "../models/users-mongoose.js";
import { passReset } from "../models/pass-reset-mongoose.js";
import { sendResetPassEmail } from "../utils/email-service.js";

dotenv.config();

// FORGOT PASSWORD
export async function forgotPassword(req, res) {
  try {
    console.log("Forgot Password Request");

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required",
      });
    }

    // CHECK IF USER EXISTS
    const user = await User.findOne({ email });

    if (!user) {
      console.log("User not found for email:", email);
      return res.status(404).json({
        success: false,
        error: "No account found with this email",
      });
    }

    console.log("User found, generating reset token...");
    const resetToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        type: "password_reset",
      },
      process.env.JWT_RESET_SECRET,
      { expiresIn: "15m" }
    );

    //SAVE TOKEN TO DATABASE
    await passReset.create({
      email: user.email,
      token: resetToken,
    });

    // SEND EMAIL TO USER
    const emailSent = await sendResetPassEmail(user.email, resetToken);

    if (emailSent) {
      console.log(`Reset email sent to: ${user.email}`);
      return res.json({
        success: true,
        message: "Password reset link has been sent to your email",
        note: "Check spam folder if not received",
      });
    } else {
      console.log("Failed to send email to:", user.email);
      return res.status(500).json({
        success: false,
        error: "Failed to send email. Please try again.",
      });
    }
  } catch (error) {
    console.error("Forgot password error:", error.message);
    return res.status(500).json({
      success: false,
      error: "An error occurred. Please try again.",
    });
  }
}

// RESET PASSWORD
export async function resetPassword(req, res) {
  try {
    console.log("RESET PASSWORD REQUEST");

    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        error: "Token and new password are required",
      });
    }

    // VERIFY TOKEN
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_RESET_SECRET);
      console.log("JWT Verification SUCCESS for:", decoded.email);
    } catch (jwtError) {
      console.log("JWT Verification FAILED:", jwtError.message);
      return res.status(400).json({
        success: false,
        error: "Invalid or expired reset token",
      });
    }

    // CHECKING TOKEN IN DATABASE
    const resetRecord = await passReset.findOne({
      token: token,
      email: decoded.email,
      used: false,
    });

    if (!resetRecord) {
      console.log("Token not found or already used/expired");
      return res.status(400).json({
        success: false,
        error: "Invalid or already used reset token",
      });
    }

    // PASSWORD REGEX FOR NEW PASSWORD
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/;

    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        success: false,
        error:
          "Password must contain: 8+ chars, uppercase, lowercase, number, special character",
      });
    }

// ENCRYPTING PASSWORD
const salt = await bcrypt.genSalt(10);
const hashedPassword = await bcrypt.hash(newPassword, salt);

    // UPDATING USER PASSWORD
    await User.findOneAndUpdate(
      { email: decoded.email },
      { password: hashedPassword }
    );

    // MARKING TOKEN AS USED
    await passReset.findByIdAndUpdate(resetRecord._id, {
      used: true,
    });

    console.log(`Password reset successful for: ${decoded.email}`);
    return res.json({
      success: true,
      message:
        "Password reset successfully.  You can now login with new password.",
    });
  } catch (error) {
    console.error("Reset password error:", error.message);
    return res.status(500).json({
      success: false,
      error: "An error occurred. Please try again.",
    });
  }
}
