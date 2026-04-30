import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, // e.g., your-email@gmail.com
    pass: process.env.EMAIL_PASS, // e.g., your-app-password
  },
});

export const sendVerificationEmail = async (email, code) => {
  const mailOptions = {
    from: `"WebShield Security" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Your WebShield Verification Code",
    html: `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 10px;">
        <h2 style="color: #00d4ff; text-align: center;">WebShield Security</h2>
        <p>Thank you for joining WebShield. To complete your registration, please use the following verification code:</p>
        <div style="text-align: center; margin: 30px 0;">
          <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #333; background: #f4f4f4; padding: 10px 20px; border-radius: 5px; border: 1px dashed #ccc;">
            ${code}
          </span>
        </div>
        <p>This code will expire in 10 minutes. If you did not request this, please ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
        <p style="font-size: 12px; color: #888; text-align: center;">&copy; 2026 WebShield Security Platform. All rights reserved.</p>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`[EmailService] Verification code sent to: ${email}`);
    return true;
  } catch (error) {
    console.error("[EmailService] Error sending email:", error.message);
    return false;
  }
};
