import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

console.log("EMAIL_USER:", process.env.EMAIL_USER);
console.log("EMAIL_PASSWORD:", process.env.EMAIL_PASSWORD);
const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASSWORD;

// CHECK CREDENTIALS ON STARTUP (EXIT IF MISSING)
if (!emailUser || !emailPass) {
  console.error(" FATAL:  Email credentials are missing");
  console.error("Please add EMAIL_USER and EMAIL_PASSWORD to your .env file");

  // Only exit in production (allow development without email)
  if (process.env.NODE_ENV === "production") {
    console.error(
      "Cannot start server without email credentials in production",
    );
    process.exit(1);
  } else {
    console.warn(
      " WARNING: Email service will not work.  Add credentials to .env",
    );
  }
}

// CREATE TRANSPORTER
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: emailUser,
    pass: emailPass,
  },
});

//  VERIFY TRANSPORTER ON STARTUP
transporter.verify(function (error, success) {
  if (error) {
    console.error("Email transporter error:", error.message);

    // Exit in production if email is broken
    if (process.env.NODE_ENV === "production") {
      console.error(
        "Cannot start server with broken email service in production",
      );
      process.exit(1);
    } else {
      console.warn(
        "Email service verification failed. Password reset won't work.",
      );
    }
  } else {
    console.log("Email transporter is ready");
  }
});

// SEND PASSWORD RESET EMAIL
export async function sendResetPassEmail(email, resetToken) {
  try {
    console.log(`Attempting to send reset email to: ${email}`);

    // CHECK IF TRANSPORTER IS CONFIGURED
    if (!emailUser || !emailPass) {
      console.error("Cannot send email:  credentials not configured");
      return false;
    }

    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5173";
    const resetLink = `${frontendUrl}/reset-password?token=${resetToken}`;

    console.log("Reset link generated:", resetLink);

    const mailOptions = {
      from: `"WebShield Security" <${emailUser}>`,
      to: email,
      subject: "Reset Your WebShield Password",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; background-color: #f3f4f6;">
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px;">
            
            <!-- Header -->
            <div style="text-align: center; padding: 20px 0; border-bottom:  2px solid #00ff41;">
              <h1 style="color: #0a0a0a; margin: 0; font-size: 28px;">🛡️ WebShield</h1>
              <p style="color: #64748b; margin: 5px 0 0 0;">Security Scanner</p>
            </div>

            <!-- Main Content -->
            <div style="padding: 30px 20px;">
              <h2 style="color: #2563eb; margin-top: 0;">Password Reset Request</h2>
              
              <p style="color: #334155; font-size: 16px; line-height: 1.6;">
                Hello,
              </p>
              
              <p style="color: #334155; font-size: 16px; line-height: 1.6;">
                We received a request to reset your password for your <strong>WebShield Security Scanner</strong> account.
              </p>

              <!-- Button -->
              <div style="text-align: center; margin: 40px 0;">
                <a href="${resetLink}" 
                   style="background-color: #00ff41; 
                          color: #0a0a0a; 
                          padding: 14px 32px; 
                          text-decoration: none; 
                          border-radius: 6px; 
                          font-weight: bold; 
                          font-size: 16px;
                          display: inline-block;">
                  Reset Password
                </a>
              </div>

              <!-- Fallback Link -->
              <p style="color: #64748b; font-size: 14px;">
                Or copy and paste this link into your browser:
              </p>
              <p style="background-color: #f1f5f9; 
                        padding: 12px; 
                        border-radius:  5px; 
                        word-break: break-all; 
                        font-size:  13px; 
                        color: #334155;
                        border-left: 3px solid #00ff41;">
                ${resetLink}
              </p>

              <!-- Expiry Warning -->
              <div style="background-color: #fef2f2; 
                          border-left: 4px solid #ef4444; 
                          padding: 15px; 
                          margin: 20px 0; 
                          border-radius: 4px;">
                <p style="color:  #991b1b; margin: 0; font-weight: bold;">
                  ⏱️ This link will expire in 15 minutes
                </p>
              </div>
            </div>

            <!-- Footer -->
            <div style="border-top: 1px solid #e2e8f0; padding:  20px; margin-top: 20px;">
              <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin: 0 0 10px 0;">
                If you didn't request this password reset, please ignore this email.  Your password will not be changed. 
              </p>
              
              <p style="color: #94a3b8; font-size: 12px; margin: 10px 0 0 0;">
                <strong>WebShield Security Scanner</strong><br>
                Your Website Security Partner
              </p>
            </div>

          </div>
        </body>
        </html>
      `,
    };

    console.log("Sending email via Gmail...");
    const info = await transporter.sendMail(mailOptions);

    console.log(`Password reset email sent successfully`);
    console.log(`   To: ${email}`);
    console.log(`   Message ID: ${info.messageId}`);

    return true;
  } catch (error) {
    console.error("Error sending email:", error.message);

    // Log specific Gmail errors
    if (error.code === "EAUTH") {
      console.error(
        "   Authentication failed. Check your EMAIL_USER and EMAIL_PASSWORD",
      );
    } else if (error.code === "ESOCKET") {
      console.error("   Network error. Check your internet connection");
    } else if (error.responseCode === 550) {
      console.error("   Recipient email address invalid or blocked");
    }

    console.error("   Full error:", error);
    return false;
  }
}
