import { User } from "../models/users-mongoose.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { getAdminEmails } from "./admin-config.js";

export async function seedAdmin() {
  try {
    const adminEmails = getAdminEmails();
    if (adminEmails.length === 0) {
      console.warn("[seed-admin] No ADMIN_EMAILS or ADMIN_EMAIL configured. Skipping admin seed.");
      return;
    }

    const primaryAdminEmail = adminEmails[0];
    const configuredAdminPassword = process.env.ADMIN_SEED_PASSWORD;
    const fallbackRandomPassword = crypto.randomBytes(24).toString("base64url");
    const adminPassword = configuredAdminPassword || fallbackRandomPassword;

    const existingAdmin = await User.findOne({ email: primaryAdminEmail });

    if (!existingAdmin) {
      if (!configuredAdminPassword) {
        console.warn(
          "[seed-admin] ADMIN_SEED_PASSWORD not set. Creating admin with a random password; set ADMIN_SEED_PASSWORD before first login."
        );
      }
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await User.create({
        username: "admin",
        email: primaryAdminEmail,
        password: hashedPassword,
        role: "admin",
        agreedToTerms: true,
        isVerified: true,
        scanLimit: 9999,
        isBlocked: false
      });
      console.log("Admin account created: " + primaryAdminEmail);
    } else {
      existingAdmin.role = "admin";
      existingAdmin.agreedToTerms = true;
      existingAdmin.isVerified = true;
      await existingAdmin.save();
      console.log("Admin account verified: " + primaryAdminEmail);
    }

    // Ensure all configured admin emails have admin role
    for (const email of adminEmails.slice(1)) {
      const adminUser = await User.findOne({ email });
      if (adminUser && adminUser.role !== 'admin') {
        adminUser.role = "admin";
        await adminUser.save();
        console.log("Admin verified: " + email);
      }
    }
  } catch (error) {
    console.error("Error seeding admin:", error);
  }
}
