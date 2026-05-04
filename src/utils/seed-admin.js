import { User } from "../models/users-mongoose.js";
import bcrypt from "bcrypt";
import crypto from "crypto";

export async function seedAdmin() {
  try {
    const adminEmail = "admin@fsociety.com";
    const configuredAdminPassword = process.env.ADMIN_SEED_PASSWORD;
    const fallbackRandomPassword = crypto.randomBytes(24).toString("base64url");
    const adminPassword = configuredAdminPassword || fallbackRandomPassword;
    
    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      if (!configuredAdminPassword) {
        console.warn(
          "[seed-admin] ADMIN_SEED_PASSWORD not set. Creating admin with a random password; set ADMIN_SEED_PASSWORD before first login."
        );
      }
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await User.create({
        username: "fsociety_admin",
        email: adminEmail,
        password: hashedPassword,
        role: "admin",
        agreedToTerms: true,
        isVerified: true,
        scanLimit: 9999,
        isBlocked: false
      });
      console.log("Admin account created: " + adminEmail);
    } else {
      // Ensure it has admin role and agreed to terms
      existingAdmin.role = "admin";
      existingAdmin.agreedToTerms = true;
      existingAdmin.isVerified = true;
      await existingAdmin.save();
      console.log("Admin account verified: " + adminEmail);
    }

    // Also ensure pkfsociety@gmail.com is an admin
    const secondaryAdmin = await User.findOne({ email: "pkfsociety@gmail.com" });
    if (secondaryAdmin) {
      secondaryAdmin.role = "admin";
      await secondaryAdmin.save();
      console.log("Secondary admin verified: pkfsociety@gmail.com");
    }
  } catch (error) {
    console.error("Error seeding admin:", error);
  }
}
