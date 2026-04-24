import { User } from "../models/users-mongoose.js";
import bcrypt from "bcrypt";

export async function seedAdmin() {
  try {
    const adminEmail = "admin@fsociety.com";
    const adminPassword = "Anonymous@payload!@#";
    
    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await User.create({
        username: "fsociety_admin",
        email: adminEmail,
        password: hashedPassword,
        role: "admin",
        agreedToTerms: true,
        scanLimit: 9999,
        isBlocked: false
      });
      console.log("Admin account created: " + adminEmail);
    } else {
      // Ensure it has admin role and agreed to terms
      existingAdmin.role = "admin";
      existingAdmin.agreedToTerms = true;
      await existingAdmin.save();
      console.log("Admin account verified: " + adminEmail);
    }
  } catch (error) {
    console.error("Error seeding admin:", error);
  }
}
