import admin from "firebase-admin";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Search for serviceAccountKey.json in config directory
const serviceAccountPath = path.join(__dirname, "serviceAccountKey.json");

if (fs.existsSync(serviceAccountPath)) {
  try {
    const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf-8"));
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log("✅ Firebase Admin initialized successfully");
  } catch (err) {
    console.error("❌ Error initializing Firebase Admin:", err.message);
  }
} else {
  console.warn("⚠️ Firebase Admin Service Account not found at:", serviceAccountPath);
  console.warn("Social login verification will be unavailable until serviceAccountKey.json is provided.");
}

export default admin;
