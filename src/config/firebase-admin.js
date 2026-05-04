import admin from "firebase-admin";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const bundledServiceAccountPath = path.join(__dirname, "serviceAccountKey.json");

function getFirebaseCredential() {
  const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (rawJson) {
    return admin.credential.cert(JSON.parse(rawJson));
  }

  const keyPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (keyPath && fs.existsSync(keyPath)) {
    const fileData = JSON.parse(fs.readFileSync(keyPath, "utf-8"));
    return admin.credential.cert(fileData);
  }

  // Backward-compatible for local environments only.
  if (fs.existsSync(bundledServiceAccountPath)) {
    const fileData = JSON.parse(fs.readFileSync(bundledServiceAccountPath, "utf-8"));
    return admin.credential.cert(fileData);
  }

  return null;
}

try {
  const credential = getFirebaseCredential();
  if (!credential) {
    // Initialize with a dummy project to prevent "app not initialized" errors in other parts of the system
    admin.initializeApp({ projectId: "dummy-project" });
    console.log("⚠️ Firebase running in mock mode (Social Login Disabled)");
  } else {
    admin.initializeApp({ credential });
    console.log("✅ Firebase Admin initialized successfully");
  }
} catch (err) {
  console.error("❌ Error initializing Firebase Admin:", err.message);
}

export default admin;
