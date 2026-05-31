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
    try {
      const parsed = JSON.parse(rawJson);
      return admin.credential.cert(parsed);
    } catch (err) {
      console.error('Invalid FIREBASE_SERVICE_ACCOUNT_JSON:', err.message);
      return null;
    }
  }

  const keyPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (keyPath && fs.existsSync(keyPath)) {
    try {
      const fileData = JSON.parse(fs.readFileSync(keyPath, "utf-8"));
      return admin.credential.cert(fileData);
    } catch (err) {
      console.error('Failed to parse Firebase service account file at', keyPath, err.message);
      return null;
    }
  }

  // Backward-compatible for local environments only.
  if (fs.existsSync(bundledServiceAccountPath)) {
    try {
      const fileData = JSON.parse(fs.readFileSync(bundledServiceAccountPath, "utf-8"));
      return admin.credential.cert(fileData);
    } catch (err) {
      console.error('Failed to parse bundled Firebase service account:', err.message);
      return null;
    }
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
