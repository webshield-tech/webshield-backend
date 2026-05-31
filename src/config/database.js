import mongoose from "mongoose";
import { killAllProcesses } from "../services/scan-runner.js";
export async function connectDB() {
  if (!process.env.DB_URL) {
    console.error("DB_URL not configured - skipping DB connect");
    return;
  }

  try {
    await mongoose.connect(process.env.DB_URL, { serverSelectionTimeoutMS: 5000 });

    mongoose.connection.on("connected", () => {
      console.log("MongoDB connected");
    });
    mongoose.connection.on("error", (err) => {
      console.error("MongoDB connection error:", err);
    });
    mongoose.connection.on("disconnected", () => {
      console.warn("MongoDB disconnected");
    });

    // Database initialized
    console.log("Database initialized");
    return true;

    console.log("Database initialized");
    return true;
  } catch (err) {
    console.error("Failed to connect to DB:", err);
    return false;
  }
}

export async function closeDatabase() {
  console.log("Closing database connection and cleaning up resources");
  try {
    const killed = await killAllProcesses();
    console.log(`Killed ${killed} running scan processes`);
  } catch (e) {
    console.error("Error while killing processes during DB close:", e);
  }
  try {
    await mongoose.disconnect();
    console.log("MongoDB disconnected");
  } catch (e) {
    console.error("Error disconnecting MongoDB:", e);
  }
}