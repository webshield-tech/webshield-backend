import mongoose from "mongoose";
import { killProcess } from "../services/scan-runner.js";

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

    // Graceful shutdown
    const shutdown = async () => {
      console.log("SIGTERM/SIGINT received: shutting down gracefully");
      try {
        const killed = await killProcess();
        console.log(`Killed ${killed} running scan processes`);
      } catch (e) {
        console.error("Error while killing processes during shutdown:", e);
      }
      await mongoose.disconnect();
      console.log("MongoDB disconnected, exiting");
      process.exit(0);
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);

    console.log("Database initialized");
  } catch (err) {
    console.error("Failed to connect to DB:", err);
    process.exit(1);
  }
}