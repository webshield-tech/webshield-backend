import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
      minlength: 3,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: 6,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    scanLimit: {
      type: Number,
      default: 15,
    },
    usedScan: {
      type: Number,
      default: 0,
    },
    agreedToTerms: { type: Boolean, default: false },
    termsAcceptedAt: { type: Date },
    termsAcceptedIP: { type: String },
  },
  {
    timestamps: true,
  }
);
userSchema.index({ role: 1 });

export const User = mongoose.model("User", userSchema);
