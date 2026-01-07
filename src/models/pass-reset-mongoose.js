import mongoose from 'mongoose';

const passResetSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    token: {
      type: String,
      required: true,
      unique: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      default: () => new Date(Date.now() + 10 * 60 * 1000),
    },
    used: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

passResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const passReset = mongoose.model('passwordReset', passResetSchema);
