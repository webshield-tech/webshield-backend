import mongoose from "mongoose";

const scanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    targetUrl: {
      type: String,
      required: true,
    },
    scanType: {
      type: String,
      enum: [
        "nmap",
        "sqlmap",
        "ssl",
        "nikto",
        "gobuster",
        "ratelimit",
        "ffuf",
        "wapiti",
        "nuclei",
        "dns",
        "whois",
      ],
      default: "nikto",
    },
    platform: {
      type: String,
      default: null,
    },
    status: {
      type: String,
      enum: ["pending", "running", "completed", "failed", "cancelled"],
      default: "pending",
    },
    results: {
      type: Object,
      default: {},
    },
    // Individual scan text report (single-tool)
    reportContent: {
      type: String,
      default: null,
    },
    reportGeneratedAt: {
      type: Date,
      default: null,
    },
    reportLanguage: {
      type: String,
      default: "english",
    },
    // Batch / auto-scan: structured JSON from AI correlated analysis
    batchAnalysisJson: {
      type: Object,
      default: null,
    },
    scanPlan: {
      type: Object,
      default: null,
    },
    quotaRefunded: {
      type: Boolean,
      default: false,
    },
    startedAt: {
      type: Date,
      default: null,
    },
    completedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
scanSchema.index({ userId: 1, createdAt: -1 });
scanSchema.index({ status: 1 });
scanSchema.index({ userId: 1, status: 1 });
scanSchema.index({ "results.batchId": 1 });

export const Scan = mongoose.model("Scan", scanSchema);
