import { osintReport } from "../utils/osintReport.js";

export const generateOsint = async (req, res) => {
  try {
    const { targetName, targetIdentifier } = req.body;
    
    if (!targetName) {
      return res.status(400).json({ success: false, error: "Target name is required" });
    }

    const report = await osintReport(targetName, targetIdentifier || "Unknown");
    
    return res.status(200).json({
      success: true,
      report
    });
  } catch (error) {
    console.error("[OSINT Controller Error]:", error);
    return res.status(500).json({ success: false, error: "Failed to generate OSINT profile." });
  }
};
