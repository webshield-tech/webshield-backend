import { Scan } from "../../models/scans-mongoose.js";

export async function getScanStatistics(userId, targetUrl, scanType) {
  try {
    // Normalize the URL for comparison
    let normalizedUrl = targetUrl.toLowerCase();
    normalizedUrl = normalizedUrl
      .replace(/^https?:\/\//, "")
      .replace(/^http?:\/\//, "")
      .replace(/^www\./, "")
      .replace(/\/$/, "")
      .trim();

    // Get all user's scans of this type
    const userScans = await Scan.find({
      userId: userId,
      scanType: scanType,
    }).sort({ createdAt: -1 });

    console.log(`User has ${userScans.length} total scans of type ${scanType}`);

    // Count scans for this specific URL
    let urlScanCount = 0;
    let lastScanDate = null;

    for (const scan of userScans) {
      let scanUrl = scan.targetUrl.toLowerCase();
      scanUrl = scanUrl
        .replace(/^https?:\/\//, "")
        .replace(/^http?:\/\//, "")
        .replace(/^www\./, "")
        .replace(/\/$/, "")
        .trim();

      if (scanUrl === normalizedUrl) {
        urlScanCount++;
        if (!lastScanDate || scan.createdAt > lastScanDate) {
          lastScanDate = scan.createdAt;
        }
      }
    }

    return {
      totalScansOfType: userScans.length,
      urlScanCount: urlScanCount,
      lastScanDate: lastScanDate,
      message: `User has ${userScans.length} ${scanType} scans total, ${urlScanCount} for this URL`,
    };
  } catch (error) {
    console.error("Scan statistics error:", error);
    return {
      totalScansOfType: 0,
      urlScanCount: 0,
      lastScanDate: null,
      message: "Could not retrieve scan statistics",
    };
  }
}
