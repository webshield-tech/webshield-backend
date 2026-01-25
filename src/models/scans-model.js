import { Scan } from "./scans-mongoose.js";

export async function createScan(scanData) {
  try {
    const newScan = new Scan(scanData);
    const savedScan = await newScan.save();
    return savedScan;
  } catch (error) {
    console.error("Error Creating new Scan", error.message);
    throw error;
  }
}
export async function userScanHistory(userId) {
  try {
    const scans = await Scan.find({ userId: userId }).sort({ createdAt: -1 });
    return scans;
  } catch (error) {
    console.error("Error fetching user Scans: ", error.message);
    throw error;
  }
}

export async function scanById(scanId, userId) {
  try {
    const scan = await Scan.findOne({ _id: scanId, userId: userId });
    return scan;
  } catch (error) {
    console.error("Error fetching scan:", error.message);
    throw error;
  }
}

export async function deleteScan(scanId, userId) {
  try {
    const deletedScan = await Scan.findOneAndDelete({
      _id: scanId,
      userId: userId,
    });
    return deletedScan;
  } catch (error) {
    console.error("Error deleting scan:", error.message);
    throw error;
  }
}

export async function updateScanResult(scanId, results) {
  try {
    return await Scan.findByIdAndUpdate(
      scanId,
      {
        status: "completed",
        results,
        completedAt: new Date(),
      },
      { new: true },
    );
  } catch (error) {
    console.error("Error updating scan results:", error.message);
    throw error;
  }
}
