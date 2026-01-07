import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export async function checkAuth(req, res, next) {
  console.log("AUTH CHECK");
  console.log("Cookies received:", Object.keys(req.cookies || {}));
  console.log("Has token:", !!req.cookies?.token);

  const cookies = req.cookies;

  // Check if token exists
  if (!cookies.token) {
    console.log("No token found in cookies");
    return res.status(401).json({
      success: false,
      error: "You are not logged in",
    });
  }

  try {
    // Verify JWT token
    const decoded = jwt.verify(cookies.token, process.env.JWT_SECRET);
    console.log("User Verified:", decoded.username, "| Role:", decoded.role);

    // Normalize user object and id for all controllers
    req.user = decoded;
    req.userId = decoded.userId || decoded.id || decoded._id;
    console.log("req.userId set to:", req.userId);

    next();
  } catch (error) {
    console.log("Token verification failed:", error.message);

    // Handle token expiration
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        error: "Session expired, please login again",
      });
    }

    // Handle invalid token
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        error: "Invalid session token",
      });
    }

    // Handle other JWT errors
    return res.status(401).json({
      success: false,
      error: "Authentication failed",
    });
  }
}
