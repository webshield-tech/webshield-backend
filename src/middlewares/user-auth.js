import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export async function checkAuth(req, res, next) {
  const cookies = req.cookies || {};
  let token = cookies.token;

  // Fallback to Authorization header if cookie is missing
  if (!token && req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  }

  // Check if token exists
  if (!token) {
    return res.status(401).json({
      success: false,
      error: "You are not logged in",
    });
  }

  try {
    // Verify JWT token
    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        success: false,
        error: "Server authentication is not configured",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Normalize user object and id for all controllers
    req.user = decoded;
    req.userId = decoded.userId || decoded.id || decoded._id;

    if (!req.userId) {
      return res.status(401).json({
        success: false,
        error: "Invalid session token",
      });
    }

    next();
  } catch (error) {
    console.log("Token verification failed");

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

export const checkUserAuth = checkAuth;
