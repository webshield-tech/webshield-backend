import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export async function checkAuth(req, res, next) {
  const cookies = req.cookies || {};
  let token = null;

  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  } else if (cookies.token) {
    token = cookies.token;
  }

  if (!token) {
    return res.status(401).json({ success: false, error: "You are not logged in" });
  }

  try {
    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ success: false, error: "Server authentication is not configured" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    req.userId = decoded.userId || decoded.id || decoded._id;

    if (!req.userId) {
      return res.status(401).json({ success: false, error: "Invalid session token" });
    }

    next();
  } catch (error) {
    console.log("Token verification failed");
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, error: "Session expired, please login again" });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ success: false, error: "Invalid session token" });
    }
    return res.status(401).json({ success: false, error: "Authentication failed" });
  }
}

export const checkUserAuth = checkAuth;
export default checkAuth;
