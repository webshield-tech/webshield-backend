import crypto from 'crypto';
import { promisify } from 'util';

const randomBytes = promisify(crypto.randomBytes);

/**
 * ✅ SECURITY FIX: CSRF Protection Middleware
 * Implements token-based CSRF protection for state-changing operations
 */

export const csrfTokenMiddleware = async (req, res, next) => {
  // Generate CSRF token if not exists in session
  if (!req.session) {
    req.session = {};
  }
  
  if (!req.session.csrfToken) {
    try {
      const token = (await randomBytes(32)).toString('hex');
      req.session.csrfToken = token;
      res.locals.csrfToken = token;
    } catch (err) {
      console.error('CSRF token generation error:', err);
    }
  } else {
    res.locals.csrfToken = req.session.csrfToken;
  }
  
  next();
};

export const csrfProtectionMiddleware = (req, res, next) => {
  // Skip CSRF check for GET, HEAD, OPTIONS requests (safe methods)
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Skip CSRF check if user is not authenticated (optional - can be strict)
  if (!req.userId) {
    return next();
  }

  // Get CSRF token from request (try multiple sources)
  const token = 
    req.body?.csrfToken ||
    req.headers['x-csrf-token'] ||
    req.query?.csrfToken;

  // Validate token
  if (!token || !req.session?.csrfToken || token !== req.session.csrfToken) {
    console.warn(`[CSRF] Invalid or missing CSRF token for user ${req.userId}`);
    return res.status(403).json({
      success: false,
      error: "Invalid CSRF token. Please refresh and try again.",
    });
  }

  next();
};

export default csrfProtectionMiddleware;
