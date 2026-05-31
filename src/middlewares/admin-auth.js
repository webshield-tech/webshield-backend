import { User } from '../models/users-mongoose.js';
import { getAdminEmails } from '../utils/admin-config.js';

export async function checkAdmin(req, res, next) {
  try {
    const userId = req.userId || (req.user && (req.user.userId || req.user.id || req.user._id));
    
    console.log(`[AdminCheck] Verifying admin status for userId: ${userId}`);

    if (!userId) {
      console.warn('[AdminCheck] No userId found in request');
      return res.status(401).json({ error: 'Unauthorized: No user ID found' });
    }

    const user = await User.findById(userId);

    if (!user) {
      console.warn(`[AdminCheck] User not found in database: ${userId}`);
      return res.status(404).json({
        error: 'User not found',
      });
    }

    if (user.isBlocked) {
      console.warn(`[AdminCheck] Blocked user attempted admin access: ${userId}`);
      return res.status(403).json({ error: 'Account is blocked' });
    }

    console.log(`[AdminCheck] User found: ${user.username}, Email: ${user.email}, Role: ${user.role}`);

    const dbRole = String(user.role || '').trim().toLowerCase();
    const adminEmails = getAdminEmails();
    const isMasterAdmin = adminEmails.includes(user.email.toLowerCase());

    if (dbRole !== 'admin' && !isMasterAdmin) {
      console.warn(`[AdminCheck] Access denied for user: ${user.username} (Role: ${user.role})`);
      return res.status(403).json({
        error: 'Admin access is required',
      });
    }

    req.adminUser = user;
    next();
  } catch (error) {
    console.error('Admin check error:', error);
    return res.status(500).json({
      error: 'Internal server error during admin verification',
    });
  }
}
