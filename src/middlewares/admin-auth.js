import { User } from '../models/users-mongoose.js';

export async function checkAdmin(req, res, next) {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
      });
    }

    if (user.role !== 'admin') {
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
