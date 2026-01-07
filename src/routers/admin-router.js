import express from 'express';
import { checkAuth } from '../middlewares/user-auth.js';
import { checkAdmin } from '../middlewares/admin-auth.js';
import {
  removeScan,
  upgradeUserScan,
  getUserScanHistoryAdmin,
  getAllScanHistory,
} from '../controllers/admin-scan-controller.js';
const adminRouter = express.Router();
import { getAdminStats } from '../controllers/admin-scan-controller.js';

adminRouter.use(checkAuth);
adminRouter.use(checkAdmin);

adminRouter.get('/', (req, res) => {
  res.json({
    message: 'Welcome Admin',
    admin: req.adminUser.username,
  });
});

adminRouter.get('/stats', getAdminStats);
adminRouter.get('/history', getAllScanHistory);
adminRouter.get('/users/:userId/history', getUserScanHistoryAdmin);
adminRouter.post('/update-limit', upgradeUserScan);
adminRouter.delete('/scan/:id', removeScan);

export default adminRouter;
