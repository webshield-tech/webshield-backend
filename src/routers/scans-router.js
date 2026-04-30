import express from 'express';
import { checkAuth } from '../middlewares/user-auth.js';
import {
  startScan,
  pingTarget,
  getScanHistory,
  getScanResultsById,
  cancelScan,
  getBatchResults,
  startImpactDemo,
  getImpactDemo,
  getTodayStats,
} from '../controllers/user-scan-controller.js';
import {
  generateAIReportForScan,
  downloadReport,
  viewReport,
  generateBatchAIReport,
  downloadBatchReport,
  viewBatchReport,
} from '../controllers/aiReport-controller.js';

import rateLimit from 'express-rate-limit';

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 scan requests per `window`
  message: { success: false, error: "Too many scans initiated from this IP, please try again after 15 minutes" },
});

const scanRouter = express.Router();
scanRouter.use(checkAuth);

scanRouter.post('/ping', pingTarget);
scanRouter.post('/start', scanLimiter, startScan);
scanRouter.get('/history', getScanHistory);
scanRouter.get('/stats/today', getTodayStats);
scanRouter.get('/batch/:batchId', getBatchResults);
scanRouter.get('/:id', getScanResultsById);
scanRouter.post('/:id/cancel', cancelScan);
scanRouter.post('/:id/impact/start', startImpactDemo);
scanRouter.get('/:id/impact', getImpactDemo);

scanRouter.post('/:id/report/generate', generateAIReportForScan);
scanRouter.get('/:id/report/download', downloadReport);
scanRouter.get('/:id/report/view', viewReport);
scanRouter.post('/batch/:batchId/report/generate', generateBatchAIReport);
scanRouter.get('/batch/:batchId/report/download', downloadBatchReport);
scanRouter.get('/batch/:batchId/report/view', viewBatchReport);

export default scanRouter;
