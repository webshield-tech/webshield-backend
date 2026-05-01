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
import { scanLimiter } from '../middlewares/rate-limiter.js';

const scanRouter = express.Router();
scanRouter.use(checkAuth);

// ── Non-parameterised routes first ──────────────────────────────────────────
scanRouter.post('/ping', pingTarget);
scanRouter.post('/start', scanLimiter, startScan);
scanRouter.get('/history', getScanHistory);
scanRouter.get('/stats/today', getTodayStats);

// ── Batch routes BEFORE /:id wildcard ───────────────────────────────────────
// (Express matches routes top-to-bottom; if /:id comes first,
//  "/batch/..." would be captured as id="batch" and fail.)
scanRouter.get('/batch/:batchId', getBatchResults);
scanRouter.post('/batch/:batchId/report/generate', generateBatchAIReport);
scanRouter.get('/batch/:batchId/report/view', viewBatchReport);
scanRouter.get('/batch/:batchId/report/download', downloadBatchReport);

// ── Single-scan routes ───────────────────────────────────────────────────────
scanRouter.get('/:id', getScanResultsById);
scanRouter.post('/:id/cancel', cancelScan);
scanRouter.post('/:id/impact/start', startImpactDemo);
scanRouter.get('/:id/impact', getImpactDemo);
scanRouter.post('/:id/report/generate', generateAIReportForScan);
scanRouter.get('/:id/report/view', viewReport);
scanRouter.get('/:id/report/download', downloadReport);

export default scanRouter;
