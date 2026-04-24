import express from 'express';
import { checkAuth } from '../middlewares/user-auth.js';
import {
  startScan,
  getScanHistory,
  getScanResultsById,
  cancelScan,
  getBatchResults,
  startImpactDemo,
  getImpactDemo,
} from '../controllers/user-scan-controller.js';
import {
  generateAIReportForScan,
  downloadReport,
  viewReport,
} from '../controllers/aiReport-controller.js';

const scanRouter = express.Router();
scanRouter.use(checkAuth);

scanRouter.post('/start', startScan);
scanRouter.get('/history', getScanHistory);
scanRouter.get('/batch/:batchId', getBatchResults);
scanRouter.get('/:id', getScanResultsById);
scanRouter.post('/:id/cancel', cancelScan);
scanRouter.post('/:id/impact/start', startImpactDemo);
scanRouter.get('/:id/impact', getImpactDemo);

scanRouter.post('/:id/report/generate', generateAIReportForScan);
scanRouter.get('/:id/report/download', downloadReport);
scanRouter.get('/:id/report/view', viewReport);

export default scanRouter;
