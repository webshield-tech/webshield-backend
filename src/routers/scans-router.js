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
  getToolAvailability,
  detectWebsite,
  dnsLookupInline,
  whoisLookupInline,
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

// ── Utility / inline routes (no scan pipeline) ──────────────────────────────
scanRouter.post('/ping', pingTarget);
scanRouter.post('/detect', detectWebsite);          // Website type detection
scanRouter.get('/tools/availability', getToolAvailability); // Tool preflight check
scanRouter.post('/dns-lookup', dnsLookupInline);    // Inline DNS lookup (no progress page)
scanRouter.post('/whois-lookup', whoisLookupInline); // Inline WHOIS lookup (no progress page)

// ── Core scan routes ─────────────────────────────────────────────────────────
scanRouter.post('/start', scanLimiter, startScan);
scanRouter.get('/history', getScanHistory);
scanRouter.get('/stats/today', getTodayStats);

// ── Batch routes BEFORE /:id wildcard ───────────────────────────────────────
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
