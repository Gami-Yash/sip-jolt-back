import express from 'express';
import * as metricsService from './services/metrics.js';
import { requireRole } from './middleware/rbac.js';

const router = express.Router();

router.get('/summary', requireRole(['ops_admin', 'building_manager']), async (req, res) => {
  try {
    const tenantId = req.query.tenantId || req.authUser?.tenantId;
    const periodDays = parseInt(req.query.days) || 7;
    
    const summary = await metricsService.getMetricsSummary(
      req.authUser?.role === 'ops_admin' ? tenantId : req.authUser?.tenantId,
      periodDays
    );
    
    res.json(summary);
  } catch (error) {
    console.error('Error getting metrics summary:', error);
    res.status(500).json({ error: 'Failed to get metrics summary' });
  }
});

router.get('/upload-failures', requireRole(['ops_admin']), async (req, res) => {
  try {
    const tenantId = req.query.tenantId || null;
    const limit = parseInt(req.query.limit) || 50;
    
    const failures = await metricsService.getRecentUploadFailures(tenantId, limit);
    res.json(failures);
  } catch (error) {
    console.error('Error getting upload failures:', error);
    res.status(500).json({ error: 'Failed to get upload failures' });
  }
});

router.get('/geo-denials', requireRole(['ops_admin']), async (req, res) => {
  try {
    const tenantId = req.query.tenantId || null;
    const limit = parseInt(req.query.limit) || 50;
    
    const denials = await metricsService.getRecentGeoDenials(tenantId, limit);
    res.json(denials);
  } catch (error) {
    console.error('Error getting geo denials:', error);
    res.status(500).json({ error: 'Failed to get geo denials' });
  }
});

router.get('/lockouts', requireRole(['ops_admin']), async (req, res) => {
  try {
    const lockouts = await metricsService.getActiveLockouts();
    res.json(lockouts);
  } catch (error) {
    console.error('Error getting lockouts:', error);
    res.status(500).json({ error: 'Failed to get lockouts' });
  }
});

router.post('/lockouts/:userId/unlock', requireRole(['ops_admin']), async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const unlockedBy = req.authUser?.id;
    
    const result = await metricsService.unlockUser(userId, unlockedBy);
    if (!result) {
      return res.status(404).json({ error: 'No active lockout found for user' });
    }
    
    res.json({ success: true, unlocked: result });
  } catch (error) {
    console.error('Error unlocking user:', error);
    res.status(500).json({ error: 'Failed to unlock user' });
  }
});

router.get('/isolation-alerts', requireRole(['ops_admin']), async (req, res) => {
  try {
    const alerts = await metricsService.getUnresolvedIsolationAlerts();
    res.json(alerts);
  } catch (error) {
    console.error('Error getting isolation alerts:', error);
    res.status(500).json({ error: 'Failed to get isolation alerts' });
  }
});

router.post('/isolation-alerts/:id/resolve', requireRole(['ops_admin']), async (req, res) => {
  try {
    const alertId = parseInt(req.params.id);
    const resolvedBy = req.authUser?.id;
    
    const result = await metricsService.resolveIsolationAlert(alertId, resolvedBy);
    if (!result) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    
    res.json({ success: true, resolved: result });
  } catch (error) {
    console.error('Error resolving alert:', error);
    res.status(500).json({ error: 'Failed to resolve alert' });
  }
});

router.post('/record/upload-failure', async (req, res) => {
  try {
    const failure = await metricsService.recordUploadFailure(req.body);
    res.json({ success: true, failure });
  } catch (error) {
    console.error('Error recording upload failure:', error);
    res.status(500).json({ error: 'Failed to record upload failure' });
  }
});

router.post('/record/geo-denial', async (req, res) => {
  try {
    const denial = await metricsService.recordGeoDenial(req.body);
    res.json({ success: true, denial });
  } catch (error) {
    console.error('Error recording geo denial:', error);
    res.status(500).json({ error: 'Failed to record geo denial' });
  }
});

router.post('/receipts', async (req, res) => {
  try {
    const receipt = await metricsService.createVisitReceipt(req.body);
    res.json({ success: true, receipt });
  } catch (error) {
    console.error('Error creating receipt:', error);
    res.status(500).json({ error: 'Failed to create receipt' });
  }
});

router.post('/receipts/:receiptId/confirm', async (req, res) => {
  try {
    const { receiptId } = req.params;
    const receipt = await metricsService.confirmVisitReceipt(receiptId);
    
    if (!receipt) {
      return res.status(404).json({ error: 'Receipt not found' });
    }
    
    res.json({ success: true, receipt });
  } catch (error) {
    console.error('Error confirming receipt:', error);
    res.status(500).json({ error: 'Failed to confirm receipt' });
  }
});

router.post('/rate-limit/check', async (req, res) => {
  try {
    const { limitKey, limitType, maxCount, windowSeconds } = req.body;
    
    if (!limitKey || !limitType || !maxCount || !windowSeconds) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }
    
    const result = await metricsService.checkRateLimit(limitKey, limitType, maxCount, windowSeconds);
    res.json(result);
  } catch (error) {
    console.error('Error checking rate limit:', error);
    res.status(500).json({ error: 'Failed to check rate limit' });
  }
});

export default router;
