import express from 'express';
import { consequenceEngineService, CONSEQUENCE_EVENT_TYPES } from './consequence-engine.js';
import { a50SqueezeGateService, A50_TEST_STEPS } from './a50-squeeze-gate.js';
import { featureFlagService, FEATURE_FLAGS } from './feature-flags.js';
import { tenantAuditService } from './tenant-audit.js';

const router = express.Router();

router.post('/a50/start', async (req, res) => {
  try {
    const { machineId, testerId } = req.body;
    
    if (!machineId || !testerId) {
      return res.status(400).json({ error: 'machineId and testerId are required' });
    }

    const flagEnabled = await featureFlagService.isEnabled(FEATURE_FLAGS.A50_SQUEEZE_GATE);
    if (!flagEnabled) {
      return res.status(403).json({ error: 'A50 Squeeze Gate feature is not enabled' });
    }

    const session = await a50SqueezeGateService.startTest(machineId, testerId);
    res.json({ success: true, session });
  } catch (error) {
    console.error('A50 start error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/a50/step', async (req, res) => {
  try {
    const { sessionId, stepId, photoUrl, decision, notes } = req.body;
    
    if (!sessionId || !stepId) {
      return res.status(400).json({ error: 'sessionId and stepId are required' });
    }

    const result = await a50SqueezeGateService.recordStepCompletion(sessionId, stepId, {
      photo_url: photoUrl,
      decision,
      notes
    });
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('A50 step error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/a50/submit', async (req, res) => {
  try {
    const { sessionId, passed, proofUrls } = req.body;
    
    if (!sessionId || passed === undefined) {
      return res.status(400).json({ error: 'sessionId and passed are required' });
    }

    const result = await a50SqueezeGateService.submitTestResult(
      sessionId, 
      passed, 
      proofUrls || []
    );
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('A50 submit error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/a50/steps', (req, res) => {
  res.json({ steps: A50_TEST_STEPS });
});

router.get('/a50/history/:machineId', async (req, res) => {
  try {
    const history = await a50SqueezeGateService.getTestHistory(
      req.params.machineId,
      parseInt(req.query.limit) || 10
    );
    res.json({ history });
  } catch (error) {
    console.error('A50 history error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/a50/status/:machineId', async (req, res) => {
  try {
    const status = await a50SqueezeGateService.getMachineTestStatus(req.params.machineId);
    res.json({ status });
  } catch (error) {
    console.error('A50 status error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/user/:userId/blocked', async (req, res) => {
  try {
    const result = await consequenceEngineService.isUserBlocked(req.params.userId);
    res.json(result);
  } catch (error) {
    console.error('User blocked check error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/restricted-mode/enter', async (req, res) => {
  try {
    const { userId, reason } = req.body;
    
    if (!userId || !reason) {
      return res.status(400).json({ error: 'userId and reason are required' });
    }

    await consequenceEngineService.enterRestrictedMode(userId, reason);
    res.json({ success: true });
  } catch (error) {
    console.error('Enter restricted mode error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/restricted-mode/exit', async (req, res) => {
  try {
    const { userId, clearedBy } = req.body;
    
    if (!userId || !clearedBy) {
      return res.status(400).json({ error: 'userId and clearedBy are required' });
    }

    await consequenceEngineService.exitRestrictedMode(userId, clearedBy);
    res.json({ success: true });
  } catch (error) {
    console.error('Exit restricted mode error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/recert/require', async (req, res) => {
  try {
    const { userId, reason } = req.body;
    
    if (!userId || !reason) {
      return res.status(400).json({ error: 'userId and reason are required' });
    }

    await consequenceEngineService.requireRecert(userId, reason);
    res.json({ success: true });
  } catch (error) {
    console.error('Require recert error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/recert/complete', async (req, res) => {
  try {
    const { userId, certifierId, certType } = req.body;
    
    if (!userId || !certifierId || !certType) {
      return res.status(400).json({ error: 'userId, certifierId, and certType are required' });
    }

    await consequenceEngineService.completeRecert(userId, certifierId, certType);
    res.json({ success: true });
  } catch (error) {
    console.error('Complete recert error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/feature-flags', async (req, res) => {
  try {
    const { tenantId, siteId } = req.query;
    const flags = await featureFlagService.getAllFlags(tenantId, siteId);
    res.json({ flags });
  } catch (error) {
    console.error('Get feature flags error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/feature-flags', async (req, res) => {
  try {
    const { flagName, enabled, tenantId, siteId } = req.body;
    const setBy = req.headers['x-user-id'] || 'unknown';
    
    if (!flagName || enabled === undefined) {
      return res.status(400).json({ error: 'flagName and enabled are required' });
    }

    const result = await featureFlagService.setFlag(flagName, enabled, tenantId, siteId, setBy);
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('Set feature flag error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/feature-flags/rollout', async (req, res) => {
  try {
    const status = await featureFlagService.getRolloutStatus();
    res.json({ status });
  } catch (error) {
    console.error('Get rollout status error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/tenant-audit/run', async (req, res) => {
  try {
    const { tenantId } = req.body;
    const result = await tenantAuditService.runIsolationAudit(tenantId);
    res.json(result);
  } catch (error) {
    console.error('Tenant audit error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/tenant-audit/history', async (req, res) => {
  try {
    const history = await tenantAuditService.getAuditHistory(
      parseInt(req.query.limit) || 10
    );
    res.json({ history });
  } catch (error) {
    console.error('Tenant audit history error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/tenant-audit/checksum/:tenantId', async (req, res) => {
  try {
    const checksum = await tenantAuditService.generateTenantChecksum(req.params.tenantId);
    res.json(checksum);
  } catch (error) {
    console.error('Tenant checksum error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/sync-sla/check', async (req, res) => {
  try {
    const { userId, queuedItems } = req.body;
    
    if (!userId || !queuedItems) {
      return res.status(400).json({ error: 'userId and queuedItems are required' });
    }

    const breaches = await consequenceEngineService.checkSyncSLA(queuedItems);
    
    if (breaches.length > 0) {
      await consequenceEngineService.handleSyncSLABreach(userId, breaches);
    }

    res.json({ 
      breaches,
      hasBreaches: breaches.length > 0,
      slaHours: consequenceEngineService.SYNC_SLA_HOURS
    });
  } catch (error) {
    console.error('Sync SLA check error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
