/**
 * SIPJOLT OS - Technician Console Routes
 * Production-ready for Replit (Single-Site Deployment)
 * 
 * COPY TO: /server/routes/yileTechnician.js
 */

import express from 'express';
import { pool } from '../../shared/db.js';
import sovereignQueue from '../services/yile/sovereignQueue.js';
import yileApi from '../services/yile/yileApiService.js';
import { requireAuth, requireSiteRole } from '../../shared/middleware/rbac.js';

const router = express.Router();

// ==================== MIDDLEWARE ====================

const checkIntegrationEnabled = (req, res, next) => {
  if (process.env.YILE_INTEGRATION_ENABLED !== 'true') {
    return res.status(503).json({
      success: false,
      error: 'Yile integration disabled. Enable in Replit Secrets: YILE_INTEGRATION_ENABLED=true',
    });
  }
  next();
};

const assignUserContext = (req, res, next) => {
  req.userContext = {
    userId: req.user?.id || null,
    userName: req.user?.name,
    userRole: req.currentSiteRole || req.siteAssignments?.[0]?.role,
    tenantId: null,
  };
  next();
};

router.use(checkIntegrationEnabled);
router.use(requireAuth);
router.use(requireSiteRole((req) => req.params.siteId, 'technician', 'partner', 'driver', 'ops_manager', 'ops_admin'));
router.use(assignUserContext);

// ==================== MISSION PANEL ====================

/**
 * GET /api/v1.01/yile-tech/sites/:siteId/mission-panel
 */
router.get('/sites/:siteId/mission-panel', async (req, res) => {
  try {
    const { siteId } = req.params;

    const deviceResult = await pool.query(`
      SELECT d.*, s.venue_name as site_name, s.address as location_address
      FROM yile_devices d
      JOIN ops_sites s ON CAST(d.site_id AS TEXT) = CAST(s.id AS TEXT)
      WHERE CAST(s.id AS TEXT) = $1::text OR CAST(s.site_id AS TEXT) = $1::text OR CAST(d.device_id AS TEXT) = $1::text
      LIMIT 1
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No Yile device found for this site',
      });
    }

    const device = deviceResult.rows[0];
    const status = await yileApi.getCachedStatus(device.yile_device_id);
    const recentCommands = await sovereignQueue.getRecentCommands(device.yile_device_id, 10);

    const incidentsResult = await pool.query(`
      SELECT COUNT(*) as count
      FROM ops_incidents
      WHERE CAST(site_id AS TEXT) = $1::text
      AND status = 'OPEN'
    `, [siteId]);

    res.json({
      success: true,
      data: {
        device: {
          deviceId: device.device_id,
          yileDeviceId: device.yile_device_id,
          siteName: device.site_name,
          location: device.location_address,
          softLockState: device.soft_lock_state,
          softLockReason: device.soft_lock_reason,
        },
        status: status ? {
          online: status.device_status === 1,
          workStatus: status.work_status,
          workStatusText: getWorkStatusText(status.work_status),
          signalStrength: status.net_signal,
          errorInfo: status.device_error_info,
          lastUpdate: status.cached_at,
        } : {
          online: false,
          workStatusText: 'Unknown',
          lastUpdate: null,
        },
        recentCommands: recentCommands.map(cmd => ({
          commandId: cmd.command_id,
          type: cmd.type,
          status: cmd.status,
          errorMessage: cmd.error_message,
          createdAt: cmd.created_at,
          completedAt: cmd.ended_at,
        })),
        openIncidents: parseInt(incidentsResult.rows[0].count) || 0,
      },
    });
  } catch (error) {
    console.error('[YileTech] Mission panel error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to load mission panel',
      details: error.message,
    });
  }
});

function getWorkStatusText(workStatus) {
  const statusMap = {
    0: 'Ready (Idle)',
    1: 'Selecting Sugar',
    2: 'Processing Payment',
    3: 'Brewing',
    5: 'Dispensing Lid',
    6: 'Settings Mode',
  };
  return statusMap[workStatus] || `Unknown (${workStatus})`;
}

// ==================== TEST BREW ====================

/**
 * POST /api/v1.01/yile-tech/sites/:siteId/test-brew
 */
router.post('/sites/:siteId/test-brew', async (req, res) => {
  try {
    const { siteId } = req.params;
    const { recipeName } = req.body;

    if (!recipeName) {
      return res.status(400).json({
        success: false,
        error: 'recipeName required in body',
      });
    }

    const deviceResult = await pool.query(`
      SELECT yile_device_id FROM yile_devices WHERE CAST(site_id AS TEXT) = $1::text
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Device not found',
      });
    }

    const deviceId = deviceResult.rows[0].yile_device_id;

    const result = await sovereignQueue.executeCommand({
      deviceId,
      type: 'BREW_TEST',
      userId: req.userContext.userId,
      userRole: req.userContext.userRole,
      payload: { recipeName },
    });

    if (result.deduplicated) {
      return res.status(409).json({
        success: false,
        error: 'Brew already in progress (duplicate within 30s)',
        commandId: result.commandId,
      });
    }

    if (result.blocked) {
      return res.status(403).json({
        success: false,
        error: result.message || 'Brew blocked',
        commandId: result.commandId,
      });
    }

    res.json({
      success: true,
      message: 'Brew initiated',
      commandId: result.commandId,
    });
  } catch (error) {
    console.error('[YileTech] Test brew error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * GET /api/v1.01/yile-tech/sites/:siteId/available-recipes
 */
router.get('/sites/:siteId/available-recipes', async (req, res) => {
  try {
    const { siteId } = req.params;

    const deviceResult = await pool.query(`
      SELECT yile_device_id FROM yile_devices WHERE CAST(site_id AS TEXT) = $1::text
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Device not found',
      });
    }

    const deviceId = deviceResult.rows[0].yile_device_id;
    const menu = await yileApi.queryCoffee(deviceId);

    res.json({
      success: true,
      data: {
        recipes: (menu.list || []).map(recipe => ({
          id: recipe.id,
          name: recipe.name,
          price: recipe.price,
          type: recipe.type,
        })),
      },
    });
  } catch (error) {
    console.error('[YileTech] Recipes error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== RESTART ====================

/**
 * POST /api/v1.01/yile-tech/sites/:siteId/restart
 */
router.post('/sites/:siteId/restart', async (req, res) => {
  try {
    const { siteId } = req.params;

    const deviceResult = await pool.query(`
      SELECT yile_device_id FROM yile_devices WHERE CAST(site_id AS TEXT) = $1::text
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Device not found',
      });
    }

    const deviceId = deviceResult.rows[0].yile_device_id;

    const result = await sovereignQueue.executeCommand({
      deviceId,
      type: 'RESTART',
      userId: req.userContext.userId,
      userRole: req.userContext.userRole,
      payload: {},
    });

    if (result.blocked) {
      return res.status(403).json({
        success: false,
        error: result.message,
        commandId: result.commandId,
      });
    }

    res.json({
      success: true,
      message: 'Restart initiated',
      commandId: result.commandId,
    });
  } catch (error) {
    console.error('[YileTech] Restart error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== TAKE OFFLINE / BRING ONLINE ====================

/**
 * POST /api/v1.01/yile-tech/sites/:siteId/take-offline
 */
router.post('/sites/:siteId/take-offline', async (req, res) => {
  try {
    const { siteId } = req.params;
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({
        success: false,
        error: 'reason required in body',
      });
    }

    const deviceResult = await pool.query(`
      SELECT yile_device_id FROM yile_devices WHERE CAST(site_id AS TEXT) = $1::text
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Device not found',
      });
    }

    const deviceId = deviceResult.rows[0].yile_device_id;

    const result = await sovereignQueue.executeCommand({
      deviceId,
      type: 'TAKE_OFFLINE',
      userId: req.userContext.userId,
      userRole: req.userContext.userRole,
      payload: { reason },
    });

    res.json({
      success: true,
      message: `Device offline: ${reason}`,
      commandId: result.commandId,
    });
  } catch (error) {
    console.error('[YileTech] Take offline error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * POST /api/v1.01/yile-tech/sites/:siteId/bring-online
 */
router.post('/sites/:siteId/bring-online', async (req, res) => {
  try {
    const { siteId } = req.params;

    const deviceResult = await pool.query(`
      SELECT yile_device_id FROM yile_devices WHERE CAST(site_id AS TEXT) = $1::text
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Device not found',
      });
    }

    const deviceId = deviceResult.rows[0].yile_device_id;

    const result = await sovereignQueue.executeCommand({
      deviceId,
      type: 'BRING_ONLINE',
      userId: req.userContext.userId,
      userRole: req.userContext.userRole,
      payload: {},
    });

    res.json({
      success: true,
      message: 'Device online',
      commandId: result.commandId,
    });
  } catch (error) {
    console.error('[YileTech] Bring online error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== COMMAND STATUS ====================

/**
 * GET /api/v1.01/yile-tech/commands/:commandId
 */
router.get('/commands/:commandId', async (req, res) => {
  try {
    const { commandId } = req.params;

    const command = await sovereignQueue.getCommandStatus(commandId);

    if (!command) {
      return res.status(404).json({
        success: false,
        error: 'Command not found',
      });
    }

    res.json({
      success: true,
      data: {
        commandId: command.command_id,
        type: command.type,
        status: command.status,
        errorMessage: command.error_message,
        createdAt: command.created_at,
        startedAt: command.started_at,
        completedAt: command.ended_at,
        pushId: command.vendor_push_id,
      },
    });
  } catch (error) {
    console.error('[YileTech] Command status error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== REFRESH STATUS ====================

/**
 * POST /api/v1.01/yile-tech/sites/:siteId/refresh-status
 */
router.post('/sites/:siteId/refresh-status', async (req, res) => {
  try {
    const { siteId } = req.params;

    const deviceResult = await pool.query(`
      SELECT yile_device_id FROM yile_devices WHERE CAST(site_id AS TEXT) = $1::text
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Device not found',
      });
    }

    const deviceId = deviceResult.rows[0].yile_device_id;
    const status = await yileApi.findDeviceInfo(deviceId);

    res.json({
      success: true,
      data: {
        online: status.deviceStatus === 1,
        workStatus: status.workStatus,
        workStatusText: getWorkStatusText(status.workStatus),
        signalStrength: status.netSignal,
        errorInfo: status.deviceErrorInfo,
      },
    });
  } catch (error) {
    console.error('[YileTech] Refresh status error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

export default router;
