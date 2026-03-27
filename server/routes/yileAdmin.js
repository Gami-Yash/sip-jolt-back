/**
 * SIPJOLT OS - Admin Routes for Diagnostic Panel
 * Backend endpoints for Admin/Diagnostic Panel features
 */

import express from 'express';
import { pool } from '../../shared/db.js';
import yileApi from '../services/yile/yileApiService.js';
import { requireAuth, requireRole } from '../../shared/middleware/rbac.js';

const router = express.Router();

// ==================== MIDDLEWARE ====================

router.use(requireAuth);
router.use(requireRole('ops_manager', 'ops_admin', 'admin'));
router.use((req, res, next) => {
  req.userContext = {
    userId: req.user?.id || null,
    userName: req.user?.name,
    userRole: req.siteAssignments?.[0]?.role,
    tenantId: null,
  };
  next();
});

// ==================== TOKEN MANAGEMENT ====================

/**
 * GET /api/v1.01/yile-admin/token/status
 * Get current token status
 */
router.get('/token/status', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT vendor, token, expires_at, refreshed_at
      FROM vendor_tokens
      WHERE vendor = 'YILE'
      ORDER BY refreshed_at DESC
      LIMIT 1
    `);

    if (result.rows.length === 0) {
      return res.json({
        success: true,
        data: {
          vendor: 'YILE',
          exists: false,
          message: 'No token found',
        },
      });
    }

    const token = result.rows[0];
    const now = new Date();
    const expiresAt = new Date(token.expires_at);
    const timeUntilExpiry = Math.max(0, expiresAt - now);
    const hours = Math.floor(timeUntilExpiry / (1000 * 60 * 60));
    const minutes = Math.floor((timeUntilExpiry % (1000 * 60 * 60)) / (1000 * 60));

    res.json({
      success: true,
      data: {
        vendor: token.vendor,
        exists: true,
        expiresAt: token.expires_at,
        refreshedAt: token.refreshed_at,
        timeUntilExpiry: `${hours}h ${minutes}m`,
        isExpired: timeUntilExpiry <= 0,
      },
    });
  } catch (error) {
    console.error('[Admin] Token status error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * POST /api/v1.01/yile-admin/token/refresh
 * Force token refresh
 */
router.post('/token/refresh', async (req, res) => {
  try {
    await yileApi.refreshToken();

    // Log audit event
    await pool.query(`
      INSERT INTO yile_audit_events (event_type, actor, metadata_json, created_at)
      VALUES ('TOKEN_FORCE_REFRESH', $1, $2, NOW())
    `, [req.user?.id, JSON.stringify({ admin: true })]);

    res.json({
      success: true,
      message: 'Token refreshed successfully',
    });
  } catch (error) {
    console.error('[Admin] Token refresh error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== CACHE MANAGEMENT ====================

/**
 * GET /api/v1.01/yile-admin/cache/status
 * Get cache status
 */
router.get('/cache/status', async (req, res) => {
  try {
    const statusResult = await pool.query(`
      SELECT device_id, cached_at, 
             EXTRACT(EPOCH FROM (NOW() - cached_at)) as age_seconds
      FROM yile_machine_status
      ORDER BY cached_at DESC
      LIMIT 10
    `);

    const inventoryResult = await pool.query(`
      SELECT COUNT(*) as count, MAX(cached_at) as last_cached,
             EXTRACT(EPOCH FROM (NOW() - MAX(cached_at))) as age_seconds
      FROM yile_inventory_cache
    `);

    res.json({
      success: true,
      data: {
        machineStatus: statusResult.rows.map(row => ({
          deviceId: row.device_id,
          cachedAt: row.cached_at,
          age: `${Math.floor(row.age_seconds)} seconds`,
        })),
        inventory: {
          items: parseInt(inventoryResult.rows[0].count),
          lastCached: inventoryResult.rows[0].last_cached,
          age: inventoryResult.rows[0].last_cached 
            ? `${Math.floor(inventoryResult.rows[0].age_seconds)} seconds` 
            : 'Never',
        },
      },
    });
  } catch (error) {
    console.error('[Admin] Cache status error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * DELETE /api/v1.01/yile-admin/cache/:type
 * Clear cache (type: status, inventory, all)
 */
router.delete('/cache/:type', async (req, res) => {
  const { type } = req.params;

  try {
    if (type === 'status' || type === 'all') {
      await pool.query('DELETE FROM yile_machine_status');
    }

    if (type === 'inventory' || type === 'all') {
      await pool.query('DELETE FROM yile_inventory_cache');
    }

    // Log audit event
    await pool.query(`
      INSERT INTO yile_audit_events (event_type, actor, metadata_json, created_at)
      VALUES ('CACHE_CLEARED', $1, $2, NOW())
    `, [req.user?.id, JSON.stringify({ cacheType: type })]);

    res.json({
      success: true,
      message: `${type} cache cleared`,
    });
  } catch (error) {
    console.error('[Admin] Cache clear error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== RESET OPERATIONS ====================

/**
 * POST /api/v1.01/yile-admin/soft-reset
 * Soft reset: Clear cache + force token refresh
 */
router.post('/soft-reset', async (req, res) => {
  try {
    // Clear cache
    await pool.query('DELETE FROM yile_machine_status');
    await pool.query('DELETE FROM yile_inventory_cache');

    // Force token refresh
    await yileApi.refreshToken();

    // Log audit event
    await pool.query(`
      INSERT INTO yile_audit_events (event_type, actor, metadata_json, created_at)
      VALUES ('SOFT_RESET', $1, $2, NOW())
    `, [req.user?.id, JSON.stringify({ admin: true })]);

    res.json({
      success: true,
      message: 'Soft reset complete',
    });
  } catch (error) {
    console.error('[Admin] Soft reset error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * POST /api/v1.01/yile-admin/hard-reset
 * Hard reset: Delete token + clear cache + force new token
 */
router.post('/hard-reset', async (req, res) => {
  try {
    // Delete current token
    await pool.query("DELETE FROM vendor_tokens WHERE vendor = 'YILE'");

    // Clear cache
    await pool.query('DELETE FROM yile_machine_status');
    await pool.query('DELETE FROM yile_inventory_cache');

    // Clear in-flight commands
    await pool.query(`
      UPDATE yile_commands 
      SET status = 'FAIL', error_message = 'Hard reset', ended_at = NOW()
      WHERE status IN ('QUEUED', 'RUNNING')
    `);

    // Force new token fetch
    await yileApi.refreshToken();

    // Log audit event
    await pool.query(`
      INSERT INTO yile_audit_events (event_type, actor, metadata_json, created_at)
      VALUES ('HARD_RESET', $1, $2, NOW())
    `, [req.user?.id, JSON.stringify({ admin: true })]);

    res.json({
      success: true,
      message: 'Hard reset complete',
    });
  } catch (error) {
    console.error('[Admin] Hard reset error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== RATE LIMIT ====================

/**
 * GET /api/v1.01/yile-admin/rate-limit
 * Get current rate limit status
 */
router.get('/rate-limit', async (req, res) => {
  try {
    // This reads from the yileApi service's internal rate limiter
    const callsThisMinute = yileApi.callsThisMinute || 0;
    const maxPerMinute = yileApi.MAX_CALLS_PER_MINUTE || 100;
    const percentage = Math.round((callsThisMinute / maxPerMinute) * 100);
    
    const now = Date.now();
    const minuteStart = yileApi.minuteStart || now;
    const elapsed = now - minuteStart;
    const resetIn = Math.max(0, 60 - Math.floor(elapsed / 1000));

    res.json({
      success: true,
      data: {
        currentMinute: callsThisMinute,
        maxPerMinute: maxPerMinute,
        percentage: percentage,
        resetIn: resetIn,
      },
    });
  } catch (error) {
    console.error('[Admin] Rate limit error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== AUDIT LOG ====================

/**
 * GET /api/v1.01/yile-admin/audit-log
 * Get recent audit events
 */
router.get('/audit-log', async (req, res) => {
  const limit = parseInt(req.query.limit) || 50;

  try {
    const result = await pool.query(`
      SELECT event_id, event_type, actor, device_id, metadata_json, created_at
      FROM yile_audit_events
      ORDER BY created_at DESC
      LIMIT $1
    `, [limit]);

    res.json({
      success: true,
      data: result.rows.map(row => ({
        id: row.event_id,
        eventType: row.event_type,
        actor: row.actor,
        deviceId: row.device_id,
        metadata: row.metadata_json,
        createdAt: row.created_at,
      })),
    });
  } catch (error) {
    console.error('[Admin] Audit log error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// ==================== INVENTORY ====================

/**
 * GET /api/v1.01/yile-admin/sites/:siteId/inventory
 * Get inventory for admin panel
 */
router.get('/sites/:siteId/inventory', async (req, res) => {
  const { siteId } = req.params;

  try {
    const deviceResult = await pool.query(`
      SELECT yile_device_id FROM yile_devices WHERE site_id = $1
    `, [siteId]);

    if (deviceResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Device not found',
      });
    }

    const deviceId = deviceResult.rows[0].yile_device_id;
    const inventory = await yileApi.findInventory(deviceId);

    res.json({
      success: true,
      data: inventory,
    });
  } catch (error) {
    console.error('[Admin] Inventory error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

export default router;
