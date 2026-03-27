/**
 * SIPJOLT v1.01 Gate5 OS - Ghost Delivery API Routes (ES Module)
 * 
 * REST endpoints for unattended delivery workflow.
 */

import express from 'express';
import {
  validateGhostDelivery, completeGhostDelivery, checkGhostDeliveryEligibility,
  enableGhostDelivery, disableGhostDelivery, getGhostDeliveryHistory,
} from '../services/ghostDeliveryService.js';
import { requireHeaderAuth } from '../middleware/headerAuth.js';

const router = express.Router();

const requireDriverOrOps = requireHeaderAuth(['driver', 'ops_manager', 'ops_admin']);
const requireDriverOnly = requireHeaderAuth(['driver', 'ops_manager', 'ops_admin']);
const requireOpsOnly = requireHeaderAuth(['ops_manager', 'ops_admin']);
const requireHistoryRole = requireHeaderAuth(['ops_manager', 'ops_admin', 'technician', 'partner']);

// GET /api/v1.00/ghost/eligibility/:siteId - Check if site supports ghost delivery
router.get('/eligibility/:siteId', requireDriverOrOps, async (req, res) => {
  try {
    const eligibility = await checkGhostDeliveryEligibility(req.params.siteId);
    res.json(eligibility);
  } catch (error) {
    res.status(500).json({ error: 'ELIGIBILITY_CHECK_FAILED', message: error.message });
  }
});

// POST /api/v1.00/ghost/validate - Validate ghost delivery data (pre-flight check)
router.post('/validate', requireDriverOnly, async (req, res) => {
  try {
    const { siteId, gpsLatitude, gpsLongitude, accessCodeUsed, closetPhotoUrl } = req.body;
    if (!siteId) return res.status(400).json({ error: 'MISSING_SITE_ID' });

    const validation = await validateGhostDelivery({ siteId, gpsLatitude, gpsLongitude, accessCodeUsed, closetPhotoUrl });
    res.json({
      isValid: validation.isValid,
      errors: validation.errors,
      warnings: validation.warnings,
      locationAnomaly: validation.locationAnomaly,
      distanceMeters: validation.distanceMeters,
    });
  } catch (error) {
    res.status(500).json({ error: 'VALIDATION_FAILED', message: error.message });
  }
});

// POST /api/v1.00/ghost/complete - Complete ghost delivery
router.post('/complete', requireDriverOnly, async (req, res) => {
  try {
    const { deliveryId, siteId, accessCodeUsed, scannedBarcodes, closetPhotoUrl, gpsLatitude, gpsLongitude, clientTimestamp } = req.body;

    const missing = [];
    if (!deliveryId) missing.push('deliveryId');
    if (!siteId) missing.push('siteId');
    if (!scannedBarcodes || !Array.isArray(scannedBarcodes)) missing.push('scannedBarcodes');
    if (!closetPhotoUrl) missing.push('closetPhotoUrl');
    if (gpsLatitude === undefined) missing.push('gpsLatitude');
    if (gpsLongitude === undefined) missing.push('gpsLongitude');
    if (!clientTimestamp) missing.push('clientTimestamp');

    if (missing.length) return res.status(400).json({ error: 'MISSING_REQUIRED_FIELDS', message: `Missing: ${missing.join(', ')}` });

    const result = await completeGhostDelivery(
      { deliveryId, siteId, accessCodeUsed, scannedBarcodes, closetPhotoUrl, gpsLatitude, gpsLongitude, clientTimestamp },
      req.user.id
    );
    res.json({ success: true, ...result });
  } catch (error) {
    if (error.message.includes('validation failed')) return res.status(422).json({ error: 'GHOST_DELIVERY_VALIDATION_FAILED', message: error.message });
    if (error.message.includes('not found')) return res.status(404).json({ error: 'NOT_FOUND', message: error.message });
    res.status(500).json({ error: 'GHOST_DELIVERY_FAILED', message: error.message });
  }
});

// GET /api/v1.00/ghost/history/:siteId - Get ghost delivery history
router.get('/history/:siteId', requireHistoryRole, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const history = await getGhostDeliveryHistory(req.params.siteId, limit);
    res.json({ siteId: req.params.siteId, count: history.length, deliveries: history });
  } catch (error) {
    res.status(500).json({ error: 'HISTORY_FETCH_FAILED', message: error.message });
  }
});

// POST /api/v1.00/ghost/enable/:siteId - Enable ghost delivery for site
router.post('/enable/:siteId', requireOpsOnly, async (req, res) => {
  try {
    const { accessCode, geofenceRadius } = req.body;
    const site = await enableGhostDelivery(req.params.siteId, { accessCode, geofenceRadius }, req.user.id);
    res.json({
      success: true,
      message: `Ghost delivery enabled for ${site.venue_name}`,
      site: { siteId: site.site_id, venueName: site.venue_name, ghostDeliveryEnabled: true, hasAccessCode: !!site.closet_access_code, geofenceRadius: site.geofence_radius_meters },
    });
  } catch (error) {
    if (error.message.includes('not found')) return res.status(404).json({ error: 'SITE_NOT_FOUND', message: error.message });
    res.status(500).json({ error: 'ENABLE_FAILED', message: error.message });
  }
});

// POST /api/v1.00/ghost/disable/:siteId - Disable ghost delivery for site
router.post('/disable/:siteId', requireOpsOnly, async (req, res) => {
  try {
    const site = await disableGhostDelivery(req.params.siteId, req.user.id);
    res.json({ success: true, message: `Ghost delivery disabled for ${site.venue_name}` });
  } catch (error) {
    if (error.message.includes('not found')) return res.status(404).json({ error: 'SITE_NOT_FOUND', message: error.message });
    res.status(500).json({ error: 'DISABLE_FAILED', message: error.message });
  }
});

export default router;
