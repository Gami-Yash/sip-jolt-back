/**
 * SIPJOLT v1.00.0 - Ghost Delivery Service (ES Module)
 * 
 * Handles unattended delivery workflow when no one is at site:
 * 1. Driver enters closet access code
 * 2. Driver scans all boxes
 * 3. Driver takes closet photo (with GPS validation)
 * 4. System records POD and sets 24h acceptance deadline
 */

import { pool } from '../../shared/db.js';
import { haversineDistance, validateGeofence } from '../utils/geo.js';

const DEFAULT_GEOFENCE_RADIUS = 50; // meters

// Simple event logger
async function logEvent(eventData) {
  try {
    const { eventType, eventSubtype, tenantId, siteId, actorUserId, clientTimestamp, payload } = eventData;
    await pool.query(
      `INSERT INTO events (event_type, event_subtype, tenant_id, site_id, actor_user_id, client_timestamp, payload, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [eventType, eventSubtype || null, tenantId, siteId || null, actorUserId, clientTimestamp || new Date(), JSON.stringify(payload || {})]
    );
  } catch (err) {
    console.warn('[ghostDeliveryService] Event logging failed:', err.message);
  }
}

/**
 * Validates ghost delivery requirements
 */
export async function validateGhostDelivery(data) {
  const { siteId, gpsLatitude, gpsLongitude, accessCodeUsed, closetPhotoUrl } = data;

  const result = {
    isValid: true,
    errors: [],
    warnings: [],
    locationAnomaly: false,
    distanceMeters: null,
  };

  // Get site data
  const siteResult = await pool.query(
    `SELECT site_id, venue_name, lat, lng, geofence_radius_meters, closet_access_code, is_ghost_delivery_enabled, tenant_id
     FROM ops_sites WHERE site_id = $1`,
    [siteId]
  );

  if (!siteResult.rows[0]) {
    result.isValid = false;
    result.errors.push({ code: 'SITE_NOT_FOUND', message: `Site not found: ${siteId}` });
    return result;
  }

  const site = siteResult.rows[0];

  // Check 1: Ghost delivery enabled
  if (!site.is_ghost_delivery_enabled) {
    result.isValid = false;
    result.errors.push({ code: 'GHOST_DELIVERY_DISABLED', message: `Ghost delivery not enabled for ${site.venue_name}` });
    return result;
  }

  // Check 2: Access code
  if (site.closet_access_code) {
    if (!accessCodeUsed) {
      result.isValid = false;
      result.errors.push({ code: 'ACCESS_CODE_REQUIRED', message: 'Access code required for this site' });
    } else if (accessCodeUsed !== site.closet_access_code) {
      result.isValid = false;
      result.errors.push({ code: 'INVALID_ACCESS_CODE', message: 'Access code does not match' });
    }
  }

  // Check 3: GPS geofence
  if (site.lat && site.lng && gpsLatitude && gpsLongitude) {
    const radius = site.geofence_radius_meters || DEFAULT_GEOFENCE_RADIUS;
    const geoResult = validateGeofence(
      { lat: gpsLatitude, lng: gpsLongitude },
      { lat: parseFloat(site.lat), lng: parseFloat(site.lng) },
      radius
    );

    result.distanceMeters = geoResult.distanceMeters;
    if (!geoResult.isValid) {
      result.locationAnomaly = true;
      result.warnings.push({ code: 'LOCATION_ANOMALY', message: geoResult.message, distanceMeters: geoResult.distanceMeters });
    }
  } else if (!gpsLatitude || !gpsLongitude) {
    result.isValid = false;
    result.errors.push({ code: 'GPS_REQUIRED', message: 'GPS coordinates required for ghost delivery' });
  }

  // Check 4: Closet photo
  if (!closetPhotoUrl) {
    result.isValid = false;
    result.errors.push({ code: 'MISSING_CLOSET_PHOTO', message: 'Closet photo required for ghost delivery' });
  }

  result.site = site;
  return result;
}

/**
 * Completes a ghost delivery
 */
export async function completeGhostDelivery(data, driverId) {
  const { deliveryId, siteId, accessCodeUsed, scannedBarcodes, closetPhotoUrl, gpsLatitude, gpsLongitude, clientTimestamp } = data;

  // Validate
  const validation = await validateGhostDelivery({ siteId, gpsLatitude, gpsLongitude, accessCodeUsed, closetPhotoUrl });
  if (!validation.isValid) {
    throw new Error(`Ghost delivery validation failed: ${validation.errors.map(e => e.message).join(', ')}`);
  }

  // Log location anomaly if detected
  if (validation.locationAnomaly) {
    await logEvent({
      eventType: 'LOCATION_ANOMALY',
      eventSubtype: 'GHOST_DELIVERY',
      tenantId: validation.site.tenant_id,
      siteId,
      actorUserId: driverId,
      clientTimestamp: new Date(clientTimestamp),
      payload: validation.warnings[0],
    });
  }

  // Get delivery record
  const deliveryResult = await pool.query('SELECT * FROM ops_delivery_records WHERE delivery_id = $1', [deliveryId]);
  if (!deliveryResult.rows[0]) throw new Error(`Delivery not found: ${deliveryId}`);

  const podTimestamp = new Date(clientTimestamp);
  const acceptanceDeadline = new Date(podTimestamp.getTime() + 24 * 60 * 60 * 1000);

  // Update delivery record
  const result = await pool.query(
    `UPDATE ops_delivery_records SET
      status = 'DELIVERED', is_ghost_delivery = TRUE, ghost_access_code_used = $1, ghost_closet_photo_url = $2,
      driver_proof_photo_url = $2, driver_proof_photo_timestamp = $3, driver_gps_lat = $4, driver_gps_lng = $5,
      driver_gps_validated = $6, pod_timestamp = $3, acceptance_deadline = $7, delivered_at = $3, updated_at = NOW()
     WHERE delivery_id = $8 RETURNING *`,
    [accessCodeUsed, closetPhotoUrl, podTimestamp, gpsLatitude, gpsLongitude, !validation.locationAnomaly, acceptanceDeadline, deliveryId]
  );

  // Update box scan timestamps
  if (scannedBarcodes?.length > 0) {
    await pool.query(
      `UPDATE boxes SET scanned_at_delivery = $1, updated_at = NOW() WHERE barcode = ANY($2)`,
      [podTimestamp, scannedBarcodes]
    );
  }

  // Log event
  await logEvent({
    eventType: 'GHOST_DELIVERY_COMPLETE',
    tenantId: validation.site.tenant_id,
    siteId,
    actorUserId: driverId,
    clientTimestamp: podTimestamp,
    payload: {
      deliveryId, closetPhotoUrl, gpsValidated: !validation.locationAnomaly, distanceMeters: validation.distanceMeters,
      scannedBoxCount: scannedBarcodes?.length || 0, acceptanceDeadline: acceptanceDeadline.toISOString(),
    },
  });

  return {
    delivery: result.rows[0],
    validation: { gpsValidated: !validation.locationAnomaly, distanceMeters: validation.distanceMeters, boxesScanned: scannedBarcodes?.length || 0 },
    acceptanceDeadline,
    message: validation.locationAnomaly ? 'Ghost delivery complete with location anomaly flag' : 'Ghost delivery complete. Partner has 24h to accept.',
  };
}

/**
 * Checks if site supports ghost delivery
 */
export async function checkGhostDeliveryEligibility(siteId) {
  const result = await pool.query(
    `SELECT site_id, venue_name, is_ghost_delivery_enabled, closet_access_code, lat, lng, geofence_radius_meters
     FROM ops_sites WHERE site_id = $1`,
    [siteId]
  );

  if (!result.rows[0]) return { eligible: false, reason: 'Site not found' };

  const site = result.rows[0];
  return {
    eligible: site.is_ghost_delivery_enabled,
    siteId: site.site_id,
    siteName: site.venue_name,
    requiresAccessCode: !!site.closet_access_code,
    hasGpsCoordinates: !!(site.lat && site.lng),
    geofenceRadius: site.geofence_radius_meters || DEFAULT_GEOFENCE_RADIUS,
    reason: site.is_ghost_delivery_enabled ? 'Ghost delivery enabled' : 'Ghost delivery not enabled',
  };
}

/**
 * Enables ghost delivery for a site
 */
export async function enableGhostDelivery(siteId, config, userId) {
  const { accessCode, geofenceRadius } = config;

  const result = await pool.query(
    `UPDATE ops_sites SET is_ghost_delivery_enabled = TRUE, closet_access_code = COALESCE($1, closet_access_code),
     geofence_radius_meters = COALESCE($2, geofence_radius_meters, 50), updated_at = NOW()
     WHERE site_id = $3 RETURNING *`,
    [accessCode, geofenceRadius, siteId]
  );

  if (!result.rows[0]) throw new Error(`Site not found: ${siteId}`);

  await logEvent({
    eventType: 'GHOST_DELIVERY_ENABLED',
    tenantId: result.rows[0].tenant_id,
    siteId,
    actorUserId: userId,
    payload: { accessCodeSet: !!accessCode, geofenceRadius: geofenceRadius || 50 },
  });

  return result.rows[0];
}

/**
 * Disables ghost delivery for a site
 */
export async function disableGhostDelivery(siteId, userId) {
  const result = await pool.query(
    `UPDATE ops_sites SET is_ghost_delivery_enabled = FALSE, updated_at = NOW() WHERE site_id = $1 RETURNING *`,
    [siteId]
  );

  if (!result.rows[0]) throw new Error(`Site not found: ${siteId}`);

  await logEvent({
    eventType: 'GHOST_DELIVERY_DISABLED',
    tenantId: result.rows[0].tenant_id,
    siteId,
    actorUserId: userId,
    payload: {},
  });

  return result.rows[0];
}

/**
 * Gets ghost delivery history for a site
 */
export async function getGhostDeliveryHistory(siteId, limit = 20) {
  const result = await pool.query(
    `SELECT d.*, u.name as driver_name FROM ops_delivery_records d
     LEFT JOIN jolt_users u ON d.driver_id = u.id
     WHERE d.site_id = $1 AND d.is_ghost_delivery = TRUE
     ORDER BY d.delivered_at DESC LIMIT $2`,
    [siteId, limit]
  );
  return result.rows;
}

export { DEFAULT_GEOFENCE_RADIUS };
