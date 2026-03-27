import express from 'express';
import { getPool } from './db.js';
import { consequenceEngineService } from './consequence-engine.js';
import { featureFlagService, FEATURE_FLAGS } from './feature-flags.js';
import { eventLogService } from './services/eventLog.js';

const router = express.Router();
const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

const CLOCK_DRIFT_THRESHOLD_MINUTES = 30;

const checkClockDrift = (clientTimestamp) => {
  if (!clientTimestamp) return { hasDrift: false };
  
  const clientTime = new Date(clientTimestamp).getTime();
  const serverTime = Date.now();
  const driftMinutes = Math.abs(serverTime - clientTime) / (1000 * 60);
  
  return {
    hasDrift: driftMinutes > CLOCK_DRIFT_THRESHOLD_MINUTES,
    driftMinutes: Math.round(driftMinutes),
    threshold: CLOCK_DRIFT_THRESHOLD_MINUTES
  };
};

router.get('/machine/:id/config', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = getPool();
    
    const siteResult = await pool.query(`
      SELECT site_id, venue_name as name, status, lat, lng FROM ops_sites WHERE site_id = $1
    `, [id]);
    
    const machineResult = await pool.query(`
      SELECT machine_id, safe_mode, status FROM machines WHERE machine_id = $1
    `, [id]);
    
    const site = siteResult.rows[0];
    const machine = machineResult.rows[0];
    
    const isSafeMode = site?.status === 'SAFE_MODE' || 
                       site?.status === 'LOCKED' || 
                       machine?.safe_mode === true;
    
    const serverUtcNow = new Date().toISOString();
    
    if (isSafeMode) {
      return res.json({
        syrups_enabled: false,
        matcha_enabled: false,
        screen_mode: 'RESTRICTED',
        alert_text: 'System Maintenance in Progress',
        status: site?.status || 'SAFE_MODE',
        recovery_required: true,
        server_utc_now: serverUtcNow
      });
    }
    
    res.json({
      syrups_enabled: true,
      matcha_enabled: true,
      screen_mode: 'FULL',
      status: 'ACTIVE',
      recovery_required: false,
      server_utc_now: serverUtcNow
    });
  } catch (error) {
    console.error('Machine config error:', error);

    // In non-production environments, fall back to a safe default
    // config instead of surfacing a 500 when the database is
    // unreachable or not yet provisioned.
    if (process.env.NODE_ENV !== 'production') {
      const serverUtcNow = new Date().toISOString();
      return res.json({
        syrups_enabled: true,
        matcha_enabled: true,
        screen_mode: 'FULL',
        status: 'ACTIVE',
        recovery_required: false,
        server_utc_now: serverUtcNow,
        note: 'DEV_FALLBACK: DB unreachable, returning default machine config.'
      });
    }

    res.status(500).json({ error: 'Machine configuration unavailable' });
  }
});

router.get('/daily-token', async (req, res) => {
  try {
    const pool = getPool();
    const today = new Date().toISOString().split('T')[0];
    
    const result = await pool.query(`
      SELECT code FROM daily_tokens WHERE date = $1
    `, [today]);
    
    if (result.rows[0]) {
      res.json({ date: today, code: result.rows[0].code });
    } else {
      const code = Math.floor(100 + Math.random() * 900).toString();
      
      await pool.query(`
        INSERT INTO daily_tokens (date, code) VALUES ($1, $2)
        ON CONFLICT (date) DO NOTHING
      `, [today, code]);
      
      res.json({ date: today, code: code });
    }
  } catch (error) {
    console.error('Daily token error:', error);

    // For local development, allow the app to keep working even if
    // the database is down by returning a deterministic fallback
    // token instead of a 500.
    if (process.env.NODE_ENV !== 'production') {
      const fallbackCode = '123';
      const today = new Date().toISOString().split('T')[0];
      return res.json({
        date: today,
        code: fallbackCode,
        note: 'DEV_FALLBACK: DB unreachable, using static daily token.'
      });
    }

    res.status(500).json({ error: 'Daily token service unavailable' });
  }
});

router.post('/validate-token', async (req, res) => {
  try {
    const { code, siteId } = req.body;
    const pool = getPool();
    const today = new Date().toISOString().split('T')[0];
    
    const result = await pool.query(`
      SELECT code FROM daily_tokens WHERE date = $1
    `, [today]);
    
    if (!result.rows[0]) {
      return res.json({ valid: false, reason: 'No token for today' });
    }
    
    const isValid = result.rows[0].code === code;
    
    await pool.query(`
      INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [
      generateId('EVT'),
      isValid ? 'TOKEN_VALIDATED' : 'TOKEN_FAILED',
      siteId,
      1,
      JSON.stringify({ attempted_code: code, valid: isValid })
    ]);
    
    res.json({ valid: isValid });
  } catch (error) {
    console.error('Token validation error:', error);

    // In dev, keep the flow unblocked even if the DB cannot be
    // reached. Mirror the fallback used in /daily-token.
    if (process.env.NODE_ENV !== 'production') {
      const { code } = req.body || {};
      const fallbackCode = '123';
      const isValid = code === fallbackCode;
      return res.json({
        valid: isValid,
        note: 'DEV_FALLBACK: validation performed without database.'
      });
    }

    res.status(500).json({ error: 'Token validation service unavailable' });
  }
});

router.post('/recovery/submit', async (req, res) => {
  try {
    const { siteId, tokenPhotoUrl, squeezeVideoUrl, userId } = req.body;
    const pool = getPool();
    
    if (!siteId || !tokenPhotoUrl || !squeezeVideoUrl) {
      return res.status(400).json({ 
        error: 'Recovery items required: tokenPhoto and squeezeVideo' 
      });
    }
    
    const recoveryId = generateId('REC');
    
    await pool.query(`
      INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [
      generateId('EVT'),
      'SAFE_MODE_EXIT_ATTEMPT',
      siteId,
      userId || 1,
      JSON.stringify({
        recovery_id: recoveryId,
        token_photo: tokenPhotoUrl,
        squeeze_video: squeezeVideoUrl
      })
    ]);
    
    await pool.query(`
      UPDATE ops_sites SET status = 'ACTIVE', updated_at = NOW() WHERE site_id = $1
    `, [siteId]);
    
    await pool.query(`
      UPDATE machines SET safe_mode = FALSE, safe_mode_exited_at = NOW() WHERE machine_id = $1
    `, [siteId]);
    
    await pool.query(`
      INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [
      generateId('EVT'),
      'SAFE_MODE_EXIT',
      siteId,
      userId || 1,
      JSON.stringify({ recovery_id: recoveryId, method: '2_point_recovery' })
    ]);
    
    res.json({ 
      success: true, 
      recoveryId,
      message: 'Site recovered from SAFE_MODE' 
    });
  } catch (error) {
    console.error('Recovery submit error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/pending-tasks/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const pool = getPool();
    
    const tasks = [];
    
    const pendingAcceptance = await pool.query(`
      SELECT d.*, s.venue_name as site_name 
      FROM ops_delivery_records d
      JOIN ops_sites s ON d.site_id = s.site_id
      JOIN user_site_assignments usa ON s.site_id = usa.site_id
      WHERE usa.user_id = $1 
        AND d.partner_accepted_at IS NULL 
        AND d.partner_refused IS NULL
        AND d.delivered_at IS NOT NULL
      ORDER BY d.delivered_at ASC
    `, [userId]);
    
    for (const delivery of pendingAcceptance.rows) {
      const podTime = new Date(delivery.delivered_at).getTime();
      const deadline = podTime + (24 * 60 * 60 * 1000);
      
      tasks.push({
        id: `accept-${delivery.id}`,
        type: 'PENDING_ACCEPTANCE',
        deliveryId: delivery.id,
        siteId: delivery.site_id,
        siteName: delivery.site_name,
        deadline: new Date(deadline).toISOString(),
        isOverdue: Date.now() > deadline,
        createdAt: delivery.delivered_at
      });
    }
    
    const pendingPod = await pool.query(`
      SELECT sh.*, s.venue_name as site_name
      FROM ops_shipments sh
      JOIN ops_sites s ON sh.site_id = s.site_id
      WHERE sh.driver_id = $1 
        AND sh.status = 'in_transit'
      ORDER BY sh.created_at ASC
    `, [userId]);
    
    for (const shipment of pendingPod.rows) {
      tasks.push({
        id: `pod-${shipment.shipment_id}`,
        type: 'PENDING_POD',
        shipmentId: shipment.shipment_id,
        siteId: shipment.site_id,
        siteName: shipment.site_name,
        createdAt: shipment.created_at
      });
    }
    
    const priorityOrder = ['PENDING_ACCEPTANCE', 'PENDING_POD', 'PENDING_REFILL', 'WEEKLY_DUE'];
    tasks.sort((a, b) => {
      const aIdx = priorityOrder.indexOf(a.type);
      const bIdx = priorityOrder.indexOf(b.type);
      if (aIdx !== bIdx) return aIdx - bIdx;
      if (a.isOverdue && !b.isOverdue) return -1;
      if (!a.isOverdue && b.isOverdue) return 1;
      return 0;
    });
    
    res.json({ tasks });
  } catch (error) {
    console.error('Pending tasks error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/gps-validate', async (req, res) => {
  try {
    const { siteId, lat, lng } = req.body;
    const pool = getPool();
    
    const site = await pool.query(`
      SELECT lat, lng, venue_name as name FROM ops_sites WHERE site_id = $1
    `, [siteId]);
    
    if (!site.rows[0] || !site.rows[0].lat || !site.rows[0].lng) {
      return res.json({ valid: true, reason: 'Site has no geofence configured' });
    }
    
    const siteLat = parseFloat(site.rows[0].lat);
    const siteLng = parseFloat(site.rows[0].lng);
    
    const R = 6371e3;
    const φ1 = lat * Math.PI / 180;
    const φ2 = siteLat * Math.PI / 180;
    const Δφ = (siteLat - lat) * Math.PI / 180;
    const Δλ = (siteLng - lng) * Math.PI / 180;
    
    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    const distance = R * c;
    
    const GEOFENCE_RADIUS_M = 50;
    const isValid = distance <= GEOFENCE_RADIUS_M;
    
    res.json({
      valid: isValid,
      distance: Math.round(distance),
      maxDistance: GEOFENCE_RADIUS_M,
      siteName: site.rows[0].name
    });
  } catch (error) {
    console.error('GPS validate error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/sync-sla-check', async (req, res) => {
  try {
    const { userId, pendingItems } = req.body;
    const pool = getPool();
    const breaches = [];
    const clockAnomalies = [];
    const SLA_HOURS = 6;
    
    for (const item of pendingItems || []) {
      const clientTime = new Date(item.clientTimestamp).getTime();
      const hoursSinceCreation = (Date.now() - clientTime) / (1000 * 60 * 60);
      
      const clockDrift = checkClockDrift(item.clientTimestamp);
      if (clockDrift.hasDrift) {
        clockAnomalies.push({
          itemId: item.id,
          type: item.type,
          driftMinutes: clockDrift.driftMinutes,
          siteId: item.siteId
        });
        
        await eventLogService.appendEvent({
          eventType: 'CLOCK_ANOMALY',
          actorUserId: userId || 1,
          siteId: item.siteId,
          payload: {
            item_id: item.id,
            item_type: item.type,
            drift_minutes: clockDrift.driftMinutes,
            client_timestamp: item.clientTimestamp
          }
        });
      }
      
      if (hoursSinceCreation > SLA_HOURS) {
        breaches.push({
          itemId: item.id,
          type: item.type,
          hoursPending: Math.round(hoursSinceCreation * 10) / 10,
          siteId: item.siteId
        });
      }
    }
    
    if (breaches.length > 0) {
      const incidentId = generateId('INC');
      
      await pool.query(`
        INSERT INTO ops_incidents (incident_id, type, severity, title, description, status, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
      `, [
        incidentId,
        'sync_sla_violation',
        'high',
        `Sync SLA Breach: ${breaches.length} items overdue`,
        `User ${userId} has ${breaches.length} items exceeding 6-hour sync SLA`,
        'open'
      ]);
      
      for (const breach of breaches) {
        if (breach.siteId) {
          await pool.query(`
            UPDATE ops_sites SET status = 'SAFE_MODE', updated_at = NOW() WHERE site_id = $1
          `, [breach.siteId]);
        }
      }
    }
    
    res.json({
      breaches,
      clockAnomalies,
      hasBreaches: breaches.length > 0,
      hasClockAnomalies: clockAnomalies.length > 0,
      slaHours: SLA_HOURS
    });
  } catch (error) {
    console.error('Sync SLA check error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/refill/complete', async (req, res) => {
  try {
    const { siteId, userId, refillData, beforePhotoUrl, afterPhotoUrl } = req.body;
    const pool = getPool();
    
    if (!siteId) {
      return res.status(400).json({ error: 'siteId is required' });
    }
    
    if (!beforePhotoUrl || !afterPhotoUrl) {
      return res.status(400).json({ 
        error: 'Before and After photos are required',
        code: 'MISSING_PHOTOS',
        message: 'You must capture Before and After photos to complete the refill'
      });
    }
    
    const refillId = generateId('REFILL');
    
    await eventLogService.appendEvent({
      eventType: 'REFILL_COMPLETED',
      actorUserId: userId || 1,
      siteId,
      payload: {
        refill_id: refillId,
        before_photo_url: beforePhotoUrl,
        after_photo_url: afterPhotoUrl,
        refill_data: refillData
      }
    });
    
    res.json({ 
      success: true, 
      refillId,
      message: 'Refill completed successfully'
    });
  } catch (error) {
    console.error('Refill complete error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/pod/submit', async (req, res) => {
  try {
    const { shipmentId, siteId, userId, photoUrl, gpsValidated, lat, lng, clientTimestamp } = req.body;
    const pool = getPool();
    
    if (!photoUrl) {
      return res.status(400).json({ 
        error: 'Photo is required for POD',
        code: 'MISSING_PHOTO'
      });
    }
    
    if (!gpsValidated) {
      return res.status(400).json({ 
        error: 'GPS validation is required for POD',
        code: 'GPS_NOT_VALIDATED',
        message: 'You must be within 50 meters of the delivery location'
      });
    }
    
    const clockDrift = checkClockDrift(clientTimestamp);
    
    const deliveryId = generateId('DEL');
    
    await pool.query(`
      INSERT INTO ops_delivery_records (site_id, pod_photo, driver_lat, driver_lng, delivered_at, client_timestamp)
      VALUES ($1, $2, $3, $4, NOW(), $5)
    `, [siteId, photoUrl, lat, lng, clientTimestamp || new Date().toISOString()]);
    
    if (shipmentId) {
      await pool.query(`
        UPDATE ops_shipments SET status = 'delivered', updated_at = NOW() WHERE shipment_id = $1
      `, [shipmentId]);
    }
    
    const eventPayload = {
      shipment_id: shipmentId,
      photo_url: photoUrl,
      gps_validated: gpsValidated,
      lat,
      lng
    };
    
    if (clockDrift.hasDrift) {
      eventPayload.clock_anomaly = true;
      eventPayload.drift_minutes = clockDrift.driftMinutes;
      // SILENT FLAG: We log the anomaly but do NOT block submission
    }
    
    await eventLogService.appendEvent({
      eventType: 'POD_SUBMITTED', // Keep standard event type
      actorUserId: userId || 1,
      siteId,
      clientTimestamp: clientTimestamp || new Date().toISOString(),
      geoLat: lat,
      geoLng: lng,
      payload: eventPayload
    });
    
    res.json({ 
      success: true, 
      deliveryId,
      message: 'Proof of Delivery submitted successfully',
      clockAnomaly: clockDrift.hasDrift ? clockDrift : null
    });
  } catch (error) {
    console.error('POD submit error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/reliability/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const pool = getPool();
    
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    
    const submissions = await pool.query(`
      SELECT COUNT(*) as count FROM events 
      WHERE actor_user_id = $1 
        AND event_type IN ('PROOF_SUBMITTED', 'PHOTO_SYNCED', 'POD_SUBMITTED')
        AND server_timestamp > $2
    `, [userId, thirtyDaysAgo]);
    
    const rejections = await pool.query(`
      SELECT COUNT(*) as count FROM events 
      WHERE actor_user_id = $1 
        AND event_type = 'PROOF_REJECTED'
        AND server_timestamp > $2
    `, [userId, thirtyDaysAgo]);
    
    const lateAcceptances = await pool.query(`
      SELECT COUNT(*) as count FROM events 
      WHERE actor_user_id = $1 
        AND event_type IN ('ACCEPTANCE_OVERDUE', 'SYNC_SLA_BREACH')
        AND server_timestamp > $2
    `, [userId, thirtyDaysAgo]);
    
    const submissionCount = parseInt(submissions.rows[0].count) || 0;
    const rejectionCount = parseInt(rejections.rows[0].count) || 0;
    const lateCount = parseInt(lateAcceptances.rows[0].count) || 0;
    
    const rejectionRate = submissionCount > 0 
      ? (rejectionCount / submissionCount) * 100 
      : 0;
    
    let status = 'green';
    if (rejectionRate > 20 || lateCount >= 3) {
      status = 'red';
    } else if (rejectionRate > 5 || lateCount >= 1) {
      status = 'yellow';
    }
    
    const isRestricted = status === 'red';
    
    if (isRestricted) {
      await pool.query(`
        UPDATE jolt_users SET restricted_mode = TRUE, restricted_mode_reason = 'low_reliability'
        WHERE user_id = $1 AND (restricted_mode IS NULL OR restricted_mode = FALSE)
      `, [userId]);
    }
    
    res.json({
      userId,
      status,
      rejectionRate: Math.round(rejectionRate * 10) / 10,
      lateAcceptances: lateCount,
      proofSubmissions: submissionCount,
      proofRejections: rejectionCount,
      isRestricted
    });
  } catch (error) {
    console.error('Reliability check error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/onboarding-complete', async (req, res) => {
  try {
    const { user_id, user_role, completed_at, logic_test_passed, evidence_hash } = req.body;
    const pool = getPool();
    
    await pool.query(`
      INSERT INTO training_flags (user_id, flag_key, flag_value, updated_at)
      VALUES ($1, 'onboarding_v1.00_complete', $2, NOW())
      ON CONFLICT (user_id, flag_key) DO UPDATE SET flag_value = $2, updated_at = NOW()
    `, [user_id, JSON.stringify({ completed_at, logic_test_passed, evidence_hash, user_role })]);
    
    await pool.query(`
      INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [
      generateId('EVT'),
      'ONBOARDING_COMPLETE',
      'system',
      user_id,
      JSON.stringify({ user_role, completed_at, logic_test_passed, evidence_hash })
    ]);
    
    console.log(`[Onboarding] User ${user_id} (${user_role}) completed training, hash: ${evidence_hash?.substring(0, 16)}...`);
    
    res.json({ success: true, logged: true });
  } catch (error) {
    console.error('Onboarding complete error:', error);
    res.json({ success: true, logged: false, error: error.message });
  }
});

router.post('/user/recertify', async (req, res) => {
  try {
    const { user_id, passed_at, quiz_score } = req.body;
    const pool = getPool();
    
    await pool.query(`
      INSERT INTO training_flags (user_id, flag_key, flag_value, updated_at)
      VALUES ($1, 'recertification_passed', $2, NOW())
      ON CONFLICT (user_id, flag_key) DO UPDATE SET flag_value = $2, updated_at = NOW()
    `, [user_id, JSON.stringify({ passed_at, quiz_score, new_score: 80, badge: 'yellow' })]);
    
    await pool.query(`
      INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [
      generateId('EVT'),
      'RECERTIFICATION_COMPLETE',
      'system',
      user_id,
      JSON.stringify({ passed_at, quiz_score, new_reliability_score: 80 })
    ]);
    
    console.log(`[Recertification] User ${user_id} passed recertification, score reset to 80`);
    
    res.json({ success: true, newReliabilityScore: 80, badge: 'yellow' });
  } catch (error) {
    console.error('Recertification error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/ops-warning', async (req, res) => {
  try {
    const { type, message, siteId, userId } = req.body;
    const pool = getPool();
    
    await pool.query(`
      INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [
      generateId('EVT'),
      'OPS_WARNING',
      siteId || 'system',
      userId || 1,
      JSON.stringify({ type, warning_message: message })
    ]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Ops warning error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/ghost/eligibility/:siteId', async (req, res) => {
  try {
    const { siteId } = req.params;
    const pool = getPool();
    
    const site = await pool.query(`
      SELECT ghost_delivery_enabled, closet_access_code FROM ops_sites WHERE site_id = $1
    `, [siteId]);
    
    if (!site.rows[0]) {
      return res.json({ eligible: false });
    }
    
    res.json({
      eligible: site.rows[0].ghost_delivery_enabled || true, // Default to true for v1.00 testing
      requiresAccessCode: !!site.rows[0].closet_access_code
    });
  } catch (error) {
    console.error('Ghost eligibility error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/ghost/complete', async (req, res) => {
  try {
    const { deliveryId, siteId, scannedBarcodes, closetPhotoUrl, gpsLatitude, gpsLongitude } = req.body;
    const pool = getPool();
    
    await pool.query(`
      INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [
      generateId('EVT'),
      'GHOST_DELIVERY_COMPLETE',
      siteId,
      1,
      JSON.stringify({ 
        delivery_id: deliveryId, 
        barcodes: scannedBarcodes, 
        photo: closetPhotoUrl,
        gps: { lat: gpsLatitude, lng: gpsLongitude }
      })
    ]);
    
    res.json({ success: true, message: 'Ghost delivery completed' });
  } catch (error) {
    console.error('Ghost complete error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
