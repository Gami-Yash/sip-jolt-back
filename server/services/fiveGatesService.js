/**
 * SIPJOLT v1.00.0 - Five Gates Service (ES Module)
 * 
 * Core business logic for the 5-gate QC packing workflow:
 * - Gate 1: Zero Check (scale calibration)
 * - Gate 2: Freshness Lock (oxygen absorbers for BOX_B)
 * - Gate 3: Weight Law (46.5 lb scale lock, 47.0 lb hard limit)
 * - Gate 4: Movement + Compression + Lid Bounce (v1.00 NEW)
 * - Gate 5: Envelope Sticker (traffic light color coding)
 */

import { pool } from '../../shared/db.js';
import {
  validateBoxWeight,
  validateGate4Complete,
  validateGate5Sticker,
  getExpectedStickerColor,
  WEIGHT_LIMITS,
} from '../utils/weightValidator.js';

// Box type configurations (v1.00 CORRECTED)
export const BOX_CONFIGS = {
  BOX_A: { color: 'RED', shelf: 'SHELF 1 (BOTTOM)', description: 'Syrup Jugs', requiresOxygenAbsorbers: false, requiresRedCaps: true, requiresLiquidFortress: true },
  BOX_B1: { color: 'GREEN', shelf: 'SHELF 2+3', description: '9 Oat Powder (Z-B) + 1 Cleaning Kit (Z-C)', requiresOxygenAbsorbers: true, requiresRedCaps: false, requiresKraftWall: true },
  BOX_B2: { color: 'GREEN', shelf: 'SHELF 2', description: '7 Dairy Powder + 6 Cocoa Powder', requiresOxygenAbsorbers: true, requiresRedCaps: false },
  BOX_C: { color: 'YELLOW', shelf: 'SHELF 4 (TOP)', description: '10 Coffee + 3 Sugar + 4 Chai', requiresOxygenAbsorbers: false, requiresRedCaps: false },
  CARTON_E: { color: 'BLUE', shelf: 'FLOOR', description: '4 Cup Boxes + Lids', requiresOxygenAbsorbers: false, requiresRedCaps: false },
};

// Backward compatibility: BOX_CD → BOX_C alias for legacy data migration
BOX_CONFIGS.BOX_CD = BOX_CONFIGS.BOX_C;

// Normalize legacy box types to v1.00 spec
export function normalizeBoxType(boxType) {
  if (boxType === 'BOX_CD') return 'BOX_C';
  return boxType;
}

// Simple event logger (uses existing events table if available)
async function logEvent(eventData) {
  try {
    const { eventType, eventSubtype, tenantId, siteId, actorUserId, clientTimestamp, payload } = eventData;
    await pool.query(
      `INSERT INTO events (event_type, event_subtype, tenant_id, site_id, actor_user_id, client_timestamp, payload, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [eventType, eventSubtype || null, tenantId, siteId || null, actorUserId, clientTimestamp || new Date(), JSON.stringify(payload || {})]
    );
  } catch (err) {
    console.warn('[fiveGatesService] Event logging failed:', err.message);
  }
}

/**
 * Creates a new box and initiates 5-gate workflow
 */
export async function createBox(boxData) {
  const { tenantId, shipmentId, boxType, boxSequence = 1, boxTotal = 1, bomContents = [], packedByUserId } = boxData;

  const config = BOX_CONFIGS[boxType];
  if (!config) throw new Error(`Invalid box type: ${boxType}`);

  const barcode = `${tenantId.substring(0, 4).toUpperCase()}-${shipmentId.substring(0, 6)}-${boxSequence}-${Date.now().toString(36).toUpperCase()}`;

  const result = await pool.query(
    `INSERT INTO boxes (tenant_id, shipment_id, box_type, box_label_color, box_sequence, box_total, bom_contents, barcode, packed_by_user_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
    [tenantId, shipmentId, boxType, config.color, boxSequence, boxTotal, JSON.stringify(bomContents), barcode, packedByUserId]
  );

  await logEvent({
    eventType: 'BOX_CREATED',
    tenantId,
    actorUserId: packedByUserId,
    payload: { boxId: result.rows[0].box_id, boxType, shipmentId },
  });

  return result.rows[0];
}

/**
 * Gate 1: Zero Check (Scale Calibration)
 */
export async function processGate1(boxId, gateData, userId) {
  const { calibrationWeightLbs } = gateData;
  const isValid = calibrationWeightLbs >= 9.5 && calibrationWeightLbs <= 10.5;

  const result = await pool.query(
    `UPDATE boxes SET gate_1_scale_tared_at = NOW(), gate_1_calibration_weight_lbs = $1, gate_1_passed = $2, updated_at = NOW()
     WHERE box_id = $3 RETURNING *`,
    [calibrationWeightLbs, isValid, boxId]
  );

  if (!result.rows[0]) throw new Error(`Box not found: ${boxId}`);

  await logEvent({
    eventType: 'GATE_1_COMPLETE',
    tenantId: result.rows[0].tenant_id,
    actorUserId: userId,
    payload: { boxId, calibrationWeightLbs, passed: isValid },
  });

  return {
    box: result.rows[0],
    gateResult: { gate: 1, name: 'Zero Check', passed: isValid, message: isValid ? 'Scale calibrated' : `Calibration ${calibrationWeightLbs} lbs outside 9.5-10.5 range` },
  };
}

/**
 * Gate 2: Freshness Lock (Oxygen Absorbers)
 */
export async function processGate2(boxId, gateData, userId) {
  const { absorberCount, confirmed } = gateData;

  const boxResult = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!boxResult.rows[0]) throw new Error(`Box not found: ${boxId}`);

  const box = boxResult.rows[0];
  const config = BOX_CONFIGS[box.box_type];
  
  let passed = false, message = '';
  if (!config.requiresOxygenAbsorbers) {
    passed = true;
    message = `Gate 2 not required for ${box.box_type}`;
  } else if (confirmed && absorberCount > 0) {
    passed = true;
    message = `${absorberCount} oxygen absorbers confirmed`;
  } else {
    message = 'Oxygen absorbers required for dry goods';
  }

  const result = await pool.query(
    `UPDATE boxes SET gate_2_oxygen_absorbers_count = $1, gate_2_passed = $2, updated_at = NOW() WHERE box_id = $3 RETURNING *`,
    [absorberCount, passed, boxId]
  );

  await logEvent({
    eventType: 'GATE_2_COMPLETE',
    tenantId: box.tenant_id,
    actorUserId: userId,
    payload: { boxId, absorberCount, passed },
  });

  return { box: result.rows[0], gateResult: { gate: 2, name: 'Freshness Lock', passed, message, required: config.requiresOxygenAbsorbers } };
}

/**
 * Gate 3: Weight Law (Hub Sovereign - immutable enforcement)
 */
export async function processGate3(boxId, gateData, userId) {
  const { tareWeightLbs, finalWeightLbs } = gateData;

  const boxResult = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!boxResult.rows[0]) throw new Error(`Box not found: ${boxId}`);

  const box = boxResult.rows[0];
  const validation = validateBoxWeight(box.box_type, finalWeightLbs);

  // DB trigger will also enforce, but we validate here for immediate feedback
  const result = await pool.query(
    `UPDATE boxes SET gate_3_tare_weight_lbs = $1, gate_3_final_weight_lbs = $2, gate_3_passed = $3, gate_3_split_required = $4, updated_at = NOW()
     WHERE box_id = $5 RETURNING *`,
    [tareWeightLbs, finalWeightLbs, validation.isValid, validation.requiresSplit, boxId]
  );

  await logEvent({
    eventType: 'GATE_3_COMPLETE',
    eventSubtype: validation.isValid ? 'PASSED' : (validation.requiresSplit ? 'SPLIT_REQUIRED' : 'FAILED'),
    tenantId: box.tenant_id,
    actorUserId: userId,
    payload: { boxId, tareWeightLbs, finalWeightLbs, passed: validation.isValid, splitRequired: validation.requiresSplit, errorCode: validation.errorCode, warnings: validation.warnings },
  });

  return {
    box: result.rows[0],
    gateResult: {
      gate: 3, name: 'Weight Law', passed: validation.isValid, splitRequired: validation.requiresSplit,
      message: validation.errorMessage || (validation.isValid ? `Weight ${finalWeightLbs} lbs approved` : 'Weight validation failed'),
      warnings: validation.warnings, limits: WEIGHT_LIMITS,
    },
  };
}

/**
 * Gate 4: Movement + Compression + Lid Bounce (v1.00 NEW: lid bounce test)
 */
export async function processGate4(boxId, gateData, userId) {
  const { shakePassed, compressionSinkInches, lidBounceInches } = gateData;

  const boxResult = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!boxResult.rows[0]) throw new Error(`Box not found: ${boxId}`);

  const box = boxResult.rows[0];
  const validation = validateGate4Complete({ shakePassed, compressionSinkInches, lidBounceInches });

  const result = await pool.query(
    `UPDATE boxes SET gate_4_shake_passed = $1, gate_4_compression_sink_inches = $2, gate_4_compression_passed = $3,
     gate_4_lid_bounce_inches = $4, gate_4_lid_bounce_passed = $5, updated_at = NOW() WHERE box_id = $6 RETURNING *`,
    [shakePassed, compressionSinkInches, validation.compression?.isValid ?? false, lidBounceInches, validation.lidBounce?.isValid ?? false, boxId]
  );

  await logEvent({
    eventType: 'GATE_4_COMPLETE',
    tenantId: box.tenant_id,
    actorUserId: userId,
    payload: { boxId, shakePassed, compressionSinkInches, lidBounceInches, allPassed: validation.allPassed, failures: validation.failures },
  });

  return {
    box: result.rows[0],
    gateResult: {
      gate: 4, name: 'Movement + Compression + Lid Bounce', passed: validation.allPassed,
      message: validation.allPassed ? 'All Gate 4 tests passed' : validation.failures.map(f => f.errorMessage).join(' | '),
      tests: { shake: { passed: shakePassed }, compression: validation.compression, lidBounce: validation.lidBounce },
    },
  };
}

/**
 * Gate 5: Envelope Sticker (Traffic Light System)
 */
export async function processGate5(boxId, gateData, userId) {
  const { stickerColor, stickerPosition, redCapsVerified } = gateData;

  const boxResult = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!boxResult.rows[0]) throw new Error(`Box not found: ${boxId}`);

  const box = boxResult.rows[0];
  const config = BOX_CONFIGS[box.box_type];
  const stickerValidation = validateGate5Sticker(box.box_type, stickerColor, stickerPosition);

  // For BOX_A, also check red caps
  if (config.requiresRedCaps && redCapsVerified !== true) {
    stickerValidation.isValid = false;
    stickerValidation.errors.push({ errorCode: 'RED_CAPS_NOT_VERIFIED', errorMessage: 'BOX_A requires Safety Red Caps verification' });
  }

  const result = await pool.query(
    `UPDATE boxes SET gate_5_sticker_color = $1, gate_5_sticker_position = $2, gate_5_sticker_verified = $3, gate_5_red_caps_verified = $4, updated_at = NOW()
     WHERE box_id = $5 RETURNING *`,
    [stickerColor, stickerPosition, stickerValidation.isValid, config.requiresRedCaps ? redCapsVerified : null, boxId]
  );

  await logEvent({
    eventType: 'GATE_5_COMPLETE',
    tenantId: box.tenant_id,
    actorUserId: userId,
    payload: { boxId, expectedColor: stickerValidation.expectedColor, actualColor: stickerColor, passed: stickerValidation.isValid },
  });

  return {
    box: result.rows[0],
    gateResult: {
      gate: 5, name: 'Envelope Sticker', passed: stickerValidation.isValid,
      message: stickerValidation.isValid ? `${stickerColor} sticker verified on TOP` : stickerValidation.errors.map(e => e.errorMessage).join(' | '),
      expectedColor: stickerValidation.expectedColor, redCapsRequired: config.requiresRedCaps,
    },
  };
}

/**
 * Processes Liquid Fortress Protocol (BOX_A only)
 */
export async function processLiquidFortress(boxId, data, userId) {
  const { jugCount, allBagged, allSealed, tipTestPassed } = data;

  const boxResult = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!boxResult.rows[0]) throw new Error(`Box not found: ${boxId}`);
  if (boxResult.rows[0].box_type !== 'BOX_A') throw new Error('Liquid Fortress only applies to BOX_A');

  const allPassed = allBagged && allSealed && tipTestPassed;

  const result = await pool.query(
    `UPDATE boxes SET liquid_fortress_jug_count = $1, liquid_fortress_all_bagged = $2, liquid_fortress_all_sealed = $3, liquid_fortress_tip_test_passed = $4, updated_at = NOW()
     WHERE box_id = $5 RETURNING *`,
    [jugCount, allBagged, allSealed, tipTestPassed, boxId]
  );

  await logEvent({
    eventType: 'LIQUID_FORTRESS_COMPLETE',
    tenantId: boxResult.rows[0].tenant_id,
    actorUserId: userId,
    payload: { boxId, jugCount, allBagged, allSealed, tipTestPassed, passed: allPassed },
  });

  return { box: result.rows[0], fortressResult: { passed: allPassed, jugCount, checks: { allBagged, allSealed, tipTestPassed } } };
}

/**
 * Processes Kraft Wall installation (BOX_B1 only)
 */
export async function processKraftWall(boxId, installed, userId) {
  const boxResult = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!boxResult.rows[0]) throw new Error(`Box not found: ${boxId}`);
  if (boxResult.rows[0].box_type !== 'BOX_B1') throw new Error('Kraft Wall only applies to BOX_B1');

  const result = await pool.query(
    `UPDATE boxes SET kraft_wall_divider_installed = $1, updated_at = NOW() WHERE box_id = $2 RETURNING *`,
    [installed, boxId]
  );

  await logEvent({
    eventType: 'KRAFT_WALL_COMPLETE',
    tenantId: boxResult.rows[0].tenant_id,
    actorUserId: userId,
    payload: { boxId, installed },
  });

  return { box: result.rows[0], kraftWallResult: { installed, message: installed ? 'Kraft Wall divider installed' : 'Kraft Wall required for BOX_B1' } };
}

/**
 * Finalizes box after all gates pass (Label Lock)
 */
export async function finalizeBox(boxId, userId) {
  const boxResult = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!boxResult.rows[0]) throw new Error(`Box not found: ${boxId}`);

  const box = boxResult.rows[0];
  if (!box.all_gates_passed) {
    const failedGates = [];
    if (!box.gate_1_passed) failedGates.push('Gate 1');
    if (BOX_CONFIGS[box.box_type].requiresOxygenAbsorbers && !box.gate_2_passed) failedGates.push('Gate 2');
    if (!box.gate_3_passed) failedGates.push('Gate 3');
    if (!box.gate_4_shake_passed || !box.gate_4_compression_passed || !box.gate_4_lid_bounce_passed) failedGates.push('Gate 4');
    if (!box.gate_5_sticker_verified) failedGates.push('Gate 5');
    throw new Error(`Cannot finalize. Failed: ${failedGates.join(', ')}`);
  }

  const result = await pool.query(
    `UPDATE boxes SET scanned_at_packing = NOW(), updated_at = NOW() WHERE box_id = $1 RETURNING *`,
    [boxId]
  );

  await logEvent({
    eventType: 'BOX_FINALIZED',
    eventSubtype: 'LABEL_LOCKED',
    tenantId: box.tenant_id,
    actorUserId: userId,
    payload: { boxId, barcode: box.barcode, boxType: box.box_type, finalWeight: box.gate_3_final_weight_lbs },
  });

  return { box: result.rows[0], finalized: true, message: `Box ${boxId} finalized and label locked` };
}

/**
 * Gets box gate status summary
 */
export async function getBoxGateStatus(boxId) {
  const result = await pool.query('SELECT * FROM boxes WHERE box_id = $1', [boxId]);
  if (!result.rows[0]) throw new Error(`Box not found: ${boxId}`);

  const box = result.rows[0];
  const config = BOX_CONFIGS[box.box_type];

  return {
    box,
    config,
    gateSummary: {
      gate1: { name: 'Zero Check', passed: box.gate_1_passed },
      gate2: { name: 'Freshness Lock', passed: box.gate_2_passed, required: config.requiresOxygenAbsorbers },
      gate3: { name: 'Weight Law', passed: box.gate_3_passed, splitRequired: box.gate_3_split_required },
      gate4: { name: 'Movement Tests', passed: box.gate_4_shake_passed && box.gate_4_compression_passed && box.gate_4_lid_bounce_passed },
      gate5: { name: 'Envelope Sticker', passed: box.gate_5_sticker_verified },
      allPassed: box.all_gates_passed,
    },
  };
}
