/**
 * SIPJOLT v1.01 Gate5 OS - Boxes API Routes (ES Module)
 * 
 * REST endpoints for the 5-gate QC packing workflow.
 */

import express from 'express';
import {
  createBox, finalizeBox, getBoxGateStatus,
  processGate1, processGate2, processGate3, processGate4, processGate5,
  processLiquidFortress, processKraftWall, BOX_CONFIGS,
} from '../services/fiveGatesService.js';
import { requireHeaderAuth } from '../middleware/headerAuth.js';

const router = express.Router();

const requireOpsRole = requireHeaderAuth(['ops_manager', 'ops_admin']);
const requireAnyUser = requireHeaderAuth();

// GET /api/v1.00/boxes/types - Get available box types
router.get('/types', requireAnyUser, (req, res) => {
  res.json({
    types: BOX_CONFIGS,
    trafficLight: { RED: 'BOX_A (Liquids)', GREEN: 'BOX_B1/B2 (Dry)', YELLOW: 'BOX_C (Coffee+Sugar+Chai)', BLUE: 'CARTON_E (Cups)' },
  });
});

// POST /api/v1.00/boxes - Create new box
router.post('/', requireOpsRole, async (req, res) => {
  try {
    const { tenantId, shipmentId, boxType, boxSequence, boxTotal, bomContents } = req.body;

    if (!tenantId || !shipmentId || !boxType) {
      return res.status(400).json({ error: 'MISSING_REQUIRED_FIELDS', message: 'tenantId, shipmentId, boxType required' });
    }
    if (!BOX_CONFIGS[boxType]) {
      return res.status(400).json({ error: 'INVALID_BOX_TYPE', message: `Valid types: ${Object.keys(BOX_CONFIGS).join(', ')}` });
    }

    const box = await createBox({ tenantId, shipmentId, boxType, boxSequence, boxTotal, bomContents, packedByUserId: req.user.id });
    res.status(201).json({ success: true, box, config: BOX_CONFIGS[boxType] });
  } catch (error) {
    console.error('Error creating box:', error);
    res.status(500).json({ error: 'CREATE_BOX_FAILED', message: error.message });
  }
});

// GET /api/v1.00/boxes/:id - Get box details
router.get('/:id', requireAnyUser, async (req, res) => {
  try {
    const result = await getBoxGateStatus(req.params.id);
    res.json(result);
  } catch (error) {
    if (error.message.includes('not found')) return res.status(404).json({ error: 'BOX_NOT_FOUND', message: error.message });
    res.status(500).json({ error: 'GET_BOX_FAILED', message: error.message });
  }
});

// GET /api/v1.00/boxes/:id/gates - Get gate summary
router.get('/:id/gates', requireAnyUser, async (req, res) => {
  try {
    const result = await getBoxGateStatus(req.params.id);
    res.json({ boxId: req.params.id, boxType: result.box.box_type, gates: result.gateSummary });
  } catch (error) {
    res.status(500).json({ error: 'GET_GATES_FAILED', message: error.message });
  }
});

// PATCH /api/v1.00/boxes/:id/gate/1 - Gate 1: Zero Check
router.patch('/:id/gate/1', requireOpsRole, async (req, res) => {
  try {
    const { calibrationWeightLbs } = req.body;
    if (calibrationWeightLbs == null) return res.status(400).json({ error: 'MISSING_CALIBRATION_WEIGHT' });
    const result = await processGate1(req.params.id, { calibrationWeightLbs }, req.user.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'GATE_1_FAILED', message: error.message });
  }
});

// PATCH /api/v1.00/boxes/:id/gate/2 - Gate 2: Freshness Lock
router.patch('/:id/gate/2', requireOpsRole, async (req, res) => {
  try {
    const { absorberCount, confirmed } = req.body;
    const result = await processGate2(req.params.id, { absorberCount, confirmed }, req.user.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'GATE_2_FAILED', message: error.message });
  }
});

// PATCH /api/v1.00/boxes/:id/gate/3 - Gate 3: Weight Law
router.patch('/:id/gate/3', requireOpsRole, async (req, res) => {
  try {
    const { tareWeightLbs, finalWeightLbs } = req.body;
    if (finalWeightLbs == null) return res.status(400).json({ error: 'MISSING_WEIGHT' });
    const result = await processGate3(req.params.id, { tareWeightLbs, finalWeightLbs }, req.user.id);
    if (result.gateResult.splitRequired) {
      return res.status(422).json({ ...result, action: 'SPLIT_REQUIRED', message: 'Weight exceeds 46.5 lbs. Split shipment required.' });
    }
    res.json(result);
  } catch (error) {
    if (error.message.includes('WEIGHT_LAW_VIOLATION')) return res.status(422).json({ error: 'WEIGHT_LAW_VIOLATION', message: error.message });
    res.status(500).json({ error: 'GATE_3_FAILED', message: error.message });
  }
});

// PATCH /api/v1.00/boxes/:id/gate/4 - Gate 4: Movement + Compression + Lid Bounce
router.patch('/:id/gate/4', requireOpsRole, async (req, res) => {
  try {
    const { shakePassed, compressionSinkInches, lidBounceInches } = req.body;
    const missing = [];
    if (shakePassed === undefined) missing.push('shakePassed');
    if (compressionSinkInches === undefined) missing.push('compressionSinkInches');
    if (lidBounceInches === undefined) missing.push('lidBounceInches');
    if (missing.length) return res.status(400).json({ error: 'MISSING_GATE_4_DATA', message: `Missing: ${missing.join(', ')}` });
    const result = await processGate4(req.params.id, { shakePassed, compressionSinkInches, lidBounceInches }, req.user.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'GATE_4_FAILED', message: error.message });
  }
});

// PATCH /api/v1.00/boxes/:id/gate/5 - Gate 5: Envelope Sticker
router.patch('/:id/gate/5', requireOpsRole, async (req, res) => {
  try {
    const { stickerColor, stickerPosition, redCapsVerified } = req.body;
    if (!stickerColor || !stickerPosition) return res.status(400).json({ error: 'MISSING_STICKER_DATA' });
    const result = await processGate5(req.params.id, { stickerColor, stickerPosition, redCapsVerified }, req.user.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'GATE_5_FAILED', message: error.message });
  }
});

// POST /api/v1.00/boxes/:id/finalize - Finalize box (Label Lock)
router.post('/:id/finalize', requireOpsRole, async (req, res) => {
  try {
    const result = await finalizeBox(req.params.id, req.user.id);
    res.json(result);
  } catch (error) {
    if (error.message.includes('Cannot finalize')) return res.status(422).json({ error: 'GATES_NOT_PASSED', message: error.message });
    res.status(500).json({ error: 'FINALIZE_FAILED', message: error.message });
  }
});

// POST /api/v1.00/boxes/:id/liquid-fortress - BOX_A only
router.post('/:id/liquid-fortress', requireOpsRole, async (req, res) => {
  try {
    const { jugCount, allBagged, allSealed, tipTestPassed } = req.body;
    const result = await processLiquidFortress(req.params.id, { jugCount, allBagged, allSealed, tipTestPassed }, req.user.id);
    res.json(result);
  } catch (error) {
    if (error.message.includes('only applies to BOX_A')) return res.status(422).json({ error: 'WRONG_BOX_TYPE', message: error.message });
    res.status(500).json({ error: 'LIQUID_FORTRESS_FAILED', message: error.message });
  }
});

// POST /api/v1.00/boxes/:id/kraft-wall - BOX_B1 only
router.post('/:id/kraft-wall', requireOpsRole, async (req, res) => {
  try {
    const { installed } = req.body;
    const result = await processKraftWall(req.params.id, installed, req.user.id);
    res.json(result);
  } catch (error) {
    if (error.message.includes('only applies to BOX_B1')) return res.status(422).json({ error: 'WRONG_BOX_TYPE', message: error.message });
    res.status(500).json({ error: 'KRAFT_WALL_FAILED', message: error.message });
  }
});

export default router;
