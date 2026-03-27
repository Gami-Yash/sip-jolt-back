/**
 * SIPJOLT v1.00.0 - Weight & Gate Validator (ES Module)
 * 
 * Enforces immutable Weight Law and Gate 4 physical tests.
 * Hub is the SOLE source of weight truth - drivers never enter weights.
 */

// ============================================
// WEIGHT LIMITS (IMMUTABLE)
// ============================================
export const WEIGHT_LIMITS = {
  SCALE_LOCK: 46.5,    // System prevents label printing
  HARD_LIMIT: 47.0,    // Absolute maximum
  LIQUID_LIMIT: 38.0,  // Recommended max for BOX_A
};

// Gate 4 physical test limits
export const GATE_4_LIMITS = {
  COMPRESSION_MAX: 0.25,  // inches - 10 lb audit block
  LID_BOUNCE_MAX: 0.5,    // inches - v1.00 NEW
};

// Expected weight ranges per box type (v1.00 spec)
export const BOX_WEIGHT_RANGES = {
  BOX_A:    { min: 0,    max: 46.5, liquidMax: 38.0 },
  BOX_B1:   { min: 32.0, max: 44.0 },
  BOX_B2:   { min: 30.0, max: 36.0 },
  BOX_C:    { min: 34.0, max: 46.0 },
  CARTON_E: { min: 0,    max: 46.5 },
};

// Backward compatibility: BOX_CD → BOX_C alias
BOX_WEIGHT_RANGES.BOX_CD = BOX_WEIGHT_RANGES.BOX_C;

/**
 * Validates box weight against Weight Law
 */
export function validateBoxWeight(boxType, weight) {
  const result = {
    isValid: true,
    requiresSplit: false,
    errorCode: null,
    errorMessage: null,
    warnings: [],
  };

  if (weight === null || weight === undefined) {
    return { ...result, isValid: false, errorCode: 'WEIGHT_MISSING', errorMessage: 'Weight is required' };
  }

  // Hard limit check
  if (weight > WEIGHT_LIMITS.HARD_LIMIT) {
    return {
      isValid: false,
      requiresSplit: true,
      errorCode: 'WEIGHT_LAW_VIOLATION',
      errorMessage: `Weight ${weight} lbs exceeds hard limit of ${WEIGHT_LIMITS.HARD_LIMIT} lbs`,
      warnings: [],
    };
  }

  // Scale lock check
  if (weight > WEIGHT_LIMITS.SCALE_LOCK) {
    return {
      isValid: false,
      requiresSplit: true,
      errorCode: 'SCALE_LOCK_TRIGGERED',
      errorMessage: `Weight ${weight} lbs exceeds scale lock of ${WEIGHT_LIMITS.SCALE_LOCK} lbs. Split required.`,
      warnings: [],
    };
  }

  // Box-specific warnings
  const range = BOX_WEIGHT_RANGES[boxType];
  if (range) {
    if (boxType === 'BOX_A' && weight > WEIGHT_LIMITS.LIQUID_LIMIT) {
      result.warnings.push(`BOX_A weight ${weight} lbs exceeds recommended liquid limit of ${WEIGHT_LIMITS.LIQUID_LIMIT} lbs`);
    }
    if (weight < range.min && range.min > 0) {
      result.warnings.push(`Weight ${weight} lbs below expected minimum ${range.min} lbs for ${boxType}`);
    }
  }

  return result;
}

/**
 * Validates Gate 4 Lid Bounce test (v1.00 NEW)
 */
export function validateLidBounce(bounceInches) {
  if (bounceInches === null || bounceInches === undefined) {
    return { isValid: false, errorCode: 'LID_BOUNCE_MISSING', errorMessage: 'Lid bounce measurement required' };
  }

  if (bounceInches > GATE_4_LIMITS.LID_BOUNCE_MAX) {
    return {
      isValid: false,
      errorCode: 'LID_BOUNCE_EXCEEDED',
      errorMessage: `Lid bounce ${bounceInches}" exceeds limit of ${GATE_4_LIMITS.LID_BOUNCE_MAX}". Add Kraft paper stuffing.`,
      bounceInches,
      limitInches: GATE_4_LIMITS.LID_BOUNCE_MAX,
    };
  }

  return { isValid: true, bounceInches, limitInches: GATE_4_LIMITS.LID_BOUNCE_MAX };
}

/**
 * Validates Gate 4 Compression test
 */
export function validateCompression(sinkInches) {
  if (sinkInches === null || sinkInches === undefined) {
    return { isValid: false, errorCode: 'COMPRESSION_MISSING', errorMessage: 'Compression measurement required' };
  }

  if (sinkInches > GATE_4_LIMITS.COMPRESSION_MAX) {
    return {
      isValid: false,
      errorCode: 'COMPRESSION_EXCEEDED',
      errorMessage: `Compression sink ${sinkInches}" exceeds limit of ${GATE_4_LIMITS.COMPRESSION_MAX}". Add packing material.`,
      sinkInches,
      limitInches: GATE_4_LIMITS.COMPRESSION_MAX,
    };
  }

  return { isValid: true, sinkInches, limitInches: GATE_4_LIMITS.COMPRESSION_MAX };
}

/**
 * Validates all Gate 4 tests together
 */
export function validateGate4Complete(data) {
  const { shakePassed, compressionSinkInches, lidBounceInches } = data;
  const results = { allPassed: true, failures: [] };

  if (shakePassed !== true) {
    results.allPassed = false;
    results.failures.push({ test: 'SHAKE', errorMessage: 'Shake test failed - contents moving' });
  }

  const compression = validateCompression(compressionSinkInches);
  if (!compression.isValid) {
    results.allPassed = false;
    results.failures.push({ test: 'COMPRESSION', ...compression });
  }
  results.compression = compression;

  const lidBounce = validateLidBounce(lidBounceInches);
  if (!lidBounce.isValid) {
    results.allPassed = false;
    results.failures.push({ test: 'LID_BOUNCE', ...lidBounce });
  }
  results.lidBounce = lidBounce;

  return results;
}

/**
 * Gets expected sticker color for box type
 */
export function getExpectedStickerColor(boxType) {
  // v1.00 Zone Color Mapping (with BOX_CD backward compatibility)
  const colorMap = {
    BOX_A: 'RED', BOX_B1: 'GREEN', BOX_B2: 'GREEN',
    BOX_C: 'YELLOW', BOX_CD: 'YELLOW', CARTON_E: 'BLUE',
  };
  return colorMap[boxType] || 'WHITE';
}

/**
 * Validates Gate 5 sticker
 */
export function validateGate5Sticker(boxType, stickerColor, stickerPosition) {
  const expectedColor = getExpectedStickerColor(boxType);
  const result = { isValid: true, expectedColor, actualColor: stickerColor, errors: [] };

  if (stickerColor !== expectedColor) {
    result.isValid = false;
    result.errors.push({ errorCode: 'WRONG_STICKER_COLOR', errorMessage: `Expected ${expectedColor}, got ${stickerColor}` });
  }

  if (stickerPosition !== 'TOP') {
    result.isValid = false;
    result.errors.push({ errorCode: 'WRONG_STICKER_POSITION', errorMessage: `Sticker must be on TOP, not ${stickerPosition}` });
  }

  return result;
}
