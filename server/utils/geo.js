/**
 * SIPJOLT v1.00.0 - Geo Utilities (ES Module)
 * 
 * GPS validation using Haversine formula for the 50-meter geofence rule.
 * Used for POD validation and Ghost Delivery location checks.
 */

export const EARTH_RADIUS_METERS = 6371000;

/**
 * Converts degrees to radians
 */
export function toRadians(degrees) {
  return degrees * (Math.PI / 180);
}

/**
 * Calculates distance between two GPS coordinates using Haversine formula
 * Returns distance in meters
 */
export function haversineDistance(point1, point2) {
  const lat1Rad = toRadians(point1.lat);
  const lat2Rad = toRadians(point2.lat);
  const deltaLatRad = toRadians(point2.lat - point1.lat);
  const deltaLngRad = toRadians(point2.lng - point1.lng);

  const a = Math.sin(deltaLatRad / 2) * Math.sin(deltaLatRad / 2) +
            Math.cos(lat1Rad) * Math.cos(lat2Rad) *
            Math.sin(deltaLngRad / 2) * Math.sin(deltaLngRad / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return EARTH_RADIUS_METERS * c;
}

/**
 * Validates GPS coordinates are within geofence radius
 * Default radius: 50 meters (v1.00/v1.00/v1.00 standard)
 */
export function validateGeofence(actualCoords, targetCoords, radiusMeters = 50) {
  if (!actualCoords?.lat || !actualCoords?.lng) {
    return {
      isValid: false,
      distanceMeters: null,
      radiusMeters,
      error: 'GPS_MISSING',
      message: 'GPS coordinates not provided',
    };
  }

  if (!targetCoords?.lat || !targetCoords?.lng) {
    return {
      isValid: false,
      distanceMeters: null,
      radiusMeters,
      error: 'TARGET_MISSING',
      message: 'Site GPS coordinates not configured',
    };
  }

  const distance = haversineDistance(actualCoords, targetCoords);
  const isValid = distance <= radiusMeters;

  return {
    isValid,
    distanceMeters: Math.round(distance * 10) / 10,
    radiusMeters,
    actualCoords,
    targetCoords,
    message: isValid 
      ? `GPS validated (${Math.round(distance)}m from site)` 
      : `GPS outside geofence (${Math.round(distance)}m, limit: ${radiusMeters}m)`,
  };
}

/**
 * Calculates bounding box for quick DB queries before precise Haversine
 */
export function getBoundingBox(lat, lng, radiusMeters) {
  const latDegreesPerMeter = 1 / 111320;
  const lngDegreesPerMeter = 1 / (111320 * Math.cos(toRadians(lat)));

  return {
    minLat: lat - (radiusMeters * latDegreesPerMeter),
    maxLat: lat + (radiusMeters * latDegreesPerMeter),
    minLng: lng - (radiusMeters * lngDegreesPerMeter),
    maxLng: lng + (radiusMeters * lngDegreesPerMeter),
  };
}
