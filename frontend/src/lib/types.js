/**
 * SIPJOLT v1.00.0 Neural Core - Type Definitions (JSDoc)
 * =====================================================
 */

/**
 * @typedef {'PARTNER_TECHNICIAN' | 'DRIVER' | 'OPS_MANAGER' | 'LANDLORD_VIEWER'} UserRole
 */

/**
 * @typedef {'ACTIVE' | 'SAFE_MODE' | 'LOCKED'} SiteStatus
 */

/**
 * @typedef {'GREEN' | 'YELLOW' | 'RED'} ReliabilityBadge
 */

/**
 * @typedef {'BOX_A' | 'BOX_B1' | 'BOX_B2' | 'BOX_C' | 'CARTON_E'} BoxId
 * v1.00 Corrected Box Types:
 * - BOX_A: Syrups (RED/Shelf 1 - Bottom)
 * - BOX_B1: 9 Oat Powder (Z-B) + 1 Cleaning Kit (Z-C/Shelf 3)
 * - BOX_B2: 7 Dairy Powder + 6 Cocoa Powder (GREEN/Shelf 2)
 * - BOX_C: 10 Coffee + 3 Sugar + 4 Chai (GRAY/Shelf 4 - Top)
 * - CARTON_E: 4 Cup Boxes + 1 Bag of Lids (BLUE/Floor)
 */

/**
 * @typedef {'RED' | 'GREEN' | 'YELLOW' | 'GRAY' | 'BLUE'} ZoneColor
 */

/**
 * @typedef {'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'} IncidentSeverity
 */

/**
 * @typedef {'SHIPPED' | 'DELIVERED' | 'ACCEPTED' | 'REFUSED'} DeliveryStatus
 */

/**
 * @typedef {'WET_LEAK' | 'MISSING_BOX' | 'WRONG_ITEMS' | 'DAMAGED_PACKAGING'} RefusalReason
 */

/**
 * @typedef {Object} ChatMessage
 * @property {string} id
 * @property {'user' | 'assistant'} role
 * @property {string} content
 * @property {Date} timestamp
 * @property {'sending' | 'sent' | 'error'} [status]
 */

/**
 * @typedef {Object} ChatContext
 * @property {string} [currentRoute]
 * @property {UserRole} [userRole]
 * @property {string} [siteId]
 * @property {SiteStatus} [siteStatus]
 * @property {string[]} [pendingTasks]
 */

/**
 * @typedef {Object} ChatApiRequest
 * @property {string} message
 * @property {Array<{role: 'user' | 'assistant', content: string}>} [conversationHistory]
 * @property {ChatContext} [context]
 */

/**
 * @typedef {Object} ChatApiResponse
 * @property {boolean} success
 * @property {string} [response]
 * @property {string} [error]
 * @property {string} timestamp
 * @property {string} model
 */

export const USER_ROLES = {
  PARTNER_TECHNICIAN: 'PARTNER_TECHNICIAN',
  DRIVER: 'DRIVER',
  OPS_MANAGER: 'OPS_MANAGER',
  LANDLORD_VIEWER: 'LANDLORD_VIEWER',
};

export const SITE_STATUSES = {
  ACTIVE: 'ACTIVE',
  SAFE_MODE: 'SAFE_MODE',
  LOCKED: 'LOCKED',
};

export const BOX_IDS = {
  BOX_A: 'BOX_A',
  BOX_B1: 'BOX_B1',
  BOX_B2: 'BOX_B2',
  BOX_C: 'BOX_C',
  CARTON_E: 'CARTON_E',
  // Backward compatibility alias
  BOX_CD: 'BOX_C',
};

// v1.00 CORRECTED Zone Configuration
export const ZONE_CONFIG = {
  BOX_A: { color: 'RED', shelf: 'SHELF 1 (BOTTOM)', contents: 'Syrup Jugs (individually bagged in 6mm poly)' },
  BOX_B1: { color: 'GREEN', shelf: 'SHELF 2+3', contents: '9 Oat Powder (Zone B) + 1 Cleaning Kit (Zone C)' },
  BOX_B2: { color: 'GREEN', shelf: 'SHELF 2', contents: '7 Dairy Powder + 6 Cocoa Powder' },
  BOX_C: { color: 'GRAY', shelf: 'SHELF 4 (TOP)', contents: '10 Coffee + 3 Sugar + 4 Chai' },
  CARTON_E: { color: 'BLUE', shelf: 'FLOOR', contents: '4 Cup Boxes (2,000 cups) + 1 Bag of Lids' },
};

export const ZONE_COLORS = {
  RED: 'RED',
  GREEN: 'GREEN',
  YELLOW: 'YELLOW',
  GRAY: 'GRAY',
  BLUE: 'BLUE',
};
