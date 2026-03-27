// v1.01 - Updated role system with Barista Specialist rebrand
const USER_ROLES = {
  BARISTA_SPECIALIST: 'barista_specialist',
  DELIVERY_SPECIALIST: 'delivery_specialist',
  OPS_MANAGER: 'ops_manager',
  ADMIN: 'admin',
  LANDLORD_VIEWER: 'landlord_viewer'
};

const ROLE_DISPLAY_NAMES = {
  [USER_ROLES.BARISTA_SPECIALIST]: 'SIPJOLT Barista Specialist',
  [USER_ROLES.DELIVERY_SPECIALIST]: 'Delivery Specialist',
  [USER_ROLES.OPS_MANAGER]: 'Operations Manager',
  [USER_ROLES.ADMIN]: 'Administrator',
  [USER_ROLES.LANDLORD_VIEWER]: 'Landlord Viewer'
};

const ROLE_DESCRIPTIONS = {
  [USER_ROLES.BARISTA_SPECIALIST]: 'Maintains and refills SIPJOLT machines, ensures quality and freshness',
  [USER_ROLES.DELIVERY_SPECIALIST]: 'Delivers ingredients and supplies to site locations',
  [USER_ROLES.OPS_MANAGER]: 'Oversees operations, manages alerts and escalations',
  [USER_ROLES.ADMIN]: 'Full system access and configuration',
  [USER_ROLES.LANDLORD_VIEWER]: 'Read-only access to site performance dashboards'
};

const LEGACY_ROLE_MAP = {
  'partner_technician': USER_ROLES.BARISTA_SPECIALIST,
  'driver': USER_ROLES.DELIVERY_SPECIALIST,
  'PARTNER_TECHNICIAN': USER_ROLES.BARISTA_SPECIALIST,
  'DRIVER': USER_ROLES.DELIVERY_SPECIALIST
};

function normalizeRole(role) {
  if (!role) return USER_ROLES.BARISTA_SPECIALIST;
  const normalized = role.toLowerCase();
  return LEGACY_ROLE_MAP[role] || LEGACY_ROLE_MAP[normalized] || normalized;
}

function getDisplayName(role) {
  const normalizedRole = normalizeRole(role);
  return ROLE_DISPLAY_NAMES[normalizedRole] || role;
}

module.exports = {
  USER_ROLES,
  ROLE_DISPLAY_NAMES,
  ROLE_DESCRIPTIONS,
  LEGACY_ROLE_MAP,
  normalizeRole,
  getDisplayName
};
