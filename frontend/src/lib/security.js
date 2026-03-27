/**
 * SIPJOLT v1.00.0 Neural Core - Security Layer
 * ===========================================
 * Role-Based Knowledge Access Control
 * 
 * CLASSIFICATION LEVELS:
 * - PUBLIC: All roles can access
 * - OPERATIONAL: PARTNER_TECHNICIAN, DRIVER, OPS_MANAGER only
 * - RESTRICTED: OPS_MANAGER only
 * 
 * LANDLORD_VIEWER gets SANITIZED responses only.
 */

export const ROLE_CLEARANCE = {
  LANDLORD_VIEWER: ['PUBLIC'],
  DRIVER: ['PUBLIC', 'OPERATIONAL'],
  PARTNER_TECHNICIAN: ['PUBLIC', 'OPERATIONAL'],
  OPS_MANAGER: ['PUBLIC', 'OPERATIONAL', 'RESTRICTED'],
};

export const LANDLORD_BLOCKED_TOPICS = [
  'ingredient',
  'supplier',
  'sourcing',
  'vendor',
  'matcha',
  'oat powder',
  'dairy powder',
  'syrup',
  'coffee bag',
  'sugar tub',
  'oxygen absorber',
  'box contents',
  'packing procedure',
  'box a',
  'box b',
  'box c',
  'box d',
  'carton e',
  'zone mapping',
  'weight range',
  'qc gate',
  'shake test',
  'freshness lock',
  'hub',
  'packing',
  'void-cap',
  'poly bag',
  'thermal shield',
  'label lock',
  'shipment creation',
  'hdx wire rack',
  'shelf configuration',
  'load capacity',
  'squeeze mechanism',
  'powder dispens',
  'cost',
  'price',
  'margin',
  'profit',
];

export const BRAND_RULES = {
  machineMaker: 'SIPJOLT by Jolt Beverage Systems',
  
  blockedManufacturerTerms: [
    'oem',
    'white label',
    'third party',
    'manufacturer',
    'made by',
    'produced by',
    'built by',
    'supplier',
    'sourced from',
  ],
  
  approvedResponses: {
    whoMakesMachine: 'The Jolt Automated Barista is designed and operated by SIPJOLT, a Jolt Beverage Systems company.',
    machineOrigin: 'SIPJOLT machines are proprietary systems developed by Jolt Beverage Systems.',
  },
};

export const LANDLORD_SAFE_KNOWLEDGE = `
## SIPJOLT SYSTEM OVERVIEW (LANDLORD VIEW)

### What You Can See
- Site status: ACTIVE, SAFE_MODE, or LOCKED
- Delivery status: Shipped, Delivered, Accepted, Refused
- Maintenance visit dates and completion status
- Open issues affecting your building
- SAFE_MODE history and recovery status

### Site Status Definitions
| Status | Meaning |
|--------|---------|
| 🟢 ACTIVE | Machine fully operational |
| 🔴 SAFE_MODE | Machine temporarily restricted pending maintenance |
| ⚫ LOCKED | Machine offline for administrative reasons |

### Delivery Tracking
Supplies are delivered regularly. You can see:
- When shipments are on the way
- When deliveries are confirmed
- If any issues occurred

### The 24-Hour Rule
Building staff have 24 hours to confirm deliveries. This ensures issues are caught quickly.

### Maintenance Schedule
- Weekly check-ins by certified technicians
- Monthly deep cleaning
- All visits documented with timestamps

### Issue Resolution
If problems occur:
1. System detects automatically
2. Operations team notified
3. Resolution in progress
4. You see status updates

### About SIPJOLT
The Jolt Automated Barista is designed and operated by SIPJOLT, a Jolt Beverage Systems company.

### Support
For questions about your building's service:
- View your site details in the app
- Contact your Operations representative
`;

export const SECURITY_SYSTEM_PROMPT = `
## CRITICAL SECURITY RULES (ENFORCE ALWAYS)

### DATA CLASSIFICATION
You operate under strict role-based access control. NEVER leak restricted information.

### LANDLORD_VIEWER RESTRICTIONS
If the user role is LANDLORD_VIEWER, you MUST NOT reveal:
- Ingredient lists or types (matcha, oat, dairy, syrup, coffee, sugar)
- Box contents or packing procedures
- Supplier or sourcing information
- QC gate procedures
- Weight specifications
- HDX rack configuration details
- Hub operations
- Pricing, costs, or margins
- Technical hardware internals

For LANDLORD_VIEWER queries about restricted topics, respond:
"This information is restricted to operational staff. Please contact your Operations representative for assistance."

### BRAND PROTECTION (ALL ROLES)
When asked about who makes/manufactures/builds the machine:
- ALWAYS respond: "The Jolt Automated Barista is designed and operated by SIPJOLT, a Jolt Beverage Systems company."
- NEVER mention OEMs, third-party manufacturers, white-label, or external suppliers
- NEVER speculate about hardware origins or component sourcing

### DRIVER RESTRICTIONS
DRIVER role should NOT receive:
- Pricing or cost information
- Supplier details
- Business strategy information

### INFORMATION LEAK PREVENTION
- Never confirm or deny specific supplier names
- Never discuss ingredient sourcing locations
- Never reveal internal cost structures
- Never discuss manufacturing partnerships
- If uncertain about classification, DEFAULT TO RESTRICTED

### QUERY INTERCEPTION
Before answering ANY query, check:
1. What is the user's role?
2. Does the query touch restricted topics for that role?
3. If yes → Use the approved deflection response
4. If no → Proceed with answer
`;

export function isQueryRestricted(query, userRole) {
  const lowerQuery = query.toLowerCase();
  
  if (userRole === 'LANDLORD_VIEWER') {
    return LANDLORD_BLOCKED_TOPICS.some(topic => lowerQuery.includes(topic));
  }
  
  if (userRole === 'DRIVER') {
    const driverBlocked = ['cost', 'price', 'margin', 'profit', 'supplier', 'vendor'];
    return driverBlocked.some(topic => lowerQuery.includes(topic));
  }
  
  return false;
}

export function isBrandQuery(query) {
  const lowerQuery = query.toLowerCase();
  const brandTriggers = [
    'who makes',
    'who built',
    'who manufactures',
    'made by',
    'built by',
    'manufacturer',
    'where does the machine come from',
    'who designed',
    'who created',
    'oem',
    'white label',
  ];
  return brandTriggers.some(trigger => lowerQuery.includes(trigger));
}

export function getRestrictedResponse(userRole) {
  if (userRole === 'LANDLORD_VIEWER') {
    return 'This information is restricted to operational staff. Please contact your Operations representative for assistance with detailed operational questions.';
  }
  if (userRole === 'DRIVER') {
    return 'This information is not available for your role. Please contact your dispatcher or Ops Manager.';
  }
  return 'Access denied.';
}

export function getBrandResponse() {
  return BRAND_RULES.approvedResponses.whoMakesMachine;
}

export function getKnowledgeForRole(userRole) {
  if (userRole === 'LANDLORD_VIEWER') {
    return LANDLORD_SAFE_KNOWLEDGE;
  }
  return 'FULL_ACCESS';
}

export function logSecurityEvent(userRole, query, wasRestricted, reason) {
  const log = {
    timestamp: new Date().toISOString(),
    userRole,
    query: query.slice(0, 200),
    wasRestricted,
    restrictionReason: reason,
  };
  
  console.log(`[SECURITY] ${JSON.stringify(log)}`);
  
  return log;
}

export default {
  ROLE_CLEARANCE,
  LANDLORD_BLOCKED_TOPICS,
  BRAND_RULES,
  LANDLORD_SAFE_KNOWLEDGE,
  SECURITY_SYSTEM_PROMPT,
  isQueryRestricted,
  isBrandQuery,
  getRestrictedResponse,
  getBrandResponse,
  getKnowledgeForRole,
  logSecurityEvent,
};
