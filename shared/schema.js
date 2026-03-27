import { pgTable, serial, text, timestamp, integer, jsonb, boolean, date, decimal, real } from 'drizzle-orm/pg-core';

// Machines Table
export const machines = pgTable('machines', {
  id: serial('id').primaryKey(),
  machineId: text('machine_id').unique().notNull(),
  nickname: text('nickname').notNull(),
  location: text('location').notNull(),
  status: text('status').notNull().default('active'), // active, service_due, repair, offline
  lastVisitDate: timestamp('last_visit_date'),
  lastVisitTechId: text('last_visit_tech_id'),
  nextWeeklyDue: timestamp('next_weekly_due'),
  cupsServedToday: integer('cups_served_today').default(0),
  activeErrors: jsonb('active_errors').default([]),
  notes: text('notes').default(''),
  inventory: jsonb('inventory').default({
    beans: 100,
    oat: 100,
    vanilla: 100,
    mocha: 100,
    cups: 500
  }),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Technicians Table
export const technicians = pgTable('technicians', {
  id: serial('id').primaryKey(),
  technicianId: text('technician_id').unique().notNull(),
  name: text('name').notNull(),
  xp: integer('xp').default(0),
  streak: integer('streak').default(0),
  onTimeRate: integer('on_time_rate').default(100),
  badges: jsonb('badges').default([]),
  totalVisits: integer('total_visits').default(0),
  weeklyVisits: integer('weekly_visits').default(0),
  monthlyVisits: integer('monthly_visits').default(0),
  loginCount: integer('login_count').default(0),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Visits Table
export const visits = pgTable('visits', {
  id: serial('id').primaryKey(),
  technicianId: text('technician_id').notNull(),
  machineId: text('machine_id').notNull(),
  visitType: text('visit_type').notNull(), // weekly, monthly
  completedQuestions: jsonb('completed_questions').default({}),
  photos: jsonb('photos').default({}),
  problems: jsonb('problems').default({}),
  optionSelections: jsonb('option_selections').default({}),
  textInputs: jsonb('text_inputs').default({}),
  durationMinutes: integer('duration_minutes'),
  syncedToMachineApp: boolean('synced_to_machine_app').default(false),
  syncedAt: timestamp('synced_at'),
  syncedBy: text('synced_by'),
  completedAt: timestamp('completed_at').defaultNow(),
  createdAt: timestamp('created_at').defaultNow()
});

// Prizes Table
export const prizes = pgTable('prizes', {
  id: serial('id').primaryKey(),
  technicianId: text('technician_id').notNull(),
  prizeType: text('prize_type').notNull(),
  prizeName: text('prize_name').notNull(),
  prizeValue: integer('prize_value'),
  visitType: text('visit_type').notNull(),
  notifyOps: boolean('notify_ops').default(false),
  claimed: boolean('claimed').default(false),
  claimedAt: timestamp('claimed_at'),
  wonAt: timestamp('won_at').defaultNow(),
  createdAt: timestamp('created_at').defaultNow()
});

// AI Chat Logs Table
export const aiChatLogs = pgTable('ai_chat_logs', {
  id: serial('id').primaryKey(),
  technicianId: text('technician_id').notNull(),
  machineId: text('machine_id'),
  question: text('question').notNull(),
  response: text('response').notNull(),
  hasImage: boolean('has_image').default(false),
  createdAt: timestamp('created_at').defaultNow()
});

// Photo Audit Table
export const photoAudits = pgTable('photo_audits', {
  id: serial('id').primaryKey(),
  technicianId: text('technician_id').notNull(),
  machineId: text('machine_id').notNull(),
  visitId: integer('visit_id'),
  questionId: text('question_id').notNull(),
  photoData: text('photo_data').notNull(),
  approved: boolean('approved'),
  approvedBy: text('approved_by'),
  approvedAt: timestamp('approved_at'),
  createdAt: timestamp('created_at').defaultNow()
});

// Notification Preferences Table
export const notificationPreferences = pgTable('notification_preferences', {
  id: serial('id').primaryKey(),
  technicianId: text('technician_id').unique().notNull(),
  enabledNotifications: boolean('enabled_notifications').default(true),
  visitReminders: boolean('visit_reminders').default(true),
  prizeAlerts: boolean('prize_alerts').default(true),
  machineAlerts: boolean('machine_alerts').default(true),
  maintenanceReminders: boolean('maintenance_reminders').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Notifications Table
export const notifications = pgTable('notifications', {
  id: serial('id').primaryKey(),
  technicianId: text('technician_id').notNull(),
  type: text('type').notNull(), // visit_completed, prize_won, machine_issue, maintenance_due, reminder
  title: text('title').notNull(),
  body: text('body').notNull(),
  icon: text('icon'),
  data: jsonb('data').default({}),
  read: boolean('read').default(false),
  readAt: timestamp('read_at'),
  createdAt: timestamp('created_at').defaultNow()
});

// Instructional Videos Table
export const instructionalVideos = pgTable('instructional_videos', {
  id: serial('id').primaryKey(),
  stepId: text('step_id').unique().notNull(),
  wizardType: text('wizard_type').notNull(), // weekly, monthly
  title: text('title').notNull(),
  description: text('description'),
  videoUrl: text('video_url'),
  objectPath: text('object_path'),
  fileSize: integer('file_size'),
  durationSeconds: integer('duration_seconds'),
  uploadedBy: text('uploaded_by'),
  uploadedAt: timestamp('uploaded_at'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// =====================================================
// SUPPLY CLOSET OPS MODULE - Partner Accountability System
// =====================================================

// Ops Users Table (extends existing technicians with role info)
export const opsUsers = pgTable('ops_users', {
  id: serial('id').primaryKey(),
  userId: text('user_id').unique().notNull(),
  name: text('name').notNull(),
  email: text('email'),
  phone: text('phone'),
  role: text('role').notNull().default('partner'), // partner, driver, ops_manager
  assignedSites: jsonb('assigned_sites').default([]), // array of site IDs
  isActive: boolean('is_active').default(true),
  lastLoginAt: timestamp('last_login_at'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Sites Table - Core entity for supply closet locations
export const opsSites = pgTable('ops_sites', {
  id: serial('id').primaryKey(),
  siteId: text('site_id').unique().notNull(), // e.g., SITE-042
  tenantId: text('tenant_id'), // for multi-tenant isolation
  venueName: text('venue_name').notNull(),
  address: text('address').notNull(),
  geoLat: text('geo_lat'), // optional geo pin
  geoLng: text('geo_lng'),
  primaryContactName: text('primary_contact_name'),
  primaryContactPhone: text('primary_contact_phone'),
  backupContactName: text('backup_contact_name'),
  backupContactPhone: text('backup_contact_phone'),
  closetLocation: text('closet_location'), // notes about where closet is
  accessInstructions: text('access_instructions'),
  status: text('status').notNull().default('pending_setup'), // pending_setup, ready, active, inactive
  day1CompletedAt: timestamp('day1_completed_at'),
  day1CompletedBy: text('day1_completed_by'),
  goldenPhotos: jsonb('golden_photos').default([]), // baseline rack/zone photos
  cupsHoldActive: boolean('cups_hold_active').default(false), // blocks cups shipments
  cupsHoldReason: text('cups_hold_reason'),
  cupsHoldCreatedAt: timestamp('cups_hold_created_at'),
  cupsHoldClearedAt: timestamp('cups_hold_cleared_at'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Site Config Table - Per-site settings
export const opsSiteConfigs = pgTable('ops_site_configs', {
  id: serial('id').primaryKey(),
  siteId: text('site_id').notNull().unique(),
  weeklyDueDay: text('weekly_due_day').notNull().default('tuesday'), // monday-sunday
  weeklyDueHour: integer('weekly_due_hour').default(17), // 5pm default
  overdueThresholdHours: integer('overdue_threshold_hours').default(48), // hours until overdue
  skipNextCupsDrop: boolean('skip_next_cups_drop').default(false),
  skipCupsReason: text('skip_cups_reason'),
  skipCupsExpiresAt: timestamp('skip_cups_expires_at'),
  cupsDropHoldActive: boolean('cups_drop_hold_active').default(false), // auto-hold for compliance
  cupsDropHoldReason: text('cups_drop_hold_reason'),
  a50FallbackActive: boolean('a50_fallback_active').default(false), // matcha 30-day exception mode
  a50ActivatedAt: timestamp('a50_activated_at'),
  consecutiveSoftReports: integer('consecutive_soft_reports').default(0), // to clear A-50
  consecutiveBrickedReports: integer('consecutive_bricked_reports').default(0), // to trigger A-50
  zonesLabeled: jsonb('zones_labeled').default({ A: false, B1: false, B2: false, CD: false, E: false }),
  thresholds: jsonb('thresholds').default({
    A: { min: 1, max: 4 },
    B1: { min: 1, max: 2 },
    B2: { min: 1, max: 2 },
    CD: { min: 1, max: 2 },
    E: { min: 50, max: 200 }
  }),
  ingredientsBoxesDefault: jsonb('ingredients_boxes_default').default(['A', 'B1', 'B2', 'CD']),
  cupsBoxDefault: text('cups_box_default').default('E'),
  boxASplitEnabled: boolean('box_a_split_enabled').default(false),
  boxACountDefault: integer('box_a_count_default').default(1),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Box Config Table - Canonical box mapping per site
export const opsBoxConfigs = pgTable('ops_box_configs', {
  id: serial('id').primaryKey(),
  siteId: text('site_id').notNull(),
  boxId: text('box_id').notNull(), // A, B1, B2, CD, E
  descriptor: text('descriptor').notNull(), // "LIQUIDS (SYRUP)", etc.
  isEnabled: boolean('is_enabled').default(true),
  isSplit: boolean('is_split').default(false), // for Box A split (1 of 2, 2 of 2)
  splitCount: integer('split_count').default(1), // how many boxes if split
  contents: jsonb('contents').default([]), // canonical items list
  notes: text('notes'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Weekly Tasks Table - Auto-generated weekly refill/clean tasks
export const opsWeeklyTasks = pgTable('ops_weekly_tasks', {
  id: serial('id').primaryKey(),
  taskId: text('task_id').unique().notNull(),
  siteId: text('site_id').notNull(),
  dueDate: timestamp('due_date').notNull(),
  status: text('status').notNull().default('pending'), // pending, in_progress, completed, overdue
  assignedTo: text('assigned_to'), // user_id of partner
  startedAt: timestamp('started_at'),
  completedAt: timestamp('completed_at'),
  completedBy: text('completed_by'),
  alertCreatedAt: timestamp('alert_created_at'), // 48h alert
  emergencyTaskCreatedAt: timestamp('emergency_task_created_at'), // 72h emergency
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Weekly Task Submissions Table - Partner submission records
export const opsWeeklySubmissions = pgTable('ops_weekly_submissions', {
  id: serial('id').primaryKey(),
  submissionId: text('submission_id').unique().notNull(),
  taskId: text('task_id').notNull(),
  siteId: text('site_id').notNull(),
  submittedBy: text('submitted_by').notNull(),
  beforePhoto: text('before_photo').notNull(), // wide shot URL/path
  afterPhoto: text('after_photo').notNull(), // wide shot URL/path
  closeUpPhotos: jsonb('close_up_photos').default([]), // additional issue photos
  checklist: jsonb('checklist').default({
    refillCompleted: false,
    cleaningCompleted: false,
    noLeaksVisible: false
  }),
  matchaCondition: text('matcha_condition').notNull(), // soft_normal, hard_bricked
  issueFlags: jsonb('issue_flags').default({
    lowStock: false,
    lowStockZones: [],
    leakWetBox: false,
    messyCloset: false,
    accessIssue: false
  }),
  issueNotes: text('issue_notes'),
  submittedAt: timestamp('submitted_at').defaultNow(),
  reviewedBy: text('reviewed_by'),
  reviewedAt: timestamp('reviewed_at'),
  reviewNotes: text('review_notes'),
  createdAt: timestamp('created_at').defaultNow()
});

// Shipments Table - Ops-created shipments
export const opsShipments = pgTable('ops_shipments', {
  id: serial('id').primaryKey(),
  shipmentId: text('shipment_id').unique().notNull(),
  siteId: text('site_id').notNull(),
  shipmentType: text('shipment_type').notNull(), // ingredients, cups, emergency
  carrierType: text('carrier_type').notNull().default('milk_run'), // milk_run, ups
  trackingNumber: text('tracking_number'),
  status: text('status').notNull().default('created'), // created, packed, shipped, delivered, refused, cancelled
  totalBoxes: integer('total_boxes').default(0),
  plannedShipDate: date('planned_ship_date'),
  expectedDeliveryDate: timestamp('expected_delivery_date'),
  createdBy: text('created_by').notNull(),
  packedAt: timestamp('packed_at'),
  packedBy: text('packed_by'),
  shippedAt: timestamp('shipped_at'),
  shippedBy: text('shipped_by'),
  deliveredAt: timestamp('delivered_at'),
  refusedAt: timestamp('refused_at'),
  refusalReason: text('refusal_reason'),
  cancelledAt: timestamp('cancelled_at'),
  cancelledBy: text('cancelled_by'),
  hasOverweightBoxes: boolean('has_overweight_boxes').default(false), // any box > 46.5 lb
  overweightOverrideId: text('overweight_override_id'), // FK to overrides if shipped despite overweight
  boxConfigDeviationOverrideId: text('box_config_deviation_override_id'), // FK to overrides if deviated from config
  cupsHoldOverrideId: text('cups_hold_override_id'), // FK to overrides if cups hold was overridden
  notes: text('notes'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Shipment Boxes Table - Individual boxes within a shipment
export const opsShipmentBoxes = pgTable('ops_shipment_boxes', {
  id: serial('id').primaryKey(),
  boxRecordId: text('box_record_id').unique().notNull(),
  shipmentId: text('shipment_id').notNull(),
  siteId: text('site_id').notNull(),
  boxId: text('box_id').notNull(), // A, B1, B2, CD, E
  descriptor: text('descriptor').notNull(), // "LIQUIDS (SYRUP)", etc.
  boxNumber: integer('box_number').notNull(), // 1 of X (position)
  totalInSet: integer('total_in_set').notNull(), // X total
  status: text('status').notNull().default('pending'), // pending, packed, labeled, shipped
  batchId: text('batch_id'),
  packDate: timestamp('pack_date'),
  weight: decimal('weight', { precision: 6, scale: 2 }), // lbs
  isHeavy: boolean('is_heavy').default(false), // > 40 lbs
  isOverweight: boolean('is_overweight').default(false), // > 46.5 lbs (blocks ship without override)
  hasLiquids: boolean('has_liquids').default(false), // Box A
  hasInnerKits: boolean('has_inner_kits').default(false), // Box CD
  packingLogId: text('packing_log_id'), // FK to packing_logs
  labelGeneratedAt: timestamp('label_generated_at'),
  labelType: text('label_type'), // milk_run, ups_addon
  labelPayloadJson: jsonb('label_payload_json'), // exact data used to print
  qrPayload: text('qr_payload'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Packing Logs Table - 1:1 with ShipmentBox, gates label generation
export const opsPackingLogs = pgTable('ops_packing_logs', {
  id: serial('id').primaryKey(),
  packingLogId: text('packing_log_id').unique().notNull(),
  shipmentBoxId: text('shipment_box_id').unique().notNull(), // 1:1 FK to ops_shipment_boxes.box_record_id
  packDate: timestamp('pack_date').notNull(),
  batchId: text('batch_id').notNull(),
  weightLb: decimal('weight_lb', { precision: 6, scale: 2 }),
  shakeTestPass: boolean('shake_test_pass').notNull().default(false),
  zeroRattleConfirmed: boolean('zero_rattle_confirmed').notNull().default(false),
  notes: text('notes'),
  packedByUserId: text('packed_by_user_id').notNull(),
  packedByUserName: text('packed_by_user_name'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Delivery Records Table - Driver POD submissions
export const opsDeliveryRecords = pgTable('ops_delivery_records', {
  id: serial('id').primaryKey(),
  deliveryId: text('delivery_id').unique().notNull(),
  shipmentId: text('shipment_id').notNull(),
  siteId: text('site_id').notNull(),
  driverId: text('driver_id').notNull(),
  driverName: text('driver_name'),
  routeId: text('route_id'),
  carrierType: text('carrier_type').notNull(), // milk_run, ups
  trackingNumber: text('tracking_number'),
  placementPhotos: jsonb('placement_photos').default([]), // closet photos
  status: text('status').notNull().default('pending'), // pending, delivered, refused, access_denied
  accessDenied: boolean('access_denied').default(false),
  accessDeniedPhoto: text('access_denied_photo'),
  accessDeniedNotes: text('access_denied_notes'),
  siteFailFlag: boolean('site_fail_flag').default(false), // disorganized closet
  siteFailPhoto: text('site_fail_photo'),
  siteFailNotes: text('site_fail_notes'),
  deliveredAt: timestamp('delivered_at'),
  partnerAcceptedAt: timestamp('partner_accepted_at'),
  partnerAcceptedBy: text('partner_accepted_by'),
  partnerRefused: boolean('partner_refused').default(false),
  refusalReason: text('refusal_reason'), // wet_leak, missing_box, access_issue, other
  refusalPhoto: text('refusal_photo'),
  refusalNotes: text('refusal_notes'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Incidents Table - Issue tracking and escalation
export const opsIncidents = pgTable('ops_incidents', {
  id: serial('id').primaryKey(),
  incidentId: text('incident_id').unique().notNull(),
  siteId: text('site_id').notNull(),
  type: text('type').notNull(), // wet_leak_refusal, access_denied, site_fail_messy, missing_weekly, missing_box, damaged_goods, emergency_buffer, overdue_alert
  severity: text('severity').notNull().default('medium'), // low, medium, high, critical
  title: text('title').notNull(),
  description: text('description'),
  photos: jsonb('photos').default([]),
  relatedTaskId: text('related_task_id'),
  relatedShipmentId: text('related_shipment_id'),
  relatedDeliveryId: text('related_delivery_id'),
  status: text('status').notNull().default('open'), // open, in_progress, resolved, dismissed
  assignedTo: text('assigned_to'),
  assignedAt: timestamp('assigned_at'),
  resolvedAt: timestamp('resolved_at'),
  resolvedBy: text('resolved_by'),
  resolutionNotes: text('resolution_notes'),
  escalatedAt: timestamp('escalated_at'),
  escalationLevel: integer('escalation_level').default(0),
  autoCreated: boolean('auto_created').default(false),
  createdBy: text('created_by'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Audit Log Table - Critical action tracking
export const opsAuditLog = pgTable('ops_audit_log', {
  id: serial('id').primaryKey(),
  logId: text('log_id').unique().notNull(),
  userId: text('user_id').notNull(),
  userName: text('user_name'),
  action: text('action').notNull(), // site_created, day1_completed, weekly_submitted, delivery_pod, delivery_accepted, delivery_refused, manager_override, incident_created, incident_resolved, shipment_created, label_generated
  entityType: text('entity_type').notNull(), // site, task, submission, shipment, delivery, incident
  entityId: text('entity_id').notNull(),
  details: jsonb('details').default({}),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at').defaultNow()
});

// Manager Overrides Table - Special deviation tracking
export const opsManagerOverrides = pgTable('ops_manager_overrides', {
  id: serial('id').primaryKey(),
  overrideId: text('override_id').unique().notNull(),
  managerId: text('manager_id').notNull(),
  managerName: text('manager_name').notNull(),
  overrideType: text('override_type').notNull(), // box_config_deviation, skip_cups_override, compliance_hold_release, a50_manual_clear, cups_hold_override, overweight_override
  siteId: text('site_id'),
  entityType: text('entity_type'),
  entityId: text('entity_id'),
  reason: text('reason').notNull(),
  previousValue: jsonb('previous_value'),
  newValue: jsonb('new_value'),
  expiresAt: timestamp('expires_at'),
  createdAt: timestamp('created_at').defaultNow()
});

// Notifications Table - In-app notifications for ops
export const opsNotifications = pgTable('ops_notifications', {
  id: serial('id').primaryKey(),
  notificationId: text('notification_id').unique().notNull(),
  siteId: text('site_id'),
  type: text('type').notNull(), // overdue_48h, overdue_72h, delivery_refusal, site_fail, hold_created, hold_overridden, hold_cleared, manager_override, overweight_override
  severity: text('severity').notNull().default('normal'), // normal, high, critical
  title: text('title').notNull(),
  message: text('message').notNull(),
  linkedEntityType: text('linked_entity_type'), // site, task, shipment, delivery, incident
  linkedEntityId: text('linked_entity_id'),
  readAt: timestamp('read_at'),
  readBy: text('read_by'),
  createdAt: timestamp('created_at').defaultNow()
});

// =====================================================
// MULTI-TENANT SUPPORT - Landlord/Portfolio Isolation
// =====================================================

// Tenants Table - Landlords/Portfolios for multi-tenant isolation
export const tenants = pgTable('tenants', {
  id: serial('id').primaryKey(),
  tenantId: text('tenant_id').unique().notNull(),
  name: text('name').notNull(),
  contactEmail: text('contact_email'),
  contactPhone: text('contact_phone'),
  isActive: boolean('is_active').default(true),
  createdBy: integer('created_by'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// =====================================================
// PRODUCTION SECURITY HARDENING - Identity & Immutability
// =====================================================

// JOLT Users Table - Unified identity with password authentication
export const joltUsers = pgTable('jolt_users', {
  id: serial('id').primaryKey(),
  employeeCode: text('employee_code').unique().notNull(),
  passwordHash: text('password_hash'),
  email: text('email'),
  name: text('name').notNull(),
  tenantId: text('tenant_id'), // null for ops_admin (global access)
  status: text('status').notNull().default('pending_password'), // pending_password, active, locked, revoked
  failedLoginAttempts: integer('failed_login_attempts').default(0),
  lockedUntil: timestamp('locked_until'),
  passwordSetAt: timestamp('password_set_at'),
  lastLoginAt: timestamp('last_login_at'),
  invitedBy: text('invited_by'),
  invitedAt: timestamp('invited_at'),
  revokedBy: text('revoked_by'),
  revokedAt: timestamp('revoked_at'),
  revokeReason: text('revoke_reason'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow()
});

// Auth Sessions Table - Server-side session tracking for new auth system
export const authSessions = pgTable('auth_sessions', {
  id: serial('id').primaryKey(),
  sessionId: text('session_id').unique().notNull(),
  userId: integer('user_id').notNull(),
  tokenHash: text('token_hash').notNull(),
  deviceFingerprint: text('device_fingerprint'),
  userAgent: text('user_agent'),
  ipAddress: text('ip_address'),
  expiresAt: timestamp('expires_at').notNull(),
  lastActivityAt: timestamp('last_activity_at'),
  createdAt: timestamp('created_at').defaultNow()
});

// User Site Assignments Table - RBAC role per site
export const userSiteAssignments = pgTable('user_site_assignments', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull(),
  siteId: text('site_id').notNull(),
  tenantId: text('tenant_id'), // for tenant-scoped queries
  role: text('role').notNull(), // technician, partner, driver, ops_admin, building_manager, landlord_viewer
  assignedBy: integer('assigned_by'),
  assignedAt: timestamp('assigned_at').defaultNow(),
  revokedAt: timestamp('revoked_at'),
  revokedBy: integer('revoked_by')
});

// Site QR Codes Table - Signed QR tokens per site for presence proof
export const siteQrCodes = pgTable('site_qr_codes', {
  id: serial('id').primaryKey(),
  qrId: text('qr_id').unique().notNull(),
  siteId: text('site_id').notNull(),
  qrToken: text('qr_token').notNull(), // signed JWT token
  qrType: text('qr_type').notNull().default('site_presence'), // site_presence, machine
  machineId: text('machine_id'),
  isActive: boolean('is_active').default(true),
  generatedBy: integer('generated_by'),
  generatedAt: timestamp('generated_at').defaultNow(),
  revokedAt: timestamp('revoked_at')
});

// Workflow Sessions Table - Bind all actions to QR-initiated session
export const workflowSessions = pgTable('workflow_sessions', {
  id: serial('id').primaryKey(),
  sessionId: text('session_id').unique().notNull(),
  userId: integer('user_id').notNull(),
  siteId: text('site_id').notNull(),
  tenantId: text('tenant_id'), // for tenant-scoped queries
  machineId: text('machine_id'),
  workflowType: text('workflow_type').notNull(), // weekly_visit, monthly_clean, pod_delivery, refill_task
  qrScanTimestamp: timestamp('qr_scan_timestamp').notNull(),
  qrScanGeoLat: text('qr_scan_geo_lat'),
  qrScanGeoLng: text('qr_scan_geo_lng'),
  qrScanGeoAccuracy: text('qr_scan_geo_accuracy'),
  startedAt: timestamp('started_at').defaultNow(),
  completedAt: timestamp('completed_at'),
  abandonedAt: timestamp('abandoned_at'),
  status: text('status').notNull().default('in_progress'), // in_progress, completed, abandoned
  eventCount: integer('event_count').default(0)
});

// Events Table - Immutable append-only event log (source of truth)
export const events = pgTable('events', {
  id: serial('id').primaryKey(),
  eventId: text('event_id').unique().notNull(), // ULID for ordering
  eventType: text('event_type').notNull(), // STEP_COMPLETED, PHOTO_SUBMITTED, ISSUE_FLAGGED, VISIT_COMPLETED, POD_SUBMITTED, etc.
  actorUserId: integer('actor_user_id').notNull(),
  tenantId: text('tenant_id'), // for tenant-scoped queries
  siteId: text('site_id'),
  machineId: text('machine_id'),
  workflowSessionId: text('workflow_session_id'),
  payloadJson: jsonb('payload_json').notNull(),
  clientTimestamp: timestamp('client_timestamp'),
  serverTimestamp: timestamp('server_timestamp').defaultNow(),
  geoLat: text('geo_lat'),
  geoLng: text('geo_lng'),
  geoAccuracy: text('geo_accuracy'),
  attachmentIds: jsonb('attachment_ids').default([]),
  previousEventHash: text('previous_event_hash'),
  eventHash: text('event_hash').notNull()
});

// Correction Events Table - Appended corrections (never edit originals)
export const correctionEvents = pgTable('correction_events', {
  id: serial('id').primaryKey(),
  correctionId: text('correction_id').unique().notNull(),
  originalEventId: text('original_event_id').notNull(),
  correctedByUserId: integer('corrected_by_user_id').notNull(),
  correctionType: text('correction_type').notNull(), // data_fix, clarification, void
  correctionPayload: jsonb('correction_payload').notNull(),
  reason: text('reason').notNull(),
  serverTimestamp: timestamp('server_timestamp').defaultNow()
});

// Attachments Table - Immutable photo/file records
export const attachments = pgTable('attachments', {
  id: serial('id').primaryKey(),
  attachmentId: text('attachment_id').unique().notNull(),
  eventId: text('event_id'),
  workflowSessionId: text('workflow_session_id'),
  userId: integer('user_id').notNull(),
  tenantId: text('tenant_id'), // for tenant-scoped queries
  siteId: text('site_id'),
  fileHash: text('file_hash').notNull(), // SHA-256 of file bytes
  perceptualHash: text('perceptual_hash'), // for duplicate detection
  objectPath: text('object_path').notNull(),
  fileSizeBytes: integer('file_size_bytes'),
  mimeType: text('mime_type'),
  clientCapturedTimestamp: timestamp('client_captured_timestamp'),
  serverReceivedTimestamp: timestamp('server_received_timestamp').defaultNow(),
  geoLat: text('geo_lat'),
  geoLng: text('geo_lng'),
  geoAccuracy: text('geo_accuracy'),
  deviceInfo: jsonb('device_info'),
  isDuplicate: boolean('is_duplicate').default(false),
  duplicateOfId: text('duplicate_of_id')
});

// Photos Table - Photo proof records with status tracking via events
export const photos = pgTable('photos', {
  id: serial('id').primaryKey(),
  photoId: text('photo_id').unique().notNull(),
  tenantId: text('tenant_id').notNull(),
  siteId: text('site_id').notNull(),
  workflowSessionId: text('workflow_session_id'),
  actorUserId: integer('actor_user_id').notNull(),
  storageKey: text('storage_key').notNull(), // object storage path
  sha256Hash: text('sha256_hash').notNull(), // for duplicate detection
  mimeType: text('mime_type'),
  sizeBytes: integer('size_bytes'),
  width: integer('width'),
  height: integer('height'),
  clientCapturedAt: timestamp('client_captured_at').notNull(),
  serverReceivedAt: timestamp('server_received_at').defaultNow(),
  geoLat: text('geo_lat').notNull(),
  geoLng: text('geo_lng').notNull(),
  geoAccuracyMeters: real('geo_accuracy_meters'),
  createdAt: timestamp('created_at').defaultNow()
});

// Photo Status Events Table - Immutable status transitions for photos
export const photoStatusEvents = pgTable('photo_status_events', {
  id: serial('id').primaryKey(),
  eventId: text('event_id').unique().notNull(),
  photoId: text('photo_id').notNull(),
  status: text('status').notNull(), // PENDING, UPLOADING, UPLOADED, VERIFIED, REJECTED
  actorUserId: integer('actor_user_id').notNull(),
  reason: text('reason'), // for rejections
  serverTimestamp: timestamp('server_timestamp').defaultNow()
});

// Upload Queue Table - Track pending uploads with retry
export const uploadQueue = pgTable('upload_queue', {
  id: serial('id').primaryKey(),
  queueId: text('queue_id').unique().notNull(),
  userId: integer('user_id').notNull(),
  workflowSessionId: text('workflow_session_id'),
  idempotencyKey: text('idempotency_key').unique().notNull(),
  status: text('status').notNull().default('pending'), // pending, uploading, confirmed, failed
  retryCount: integer('retry_count').default(0),
  maxRetries: integer('max_retries').default(3),
  lastAttemptAt: timestamp('last_attempt_at'),
  errorMessage: text('error_message'),
  confirmedAt: timestamp('confirmed_at'),
  attachmentId: text('attachment_id'),
  createdAt: timestamp('created_at').defaultNow()
});

// =====================================================
// PHASE 2.5 - MONITORING & OPERATIONAL CONTROLS
// =====================================================

// System Metrics Table - Aggregated metrics for monitoring
export const systemMetrics = pgTable('system_metrics', {
  id: serial('id').primaryKey(),
  tenantId: text('tenant_id'),
  metricType: text('metric_type').notNull(), // upload_failure, geo_denial, session_completion, login_lockout, visit_duration
  metricValue: real('metric_value').notNull(),
  metricCount: integer('metric_count').default(1),
  periodStart: timestamp('period_start').notNull(),
  periodEnd: timestamp('period_end').notNull(),
  metadata: jsonb('metadata').default({}),
  createdAt: timestamp('created_at').defaultNow()
});

// Upload Failures Table - Track failed uploads for monitoring
export const uploadFailures = pgTable('upload_failures', {
  id: serial('id').primaryKey(),
  tenantId: text('tenant_id'),
  userId: integer('user_id').notNull(),
  siteId: text('site_id'),
  workflowSessionId: text('workflow_session_id'),
  failureType: text('failure_type').notNull(), // network, timeout, file_too_large, invalid_format, storage_error
  errorMessage: text('error_message'),
  fileSizeBytes: integer('file_size_bytes'),
  mimeType: text('mime_type'),
  retryCount: integer('retry_count').default(0),
  resolved: boolean('resolved').default(false),
  resolvedAt: timestamp('resolved_at'),
  createdAt: timestamp('created_at').defaultNow()
});

// Geo Denials Table - Track rejected geo locations
export const geoDenials = pgTable('geo_denials', {
  id: serial('id').primaryKey(),
  tenantId: text('tenant_id'),
  userId: integer('user_id').notNull(),
  siteId: text('site_id'),
  workflowSessionId: text('workflow_session_id'),
  denialReason: text('denial_reason').notNull(), // too_far, no_gps, low_accuracy, spoofed_detection
  expectedLat: text('expected_lat'),
  expectedLng: text('expected_lng'),
  actualLat: text('actual_lat'),
  actualLng: text('actual_lng'),
  distanceMeters: real('distance_meters'),
  accuracyMeters: real('accuracy_meters'),
  deviceInfo: jsonb('device_info'),
  createdAt: timestamp('created_at').defaultNow()
});

// Session Metrics Table - Track workflow session stats
export const sessionMetrics = pgTable('session_metrics', {
  id: serial('id').primaryKey(),
  tenantId: text('tenant_id'),
  workflowSessionId: text('workflow_session_id').notNull(),
  userId: integer('user_id').notNull(),
  siteId: text('site_id'),
  workflowType: text('workflow_type').notNull(),
  status: text('status').notNull(), // completed, abandoned, in_progress
  startedAt: timestamp('started_at').notNull(),
  completedAt: timestamp('completed_at'),
  durationSeconds: integer('duration_seconds'),
  stepCount: integer('step_count').default(0),
  photoCount: integer('photo_count').default(0),
  issueCount: integer('issue_count').default(0),
  receiptHash: text('receipt_hash'), // server receipt bundle hash
  createdAt: timestamp('created_at').defaultNow()
});

// Login Lockouts Table - Track lockout events
export const loginLockouts = pgTable('login_lockouts', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull(),
  employeeCode: text('employee_code').notNull(),
  lockoutReason: text('lockout_reason').notNull(), // max_attempts, suspicious_activity, admin_action
  failedAttempts: integer('failed_attempts').default(0),
  lockedAt: timestamp('locked_at').defaultNow(),
  lockedUntil: timestamp('locked_until'),
  unlockedAt: timestamp('unlocked_at'),
  unlockedBy: integer('unlocked_by'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at').defaultNow()
});

// Rate Limit Tracking Table - Persistent rate limiting
export const rateLimits = pgTable('rate_limits', {
  id: serial('id').primaryKey(),
  limitKey: text('limit_key').unique().notNull(), // e.g., "upload:user:123", "login:ip:1.2.3.4"
  limitType: text('limit_type').notNull(), // upload, login, api_call
  currentCount: integer('current_count').default(0),
  maxCount: integer('max_count').notNull(),
  windowStart: timestamp('window_start').notNull(),
  windowSeconds: integer('window_seconds').notNull(),
  lastRequestAt: timestamp('last_request_at'),
  blocked: boolean('blocked').default(false),
  blockedAt: timestamp('blocked_at'),
  blockedUntil: timestamp('blocked_until')
});

// Data Retention Tracking Table - Track retention policies
export const retentionTracking = pgTable('retention_tracking', {
  id: serial('id').primaryKey(),
  tableName: text('table_name').notNull(),
  recordId: text('record_id').notNull(),
  tenantId: text('tenant_id'),
  retentionDays: integer('retention_days').notNull().default(365),
  createdAt: timestamp('created_at').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  markedForDeletion: boolean('marked_for_deletion').default(false),
  deletedAt: timestamp('deleted_at')
});

// Visit Receipts Table - Server receipt bundles for "no silent failure"
export const visitReceipts = pgTable('visit_receipts', {
  id: serial('id').primaryKey(),
  receiptId: text('receipt_id').unique().notNull(),
  tenantId: text('tenant_id'),
  workflowSessionId: text('workflow_session_id').notNull(),
  userId: integer('user_id').notNull(),
  siteId: text('site_id').notNull(),
  workflowType: text('workflow_type').notNull(),
  receiptHash: text('receipt_hash').notNull(), // SHA-256 of receipt content
  receiptPayload: jsonb('receipt_payload').notNull(), // full receipt data
  eventCount: integer('event_count').default(0),
  photoCount: integer('photo_count').default(0),
  issueCount: integer('issue_count').default(0),
  startedAt: timestamp('started_at').notNull(),
  completedAt: timestamp('completed_at').notNull(),
  durationSeconds: integer('duration_seconds'),
  geoVerified: boolean('geo_verified').default(false),
  clientConfirmedAt: timestamp('client_confirmed_at'),
  createdAt: timestamp('created_at').defaultNow()
});

// Tenant Isolation Alerts Table - Track potential cross-tenant issues
export const tenantIsolationAlerts = pgTable('tenant_isolation_alerts', {
  id: serial('id').primaryKey(),
  alertType: text('alert_type').notNull(), // cross_tenant_query, null_tenant, mismatched_tenant
  tableName: text('table_name'),
  recordIds: jsonb('record_ids'),
  expectedTenantId: text('expected_tenant_id'),
  actualTenantId: text('actual_tenant_id'),
  queryContext: text('query_context'),
  severity: text('severity').notNull().default('warning'), // info, warning, critical
  resolved: boolean('resolved').default(false),
  resolvedAt: timestamp('resolved_at'),
  resolvedBy: integer('resolved_by'),
  createdAt: timestamp('created_at').defaultNow()
});

// ==================== SIPJOLT OS - YILE INTEGRATION ====================

export const vendorTokensTable = `
CREATE TABLE IF NOT EXISTS vendor_tokens (
  token_id SERIAL PRIMARY KEY,
  vendor VARCHAR(50) NOT NULL,
  token TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  refreshed_at TIMESTAMP DEFAULT NOW()
);
`;

export const yileDevicesTable = `
CREATE TABLE IF NOT EXISTS yile_devices (
  device_id SERIAL PRIMARY KEY,
  site_id INTEGER NOT NULL,
  yile_device_id VARCHAR(50) NOT NULL UNIQUE,
  soft_lock_state VARCHAR(20) DEFAULT 'ACTIVE',
  soft_lock_reason TEXT,
  soft_lock_at TIMESTAMP,
  last_seen_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_yile_devices_site ON yile_devices(site_id);
CREATE INDEX IF NOT EXISTS idx_yile_devices_yile_id ON yile_devices(yile_device_id);
`;

export const yileCommandsTable = `
CREATE TABLE IF NOT EXISTS yile_commands (
  command_id SERIAL PRIMARY KEY,
  device_id VARCHAR(50) NOT NULL,
  type VARCHAR(50) NOT NULL,
  requested_by_user_id INTEGER,
  requested_by_role VARCHAR(50),
  payload_json JSONB,
  payload_hash VARCHAR(64),
  idempotency_key VARCHAR(200) UNIQUE,
  vendor_push_id VARCHAR(100),
  status VARCHAR(50) DEFAULT 'QUEUED',
  error_message TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  started_at TIMESTAMP,
  ended_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_yile_commands_device ON yile_commands(device_id);
CREATE INDEX IF NOT EXISTS idx_yile_commands_status ON yile_commands(status);
CREATE INDEX IF NOT EXISTS idx_yile_commands_created ON yile_commands(created_at DESC);
`;

export const yileAuditEventsTable = `
CREATE TABLE IF NOT EXISTS yile_audit_events (
  event_id SERIAL PRIMARY KEY,
  event_type VARCHAR(100),
  actor INTEGER,
  device_id VARCHAR(50),
  metadata_json JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_yile_audit_actor ON yile_audit_events(actor);
CREATE INDEX IF NOT EXISTS idx_yile_audit_device ON yile_audit_events(device_id);
CREATE INDEX IF NOT EXISTS idx_yile_audit_created ON yile_audit_events(created_at DESC);
`;

export const yileMachineStatusTable = `
CREATE TABLE IF NOT EXISTS yile_machine_status (
  status_id SERIAL PRIMARY KEY,
  device_id VARCHAR(50) UNIQUE,
  device_status INTEGER,
  work_status INTEGER,
  net_signal INTEGER,
  device_longitude DECIMAL(10, 7),
  device_latitude DECIMAL(10, 7),
  device_error_info TEXT,
  gmt_update TIMESTAMP,
  device_date TIMESTAMP,
  cached_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_yile_status_cached ON yile_machine_status(cached_at);
`;

export const yileInventoryCacheTable = `
CREATE TABLE IF NOT EXISTS yile_inventory_cache (
  inventory_id SERIAL PRIMARY KEY,
  device_id VARCHAR(50),
  store_type VARCHAR(50),
  vm_now_store INTEGER,
  vm_max_store INTEGER,
  gmt_update TIMESTAMP,
  cached_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(device_id, store_type)
);

CREATE INDEX IF NOT EXISTS idx_yile_inventory_cached ON yile_inventory_cache(cached_at);
`;

export const recipesTable = `
CREATE TABLE IF NOT EXISTS recipes (
  recipe_id SERIAL PRIMARY KEY,
  name VARCHAR(200),
  type VARCHAR(50),
  tab VARCHAR(50),
  is_hot BOOLEAN DEFAULT true,
  price DECIMAL(10, 2),
  status VARCHAR(50) DEFAULT 'TEMPLATE',
  created_at TIMESTAMP DEFAULT NOW()
);
`;

export const recipeStepsTable = `
CREATE TABLE IF NOT EXISTS recipe_steps (
  step_id SERIAL PRIMARY KEY,
  recipe_id INTEGER REFERENCES recipes(recipe_id) ON DELETE CASCADE,
  step_number INTEGER,
  powder_id INTEGER,
  water_ml INTEGER,
  powder_time DECIMAL(5, 2),
  mixing_seconds DECIMAL(5, 2),
  is_use BOOLEAN DEFAULT true,
  notes TEXT,
  UNIQUE(recipe_id, step_number)
);
`;

export const tables = [
  vendorTokensTable,
  yileDevicesTable,
  yileCommandsTable,
  yileAuditEventsTable,
  yileMachineStatusTable,
  yileInventoryCacheTable,
  recipesTable,
  recipeStepsTable
];
