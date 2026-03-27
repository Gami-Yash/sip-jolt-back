import express from 'express';
import {
  opsUsersService,
  opsSitesService,
  opsSiteConfigService,
  opsWeeklyTasksService,
  opsWeeklySubmissionsService,
  opsShipmentsService,
  opsShipmentBoxesService,
  opsPackingLogsService,
  opsDeliveryRecordsService,
  opsIncidentsService,
  opsAuditLogService,
  opsManagerOverridesService,
  opsNotificationsService,
  opsCupsHoldService,
  opsOverweightService,
  opsAutoSafeModeService,
  opsSLATrackerService,
  opsEscalationService,
  opsStreakMultiplierService,
  opsPhotoGuardrailsService,
  opsFleetIntegrityService,
  opsVerificationLockService,
  opsBuildingCommandService,
  boxContentsSnapshotService,
  qcGateEventsService,
  boxScanCustodyService,
  zoneParTargetsService,
  refillCountsService,
  shipmentProposalsService,
  playbookTasksService,
  acceptanceWindowService,
  evidencePacketService,
  goldenPhotosService,
  manifestService,
  goLiveCertificateService,
  kpiScoreboardService,
  weeklyCadenceService,
  landlordDigestService
} from './services/ops.js';

const router = express.Router();

// Role check middleware
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.headers['x-user-role'] || 'partner';
    if (allowedRoles.includes(userRole) || userRole === 'ops_manager') {
      next();
    } else {
      res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
    }
  };
};

// Tenant isolation middleware - enforces that users can only access their own tenant's data
const enforceTenantIsolation = async (req, res, next) => {
  const userTenantId = req.headers['x-tenant-id'];
  const siteId = req.params.siteId;
  
  if (!siteId || !userTenantId) {
    return next();
  }
  
  try {
    const site = await opsSitesService.getBySiteId(siteId);
    
    if (site && site.tenant_id && site.tenant_id !== userTenantId && userTenantId !== 'JOLT_INTERNAL') {
      console.warn(`[TENANT ISOLATION] Blocked cross-tenant access: user tenant ${userTenantId} tried to access site ${siteId} owned by ${site.tenant_id}`);
      return res.status(403).json({ 
        error: 'Access denied: tenant mismatch',
        code: 'TENANT_ISOLATION_VIOLATION'
      });
    }
    
    next();
  } catch (error) {
    console.error('Tenant isolation check error:', error);
    next();
  }
};

// =====================================================
// OPS USERS ROUTES
// =====================================================

router.get('/users', requireRole('ops_manager'), async (req, res) => {
  try {
    const { role } = req.query;
    if (role) {
      const users = await opsUsersService.getByRole(role);
      res.json({ users });
    } else {
      res.status(400).json({ error: 'Role filter required' });
    }
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

router.get('/users/:userId', async (req, res) => {
  try {
    const user = await opsUsersService.getByUserId(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

router.post('/users', requireRole('ops_manager'), async (req, res) => {
  try {
    const user = await opsUsersService.create(req.body);
    res.status(201).json({ user });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

router.put('/users/:userId', requireRole('ops_manager'), async (req, res) => {
  try {
    const user = await opsUsersService.update(req.params.userId, req.body);
    res.json({ user });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// =====================================================
// SITES ROUTES
// =====================================================

router.get('/sites', async (req, res) => {
  try {
    const { status } = req.query;
    let sites;
    if (status) {
      sites = await opsSitesService.getByStatus(status);
    } else {
      sites = await opsSitesService.getAll();
    }
    res.json({ sites });
  } catch (error) {
    console.error('Error fetching sites:', error);
    res.status(500).json({ error: 'Failed to fetch sites' });
  }
});

router.get('/sites/:siteId', enforceTenantIsolation, async (req, res) => {
  try {
    const site = await opsSitesService.getWithConfig(req.params.siteId);
    if (!site) {
      return res.status(404).json({ error: 'Site not found' });
    }
    res.json({ site });
  } catch (error) {
    console.error('Error fetching site:', error);
    res.status(500).json({ error: 'Failed to fetch site' });
  }
});

router.post('/sites', requireRole('ops_manager'), async (req, res) => {
  try {
    const site = await opsSitesService.create(req.body);
    
    // Log audit
    const userId = req.headers['x-user-id'] || 'system';
    const userName = req.headers['x-user-name'] || 'System';
    await opsAuditLogService.log(userId, userName, 'site_created', 'site', site.site_id, req.body);
    
    res.status(201).json({ site });
  } catch (error) {
    console.error('Error creating site:', error);
    res.status(500).json({ error: 'Failed to create site' });
  }
});

router.put('/sites/:siteId', requireRole('ops_manager'), async (req, res) => {
  try {
    const site = await opsSitesService.update(req.params.siteId, req.body);
    res.json({ site });
  } catch (error) {
    console.error('Error updating site:', error);
    res.status(500).json({ error: 'Failed to update site' });
  }
});

router.post('/sites/:siteId/complete-day1', requireRole('partner', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'partner';
    const userName = req.headers['x-user-name'] || 'Partner';
    const { goldenPhotos, zonesLabeled } = req.body;
    
    // Validate required fields
    if (!goldenPhotos || goldenPhotos.length === 0) {
      return res.status(400).json({ error: 'Golden photos are required' });
    }
    
    // Update site
    const site = await opsSitesService.completeDay1(req.params.siteId, userId, goldenPhotos);
    
    // Update zones labeled if provided
    if (zonesLabeled) {
      await opsSiteConfigService.update(req.params.siteId, { zonesLabeled });
    }
    
    // Log audit
    await opsAuditLogService.log(userId, userName, 'day1_completed', 'site', req.params.siteId, { goldenPhotos, zonesLabeled });
    
    res.json({ site, message: 'Day-1 setup completed successfully' });
  } catch (error) {
    console.error('Error completing Day-1:', error);
    res.status(500).json({ error: 'Failed to complete Day-1 setup' });
  }
});

// =====================================================
// SITE CONFIG ROUTES
// =====================================================

router.get('/sites/:siteId/config', async (req, res) => {
  try {
    const config = await opsSiteConfigService.getBySiteId(req.params.siteId);
    if (!config) {
      return res.status(404).json({ error: 'Config not found' });
    }
    res.json({ config });
  } catch (error) {
    console.error('Error fetching config:', error);
    res.status(500).json({ error: 'Failed to fetch config' });
  }
});

router.put('/sites/:siteId/config', requireRole('ops_manager'), async (req, res) => {
  try {
    const config = await opsSiteConfigService.update(req.params.siteId, req.body);
    res.json({ config });
  } catch (error) {
    console.error('Error updating config:', error);
    res.status(500).json({ error: 'Failed to update config' });
  }
});

// =====================================================
// WEEKLY TASKS ROUTES
// =====================================================

router.get('/tasks', async (req, res) => {
  try {
    const { siteId, status } = req.query;
    const tasks = await opsWeeklyTasksService.getAll({ siteId, status });
    res.json({ tasks });
  } catch (error) {
    console.error('Error fetching tasks:', error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

router.get('/tasks/:taskId', async (req, res) => {
  try {
    const task = await opsWeeklyTasksService.getByTaskId(req.params.taskId);
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json({ task });
  } catch (error) {
    console.error('Error fetching task:', error);
    res.status(500).json({ error: 'Failed to fetch task' });
  }
});

router.get('/sites/:siteId/pending-task', async (req, res) => {
  try {
    const task = await opsWeeklyTasksService.getPending(req.params.siteId);
    res.json({ task });
  } catch (error) {
    console.error('Error fetching pending task:', error);
    res.status(500).json({ error: 'Failed to fetch pending task' });
  }
});

router.post('/tasks', requireRole('ops_manager'), async (req, res) => {
  try {
    const { siteId, dueDate, assignedTo } = req.body;
    const task = await opsWeeklyTasksService.create(siteId, dueDate, assignedTo);
    res.status(201).json({ task });
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

router.put('/tasks/:taskId/status', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { status } = req.body;
    const task = await opsWeeklyTasksService.updateStatus(req.params.taskId, status, userId);
    res.json({ task });
  } catch (error) {
    console.error('Error updating task status:', error);
    res.status(500).json({ error: 'Failed to update task status' });
  }
});

router.get('/tasks/overdue', requireRole('ops_manager'), async (req, res) => {
  try {
    const tasks = await opsWeeklyTasksService.getOverdue();
    res.json({ tasks });
  } catch (error) {
    console.error('Error fetching overdue tasks:', error);
    res.status(500).json({ error: 'Failed to fetch overdue tasks' });
  }
});

router.post('/tasks/check-overdue-alerts', requireRole('ops_manager'), async (req, res) => {
  try {
    const alerts = await opsWeeklyTasksService.checkAndCreateOverdueAlerts();
    res.json({ 
      success: true,
      alerts,
      message: `Created ${alerts.created48h.length} attention alerts and ${alerts.created72h.length} emergency alerts`
    });
  } catch (error) {
    console.error('Error checking overdue alerts:', error);
    res.status(500).json({ error: 'Failed to check overdue alerts' });
  }
});

// =====================================================
// WEEKLY SUBMISSIONS ROUTES
// =====================================================

router.get('/submissions', requireRole('ops_manager'), async (req, res) => {
  try {
    const submissions = await opsWeeklySubmissionsService.getRecent(50);
    res.json({ submissions });
  } catch (error) {
    console.error('Error fetching submissions:', error);
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

router.get('/tasks/:taskId/submission', async (req, res) => {
  try {
    const submission = await opsWeeklySubmissionsService.getByTaskId(req.params.taskId);
    res.json({ submission });
  } catch (error) {
    console.error('Error fetching submission:', error);
    res.status(500).json({ error: 'Failed to fetch submission' });
  }
});

router.post('/submissions', requireRole('partner', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'partner';
    const userName = req.headers['x-user-name'] || 'Partner';
    
    // Validate required fields
    const { taskId, siteId, beforePhoto, afterPhoto, matchaCondition } = req.body;
    if (!taskId || !siteId || !beforePhoto || !afterPhoto || !matchaCondition) {
      return res.status(400).json({ error: 'Missing required fields: taskId, siteId, beforePhoto, afterPhoto, matchaCondition' });
    }
    
    // Check if issues require close-up photos
    const issueFlags = req.body.issueFlags || {};
    const hasIssues = issueFlags.lowStock || issueFlags.leakWetBox || issueFlags.messyCloset || issueFlags.accessIssue;
    const closeUpPhotos = req.body.closeUpPhotos || [];
    
    if (hasIssues && closeUpPhotos.length === 0) {
      return res.status(400).json({ error: 'Close-up photos required when issues are flagged' });
    }
    
    const submission = await opsWeeklySubmissionsService.create({
      ...req.body,
      submittedBy: userId
    });
    
    // Log audit
    await opsAuditLogService.log(userId, userName, 'weekly_submitted', 'submission', submission.submission_id, {
      taskId, siteId, matchaCondition, hasIssues
    });
    
    res.status(201).json({ submission, message: 'Weekly refill/clean submitted successfully' });
  } catch (error) {
    console.error('Error creating submission:', error);
    res.status(500).json({ error: 'Failed to create submission' });
  }
});

// =====================================================
// SHIPMENTS ROUTES
// =====================================================

router.get('/shipments', async (req, res) => {
  try {
    const { siteId, status, shipmentType } = req.query;
    const shipments = await opsShipmentsService.getAll({ siteId, status, shipmentType });
    res.json({ shipments });
  } catch (error) {
    console.error('Error fetching shipments:', error);
    res.status(500).json({ error: 'Failed to fetch shipments' });
  }
});

router.get('/shipments/:shipmentId', async (req, res) => {
  try {
    const shipment = await opsShipmentsService.getWithBoxes(req.params.shipmentId);
    if (!shipment) {
      return res.status(404).json({ error: 'Shipment not found' });
    }
    res.json({ shipment });
  } catch (error) {
    console.error('Error fetching shipment:', error);
    res.status(500).json({ error: 'Failed to fetch shipment' });
  }
});

router.post('/shipments', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    
    // Use createWithBoxes to auto-generate boxes based on shipment type
    const shipment = await opsShipmentsService.createWithBoxes({
      ...req.body,
      createdBy: userId
    });
    
    // Log audit
    await opsAuditLogService.log(userId, userName, 'shipment_created', 'shipment', shipment.shipment_id, {
      ...req.body,
      boxCount: shipment.boxes?.length || 0
    });
    
    res.status(201).json({ shipment });
  } catch (error) {
    if (error.message.includes('CUPS_DROP_BLOCKED')) {
      return res.status(400).json({ error: 'Cannot create cups shipment: site has cups drop hold or skip active. Use manager override if needed.' });
    }
    console.error('Error creating shipment:', error);
    res.status(500).json({ error: 'Failed to create shipment' });
  }
});

router.put('/shipments/:shipmentId/status', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { status, refusalReason } = req.body;
    const shipment = await opsShipmentsService.updateStatus(req.params.shipmentId, status, userId, { refusalReason });
    res.json({ shipment });
  } catch (error) {
    console.error('Error updating shipment status:', error);
    res.status(500).json({ error: 'Failed to update shipment status' });
  }
});

// =====================================================
// SHIPMENT BOXES ROUTES
// =====================================================

router.get('/shipments/:shipmentId/boxes', async (req, res) => {
  try {
    const boxes = await opsShipmentBoxesService.getByShipmentId(req.params.shipmentId);
    res.json({ boxes });
  } catch (error) {
    console.error('Error fetching boxes:', error);
    res.status(500).json({ error: 'Failed to fetch boxes' });
  }
});

router.get('/boxes/:boxRecordId', async (req, res) => {
  try {
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    const packingLog = await opsPackingLogsService.getByShipmentBoxId(req.params.boxRecordId);
    res.json({ box, packingLog });
  } catch (error) {
    console.error('Error fetching box:', error);
    res.status(500).json({ error: 'Failed to fetch box' });
  }
});

router.get('/boxes/:boxRecordId/verify', async (req, res) => {
  try {
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    const packingLog = await opsPackingLogsService.getByShipmentBoxId(req.params.boxRecordId);
    const shipment = await opsShipmentsService.getByShipmentId(box.shipment_id);
    const site = shipment ? await opsSitesService.getBySiteId(shipment.site_id) : null;

    res.json({
      verified: true,
      boxId: box.box_record_id,
      boxType: box.box_id,
      weight: packingLog?.weight || box.weight || null,
      packDate: packingLog?.packed_at || box.created_at,
      status: box.status || (packingLog ? 'packed' : 'created'),
      isOverweight: packingLog?.is_overweight || box.is_overweight || false,
      shipmentId: box.shipment_id,
      shipmentStatus: shipment?.status || null,
      siteName: site?.venue_name || 'Unknown Site',
      siteAddress: site?.address || null,
      contents: packingLog?.items_packed || [],
      hasLiquids: box.has_liquids || false,
      hasInnerKits: box.has_inner_kits || false
    });
  } catch (error) {
    console.error('Error verifying box:', error);
    res.status(500).json({ error: 'Failed to verify box' });
  }
});

router.post('/shipments/:shipmentId/boxes', requireRole('ops_manager'), async (req, res) => {
  try {
    const box = await opsShipmentBoxesService.create({
      ...req.body,
      shipmentId: req.params.shipmentId
    });
    res.status(201).json({ box });
  } catch (error) {
    console.error('Error creating box:', error);
    res.status(500).json({ error: 'Failed to create box' });
  }
});

// =====================================================
// PACKING LOGS ROUTES
// =====================================================

router.get('/boxes/:boxRecordId/packing-log', async (req, res) => {
  try {
    const packingLog = await opsPackingLogsService.getByShipmentBoxId(req.params.boxRecordId);
    res.json({ packingLog });
  } catch (error) {
    console.error('Error fetching packing log:', error);
    res.status(500).json({ error: 'Failed to fetch packing log' });
  }
});

router.post('/boxes/:boxRecordId/packing-log', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    
    const packingLog = await opsPackingLogsService.create({
      ...req.body,
      shipmentBoxId: req.params.boxRecordId,
      packedByUserId: userId,
      packedByUserName: userName
    });
    
    await opsAuditLogService.log(userId, userName, 'packing_log_created', 'box', req.params.boxRecordId, req.body);
    
    res.status(201).json({ packingLog, message: 'Box marked as PACKED' });
  } catch (error) {
    if (error.message.includes('VALIDATION_ERROR')) {
      return res.status(400).json({ error: error.message.replace('VALIDATION_ERROR: ', '') });
    }
    console.error('Error creating packing log:', error);
    res.status(500).json({ error: 'Failed to create packing log' });
  }
});

router.put('/boxes/:boxRecordId/packing-log', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    
    const existingLog = await opsPackingLogsService.getByShipmentBoxId(req.params.boxRecordId);
    if (!existingLog) {
      return res.status(404).json({ error: 'Packing log not found' });
    }
    
    const packingLog = await opsPackingLogsService.update(existingLog.packing_log_id, req.body);
    await opsAuditLogService.log(userId, userName, 'packing_log_edited', 'box', req.params.boxRecordId, req.body);
    
    res.json({ packingLog });
  } catch (error) {
    console.error('Error updating packing log:', error);
    res.status(500).json({ error: 'Failed to update packing log' });
  }
});

// =====================================================
// LABEL GENERATION ROUTES
// =====================================================

router.post('/boxes/:boxRecordId/generate-label', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    const { labelType } = req.body;
    
    // Check if box is PACKED (has packing log)
    const boxData = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!boxData) {
      return res.status(404).json({ error: 'Box not found' });
    }
    if (boxData.status === 'pending') {
      return res.status(400).json({ error: 'Cannot generate label: Box must be PACKED first. Complete the packing log.' });
    }
    
    // Build QR payload with deep link
    const qrPayload = JSON.stringify({
      type: 'shipment_box',
      boxRecordId: req.params.boxRecordId,
      shipmentId: boxData.shipment_id,
      siteId: boxData.site_id,
      url: `/ops/boxes/${req.params.boxRecordId}`
    });
    
    // Build label payload for storage/reprint
    const labelPayloadJson = {
      siteId: boxData.site_id,
      venueName: boxData.venue_name,
      address: boxData.address,
      attn: boxData.primary_contact_name || 'Site Manager',
      boxId: boxData.box_id,
      descriptor: boxData.descriptor,
      boxNumber: boxData.box_number,
      totalInSet: boxData.total_in_set,
      batchId: boxData.batch_id,
      packDate: boxData.pack_date,
      weight: boxData.weight,
      isHeavy: boxData.is_heavy,
      hasLiquids: boxData.has_liquids,
      hasInnerKits: boxData.has_inner_kits,
      carrierType: boxData.carrier_type,
      trackingNumber: boxData.tracking_number,
      labelType: labelType || (boxData.carrier_type === 'ups' ? 'ups_addon' : 'milk_run'),
      generatedAt: new Date().toISOString()
    };
    
    const box = await opsShipmentBoxesService.markLabelGenerated(
      req.params.boxRecordId, 
      labelPayloadJson.labelType, 
      qrPayload, 
      labelPayloadJson
    );
    
    const isReprint = boxData.label_generated_at !== null;
    await opsAuditLogService.log(userId, userName, isReprint ? 'label_reprinted' : 'label_generated', 'box', req.params.boxRecordId, { labelType: labelPayloadJson.labelType });
    
    res.json({ box, labelPayload: labelPayloadJson, qrPayload });
  } catch (error) {
    console.error('Error generating label:', error);
    res.status(500).json({ error: 'Failed to generate label' });
  }
});

router.get('/boxes/:boxRecordId/label-data', async (req, res) => {
  try {
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    const packingLog = await opsPackingLogsService.getByShipmentBoxId(req.params.boxRecordId);
    
    const labelData = {
      siteId: box.site_id,
      venueName: box.venue_name,
      address: box.address,
      attn: box.primary_contact_name || 'Site Manager',
      boxId: box.box_id,
      descriptor: box.descriptor,
      boxNumber: box.box_number,
      totalInSet: box.total_in_set,
      batchId: box.batch_id || packingLog?.batch_id,
      packDate: box.pack_date || packingLog?.pack_date,
      weight: box.weight || packingLog?.weight_lb,
      isHeavy: box.is_heavy || (packingLog?.weight_lb && parseFloat(packingLog.weight_lb) > 40),
      hasLiquids: box.has_liquids,
      hasInnerKits: box.has_inner_kits,
      carrierType: box.carrier_type,
      trackingNumber: box.tracking_number,
      labelType: box.label_type,
      labelGeneratedAt: box.label_generated_at,
      status: box.status
    };
    
    res.json({ labelData, box, packingLog });
  } catch (error) {
    console.error('Error fetching label data:', error);
    res.status(500).json({ error: 'Failed to fetch label data' });
  }
});

// =====================================================
// DELIVERY RECORDS ROUTES
// =====================================================

router.get('/deliveries', async (req, res) => {
  try {
    const { shipmentId, siteId } = req.query;
    if (shipmentId) {
      const deliveries = await opsDeliveryRecordsService.getByShipmentId(shipmentId);
      res.json({ deliveries });
    } else if (siteId) {
      const deliveries = await opsDeliveryRecordsService.getPendingForPartner(siteId);
      res.json({ deliveries });
    } else {
      res.status(400).json({ error: 'shipmentId or siteId query required' });
    }
  } catch (error) {
    console.error('Error fetching deliveries:', error);
    res.status(500).json({ error: 'Failed to fetch deliveries' });
  }
});

router.get('/deliveries/:deliveryId', async (req, res) => {
  try {
    const delivery = await opsDeliveryRecordsService.getByDeliveryId(req.params.deliveryId);
    if (!delivery) {
      return res.status(404).json({ error: 'Delivery not found' });
    }
    res.json({ delivery });
  } catch (error) {
    console.error('Error fetching delivery:', error);
    res.status(500).json({ error: 'Failed to fetch delivery' });
  }
});

router.post('/deliveries/pod', requireRole('driver', 'ops_manager'), async (req, res) => {
  try {
    const driverId = req.headers['x-user-id'] || 'driver';
    const driverName = req.headers['x-user-name'] || 'Driver';
    
    // Validate required fields
    const { shipmentId, siteId, carrierType, placementPhotos } = req.body;
    if (!shipmentId || !siteId || !carrierType) {
      return res.status(400).json({ error: 'Missing required fields: shipmentId, siteId, carrierType' });
    }
    
    // UPS requires tracking number
    if (carrierType === 'ups' && !req.body.trackingNumber) {
      return res.status(400).json({ error: 'Tracking number required for UPS deliveries' });
    }
    
    // Placement photos required unless access denied
    if (!req.body.accessDenied && (!placementPhotos || placementPhotos.length === 0)) {
      return res.status(400).json({ error: 'Placement photos required for delivery' });
    }
    
    const delivery = await opsDeliveryRecordsService.createPOD({
      ...req.body,
      driverId,
      driverName
    });
    
    // Log audit
    await opsAuditLogService.log(driverId, driverName, 'delivery_pod', 'delivery', delivery.delivery_id, {
      shipmentId, siteId, carrierType, accessDenied: req.body.accessDenied, siteFailFlag: req.body.siteFailFlag
    });
    
    res.status(201).json({ delivery, message: 'Proof of delivery recorded' });
  } catch (error) {
    console.error('Error creating POD:', error);
    res.status(500).json({ error: 'Failed to create POD' });
  }
});

router.post('/deliveries/:deliveryId/accept', requireRole('partner', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'partner';
    const userName = req.headers['x-user-name'] || 'Partner';
    
    const delivery = await opsDeliveryRecordsService.partnerAccept(req.params.deliveryId, userId);
    
    // Log audit
    await opsAuditLogService.log(userId, userName, 'delivery_accepted', 'delivery', req.params.deliveryId, {});
    
    res.json({ delivery, message: 'Delivery accepted' });
  } catch (error) {
    console.error('Error accepting delivery:', error);
    res.status(500).json({ error: 'Failed to accept delivery' });
  }
});

router.post('/deliveries/:deliveryId/refuse', requireRole('partner', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'partner';
    const userName = req.headers['x-user-name'] || 'Partner';
    
    const { reason, photo, notes } = req.body;
    if (!reason) {
      return res.status(400).json({ error: 'Refusal reason required' });
    }
    
    // Wet/leak requires photo
    if (reason === 'wet_leak' && !photo) {
      return res.status(400).json({ error: 'Photo required for wet/leak refusal' });
    }
    
    const delivery = await opsDeliveryRecordsService.partnerRefuse(req.params.deliveryId, userId, reason, photo, notes);
    
    // Log audit
    await opsAuditLogService.log(userId, userName, 'delivery_refused', 'delivery', req.params.deliveryId, { reason });
    
    res.json({ delivery, message: 'Delivery refused. Incident created.' });
  } catch (error) {
    console.error('Error refusing delivery:', error);
    res.status(500).json({ error: 'Failed to refuse delivery' });
  }
});

// =====================================================
// INCIDENTS ROUTES
// =====================================================

router.get('/incidents', async (req, res) => {
  try {
    const { siteId, status, type } = req.query;
    const incidents = await opsIncidentsService.getAll({ siteId, status, type });
    res.json({ incidents });
  } catch (error) {
    console.error('Error fetching incidents:', error);
    res.status(500).json({ error: 'Failed to fetch incidents' });
  }
});

router.get('/incidents/open', requireRole('ops_manager'), async (req, res) => {
  try {
    const incidents = await opsIncidentsService.getOpen();
    res.json({ incidents });
  } catch (error) {
    console.error('Error fetching open incidents:', error);
    res.status(500).json({ error: 'Failed to fetch open incidents' });
  }
});

router.get('/incidents/:incidentId', async (req, res) => {
  try {
    const incident = await opsIncidentsService.getByIncidentId(req.params.incidentId);
    if (!incident) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    res.json({ incident });
  } catch (error) {
    console.error('Error fetching incident:', error);
    res.status(500).json({ error: 'Failed to fetch incident' });
  }
});

router.post('/incidents', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const incident = await opsIncidentsService.create({
      ...req.body,
      createdBy: userId
    });
    res.status(201).json({ incident });
  } catch (error) {
    console.error('Error creating incident:', error);
    res.status(500).json({ error: 'Failed to create incident' });
  }
});

router.put('/incidents/:incidentId/assign', requireRole('ops_manager'), async (req, res) => {
  try {
    const { assignTo } = req.body;
    const incident = await opsIncidentsService.assign(req.params.incidentId, assignTo);
    res.json({ incident });
  } catch (error) {
    console.error('Error assigning incident:', error);
    res.status(500).json({ error: 'Failed to assign incident' });
  }
});

router.put('/incidents/:incidentId/resolve', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    const { notes } = req.body;
    
    const incident = await opsIncidentsService.resolve(req.params.incidentId, userId, notes);
    
    // Log audit
    await opsAuditLogService.log(userId, userName, 'incident_resolved', 'incident', req.params.incidentId, { notes });
    
    res.json({ incident });
  } catch (error) {
    console.error('Error resolving incident:', error);
    res.status(500).json({ error: 'Failed to resolve incident' });
  }
});

// =====================================================
// AUDIT LOG ROUTES
// =====================================================

router.get('/audit-log', requireRole('ops_manager'), async (req, res) => {
  try {
    const { entityType, entityId, limit } = req.query;
    let logs;
    if (entityType && entityId) {
      logs = await opsAuditLogService.getByEntity(entityType, entityId);
    } else {
      logs = await opsAuditLogService.getRecent(parseInt(limit) || 50);
    }
    res.json({ logs });
  } catch (error) {
    console.error('Error fetching audit log:', error);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// =====================================================
// MANAGER OVERRIDES ROUTES
// =====================================================

router.get('/overrides', requireRole('ops_manager'), async (req, res) => {
  try {
    const overrides = await opsManagerOverridesService.getRecent(50);
    res.json({ overrides });
  } catch (error) {
    console.error('Error fetching overrides:', error);
    res.status(500).json({ error: 'Failed to fetch overrides' });
  }
});

router.post('/overrides', requireRole('ops_manager'), async (req, res) => {
  try {
    const managerId = req.headers['x-user-id'] || 'ops';
    const managerName = req.headers['x-user-name'] || 'Ops Manager';
    
    const { reason } = req.body;
    if (!reason) {
      return res.status(400).json({ error: 'Override reason is required' });
    }
    
    const override = await opsManagerOverridesService.create({
      ...req.body,
      managerId,
      managerName
    });
    
    res.status(201).json({ override, message: 'Manager override recorded' });
  } catch (error) {
    console.error('Error creating override:', error);
    res.status(500).json({ error: 'Failed to create override' });
  }
});

// =====================================================
// DASHBOARD STATS ROUTE
// =====================================================

router.get('/dashboard/stats', requireRole('ops_manager'), async (req, res) => {
  try {
    const [sites, openIncidents, pendingTasks, recentSubmissions, unreadNotifications] = await Promise.all([
      opsSitesService.getAll(),
      opsIncidentsService.getOpen(),
      opsWeeklyTasksService.getAll({ status: 'pending' }),
      opsWeeklySubmissionsService.getRecent(10),
      opsNotificationsService.getUnreadCount()
    ]);
    
    res.json({
      stats: {
        totalSites: sites.length,
        activeSites: sites.filter(s => s.status === 'active').length,
        pendingSetup: sites.filter(s => s.status === 'pending_setup').length,
        openIncidents: openIncidents.length,
        criticalIncidents: openIncidents.filter(i => i.severity === 'critical').length,
        pendingTasks: pendingTasks.length,
        recentSubmissions: recentSubmissions.length,
        unreadNotifications
      },
      openIncidents: openIncidents.slice(0, 5),
      pendingTasks: pendingTasks.slice(0, 5),
      recentSubmissions: recentSubmissions.slice(0, 5)
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// =====================================================
// NOTIFICATIONS ROUTES
// =====================================================

router.get('/notifications', requireRole('ops_manager'), async (req, res) => {
  try {
    const { siteId, severity, type, unreadOnly, limit } = req.query;
    const notifications = await opsNotificationsService.getAll({
      siteId,
      severity,
      type,
      unreadOnly: unreadOnly === 'true',
      limit: parseInt(limit) || 100
    });
    res.json({ notifications });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

router.get('/notifications/count', requireRole('ops_manager'), async (req, res) => {
  try {
    const count = await opsNotificationsService.getUnreadCount();
    res.json({ count });
  } catch (error) {
    console.error('Error fetching notification count:', error);
    res.status(500).json({ error: 'Failed to fetch notification count' });
  }
});

router.post('/notifications/:notificationId/read', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const notification = await opsNotificationsService.markRead(req.params.notificationId, userId);
    res.json({ notification });
  } catch (error) {
    console.error('Error marking notification read:', error);
    res.status(500).json({ error: 'Failed to mark notification read' });
  }
});

router.post('/notifications/mark-all-read', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    await opsNotificationsService.markAllRead(userId);
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications read:', error);
    res.status(500).json({ error: 'Failed to mark all notifications read' });
  }
});

// =====================================================
// CUPS HOLD ROUTES
// =====================================================

router.post('/sites/:siteId/cups-hold/activate', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    const { reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Reason is required to activate cups hold' });
    }
    
    const site = await opsCupsHoldService.activateHold(req.params.siteId, reason, userId, userName);
    res.json({ site, message: 'Cups hold activated' });
  } catch (error) {
    console.error('Error activating cups hold:', error);
    res.status(500).json({ error: 'Failed to activate cups hold' });
  }
});

router.post('/sites/:siteId/cups-hold/clear', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    const { reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Reason is required to clear cups hold' });
    }
    
    const site = await opsCupsHoldService.clearHold(req.params.siteId, reason, userId, userName);
    res.json({ site, message: 'Cups hold cleared' });
  } catch (error) {
    console.error('Error clearing cups hold:', error);
    res.status(500).json({ error: 'Failed to clear cups hold' });
  }
});

router.get('/sites/:siteId/cups-hold/status', async (req, res) => {
  try {
    const status = await opsCupsHoldService.checkHoldStatus(req.params.siteId);
    res.json(status);
  } catch (error) {
    console.error('Error checking cups hold status:', error);
    res.status(500).json({ error: 'Failed to check cups hold status' });
  }
});

// =====================================================
// BOX CONFIG ROUTES
// =====================================================

router.get('/sites/:siteId/box-config', async (req, res) => {
  try {
    const config = await opsSiteConfigService.getBoxConfig(req.params.siteId);
    res.json({ config });
  } catch (error) {
    console.error('Error fetching box config:', error);
    res.status(500).json({ error: 'Failed to fetch box config' });
  }
});

router.put('/sites/:siteId/box-config', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'ops';
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    
    const config = await opsSiteConfigService.updateBoxConfig(
      req.params.siteId,
      req.body,
      userId,
      userName
    );
    res.json({ config, message: 'Box config updated' });
  } catch (error) {
    console.error('Error updating box config:', error);
    res.status(500).json({ error: 'Failed to update box config' });
  }
});

router.post('/sites/:siteId/check-deviation', async (req, res) => {
  try {
    const { selectedBoxes, shipmentType } = req.body;
    const deviation = await opsSiteConfigService.checkDeviation(
      req.params.siteId,
      selectedBoxes || [],
      shipmentType
    );
    res.json(deviation);
  } catch (error) {
    console.error('Error checking deviation:', error);
    res.status(500).json({ error: 'Failed to check deviation' });
  }
});

// =====================================================
// IMMUTABLE WEIGHT LAW - NO OVERRIDES ALLOWED
// =====================================================

router.get('/shipments/:shipmentId/can-ship', async (req, res) => {
  try {
    const result = await opsOverweightService.canMarkShipped(req.params.shipmentId);
    res.json(result);
  } catch (error) {
    console.error('Error checking ship eligibility:', error);
    res.status(500).json({ error: 'Failed to check ship eligibility' });
  }
});

router.get('/shipments/:shipmentId/weight-check', async (req, res) => {
  try {
    const result = await opsOverweightService.checkShipmentOverweight(req.params.shipmentId);
    res.json({
      ...result,
      weightLimit: opsOverweightService.WEIGHT_LIMIT_LBS,
      policy: 'IMMUTABLE_WEIGHT_LAW',
      message: result.hasOverweight 
        ? `Shipment contains overweight boxes exceeding ${opsOverweightService.WEIGHT_LIMIT_LBS} lb limit. These boxes must be repacked - no overrides allowed.`
        : 'All boxes within weight limit'
    });
  } catch (error) {
    console.error('Error checking weight:', error);
    res.status(500).json({ error: 'Failed to check weight' });
  }
});

router.get('/users/:userId/penalties', async (req, res) => {
  try {
    const penalty = await opsOverweightService.getUserPenalty(req.params.userId);
    res.json(penalty);
  } catch (error) {
    console.error('Error getting user penalties:', error);
    res.status(500).json({ error: 'Failed to get user penalties' });
  }
});

// =====================================================
// CUPS HOLD OVERRIDE FOR SHIPMENT CREATION
// =====================================================

router.post('/shipments/:shipmentId/cups-hold-override', requireRole('ops_manager'), async (req, res) => {
  try {
    const managerId = req.headers['x-user-id'] || 'ops';
    const managerName = req.headers['x-user-name'] || 'Ops Manager';
    const { siteId, reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Reason is required for cups hold override' });
    }
    
    const override = await opsCupsHoldService.overrideHold(
      siteId,
      req.params.shipmentId,
      reason,
      managerId,
      managerName
    );
    
    const { getPool } = await import('./db.js');
    const pool = getPool();
    await pool.query(
      `UPDATE ops_shipments SET cups_hold_override_id = $2, updated_at = NOW() WHERE shipment_id = $1`,
      [req.params.shipmentId, override.override_id]
    );
    
    res.json({ override, message: 'Cups hold override recorded' });
  } catch (error) {
    console.error('Error creating cups hold override:', error);
    res.status(500).json({ error: 'Failed to create cups hold override' });
  }
});

// =====================================================
// BOX CONFIG DEVIATION OVERRIDE FOR SHIPMENT
// =====================================================

router.post('/shipments/:shipmentId/box-deviation-override', requireRole('ops_manager'), async (req, res) => {
  try {
    const managerId = req.headers['x-user-id'] || 'ops';
    const managerName = req.headers['x-user-name'] || 'Ops Manager';
    const { siteId, reason, expectedBoxes, actualBoxes } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Reason is required for box deviation override' });
    }
    
    const override = await opsManagerOverridesService.create({
      managerId,
      managerName,
      overrideType: 'box_config_deviation',
      siteId,
      entityType: 'shipment',
      entityId: req.params.shipmentId,
      reason,
      previousValue: { expectedBoxes },
      newValue: { actualBoxes }
    });
    
    const { getPool } = await import('./db.js');
    const pool = getPool();
    await pool.query(
      `UPDATE ops_shipments SET box_config_deviation_override_id = $2, updated_at = NOW() WHERE shipment_id = $1`,
      [req.params.shipmentId, override.override_id]
    );
    
    await opsNotificationsService.create({
      siteId,
      type: 'manager_override',
      severity: 'normal',
      title: 'Box Config Deviation Override',
      message: `Manager ${managerName} approved box deviation: ${reason}`,
      linkedEntityType: 'shipment',
      linkedEntityId: req.params.shipmentId
    });
    
    res.json({ override, message: 'Box deviation override recorded' });
  } catch (error) {
    console.error('Error creating box deviation override:', error);
    res.status(500).json({ error: 'Failed to create box deviation override' });
  }
});

// =====================================================
// DRIVER POD ROUTES
// =====================================================

router.post('/deliveries', requireRole('driver', 'ops_manager'), async (req, res) => {
  try {
    const driverId = req.headers['x-user-id'];
    const driverName = req.headers['x-user-name'] || 'Driver';
    
    const { shipmentId, siteId, carrierType, trackingNumber, closetPhotos, flags, notes } = req.body;
    
    if (!shipmentId || !siteId || !closetPhotos || closetPhotos.length === 0) {
      return res.status(400).json({ error: 'Shipment ID, Site ID, and closet photos are required' });
    }
    
    if (carrierType === 'ups' && !trackingNumber) {
      return res.status(400).json({ error: 'Tracking number is required for UPS deliveries' });
    }
    
    const delivery = await opsDeliveryRecordsService.createPOD({
      shipmentId,
      siteId,
      driverId,
      driverName,
      carrierType: carrierType || 'milk_run',
      trackingNumber,
      placementPhotos: closetPhotos,
      accessDenied: flags?.accessDenied || false,
      accessDeniedPhoto: flags?.accessDenied ? closetPhotos[0] : null,
      accessDeniedNotes: flags?.accessDenied ? notes : null,
      siteFailFlag: flags?.siteFailMessy || false,
      siteFailPhoto: flags?.siteFailMessy ? closetPhotos[0] : null,
      siteFailNotes: flags?.siteFailMessy ? notes : null
    });
    
    await opsAuditLogService.log(
      driverId, driverName, 'DELIVERY_POD_CREATED',
      'delivery', delivery.delivery_id, { shipmentId, siteId, carrierType, flags }
    );
    
    if (flags?.wetLeakSeen) {
      const { getPool } = await import('./db.js');
      const pool = getPool();
      await pool.query(
        `UPDATE ops_delivery_records SET wet_leak_flagged = TRUE WHERE delivery_id = $1`,
        [delivery.delivery_id]
      );
      
      await opsIncidentsService.create({
        siteId,
        type: 'wet_leak_refusal',
        severity: 'critical',
        title: 'Wet/Leak Seen at Delivery',
        description: `Driver observed wet/leak condition at delivery`,
        photos: closetPhotos,
        relatedShipmentId: shipmentId,
        relatedDeliveryId: delivery.delivery_id,
        autoCreated: true
      });
      await opsNotificationsService.create({
        siteId,
        type: 'delivery_refusal',
        severity: 'critical',
        title: 'Wet/Leak Condition',
        message: `Driver ${driverName} flagged wet/leak at delivery - partner must refuse`,
        linkedEntityType: 'delivery',
        linkedEntityId: delivery.delivery_id
      });
    }
    
    if (flags?.siteFailMessy && !flags?.accessDenied) {
      await opsNotificationsService.create({
        siteId,
        type: 'site_fail',
        severity: 'high',
        title: 'SITE FAIL Reported',
        message: `Driver ${driverName} flagged closet as disorganized`,
        linkedEntityType: 'delivery',
        linkedEntityId: delivery.delivery_id
      });
    }
    
    res.status(201).json({ delivery, message: 'Proof of delivery recorded' });
  } catch (error) {
    console.error('Error creating delivery POD:', error);
    res.status(500).json({ error: 'Failed to create delivery POD' });
  }
});

router.get('/deliveries/pending/:siteId', async (req, res) => {
  try {
    const deliveries = await opsDeliveryRecordsService.getPendingBySite(req.params.siteId);
    res.json({ deliveries });
  } catch (error) {
    console.error('Error fetching pending deliveries:', error);
    res.status(500).json({ error: 'Failed to fetch pending deliveries' });
  }
});

// =====================================================
// TECHNICIAN DELIVERY ACCEPT/REFUSE ROUTES
// =====================================================

router.post('/deliveries/:deliveryId/accept', requireRole('partner', 'technician', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userName = req.headers['x-user-name'] || 'Partner';
    
    const delivery = await opsDeliveryRecordsService.getByDeliveryId(req.params.deliveryId);
    if (!delivery) {
      return res.status(404).json({ error: 'Delivery not found' });
    }
    
    if (delivery.wet_leak_flagged) {
      return res.status(400).json({ 
        error: 'Cannot accept delivery with wet/leak condition. Must refuse.' 
      });
    }
    
    const updated = await opsDeliveryRecordsService.accept(req.params.deliveryId, userId);
    
    await opsAuditLogService.log(
      userId, userName, 'DELIVERY_ACCEPTED',
      'delivery', req.params.deliveryId, { shipmentId: delivery.shipment_id }
    );
    
    const allDeliveries = await opsDeliveryRecordsService.getByShipmentId(delivery.shipment_id);
    const allAccepted = allDeliveries.every(d => d.status === 'accepted');
    if (allAccepted && allDeliveries.length > 0) {
      await opsShipmentsService.updateStatus(delivery.shipment_id, 'delivered', userId);
    }
    
    res.json({ delivery: updated, message: 'Delivery accepted' });
  } catch (error) {
    console.error('Error accepting delivery:', error);
    res.status(500).json({ error: 'Failed to accept delivery' });
  }
});

router.post('/deliveries/:deliveryId/refuse', requireRole('partner', 'technician', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userName = req.headers['x-user-name'] || 'Partner';
    
    const { reason, photo, notes } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Reason is required to refuse delivery' });
    }
    if (!photo) {
      return res.status(400).json({ error: 'Photo is required to refuse delivery' });
    }
    if (reason === 'other' && !notes) {
      return res.status(400).json({ error: 'Notes are required when refusing with "Other" reason' });
    }
    
    const delivery = await opsDeliveryRecordsService.getByDeliveryId(req.params.deliveryId);
    if (!delivery) {
      return res.status(404).json({ error: 'Delivery not found' });
    }
    
    const updated = await opsDeliveryRecordsService.refuse(req.params.deliveryId, userId, reason, photo, notes);
    
    await opsAuditLogService.log(
      userId, userName, 'DELIVERY_REFUSED',
      'delivery', req.params.deliveryId, { shipmentId: delivery.shipment_id, reason, notes }
    );
    
    const severity = reason === 'wet_leak' ? 'critical' : 'high';
    await opsIncidentsService.create({
      siteId: delivery.site_id,
      type: 'delivery_refused',
      severity,
      title: `Delivery Refused: ${reason.replace('_', ' ').toUpperCase()}`,
      description: notes || `Partner refused delivery with reason: ${reason}`,
      photos: [photo],
      relatedShipmentId: delivery.shipment_id,
      relatedDeliveryId: req.params.deliveryId,
      autoCreated: true
    });
    
    await opsNotificationsService.create({
      siteId: delivery.site_id,
      type: 'delivery_refusal',
      severity,
      title: 'Delivery Refused',
      message: `${userName} refused delivery: ${reason}`,
      linkedEntityType: 'delivery',
      linkedEntityId: req.params.deliveryId
    });
    
    await opsShipmentsService.updateStatus(delivery.shipment_id, 'refused', userId);
    
    res.json({ delivery: updated, message: 'Delivery refused and incident created' });
  } catch (error) {
    console.error('Error refusing delivery:', error);
    res.status(500).json({ error: 'Failed to refuse delivery' });
  }
});

// =====================================================
// QR VERIFICATION ROUTE (ROLE-SAFE)
// =====================================================

router.get('/verify/box/:boxRecordId', async (req, res) => {
  try {
    const userRole = req.headers['x-user-role'] || 'partner';
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    const verification = {
      boxRecordId: box.box_record_id,
      siteId: box.site_id,
      siteName: box.venue_name,
      boxId: box.box_id,
      descriptor: box.descriptor,
      boxNumber: box.box_number,
      totalInSet: box.total_in_set,
      status: box.status,
      packDate: box.pack_date,
      batchId: box.batch_id,
      weight: box.weight,
      isHeavy: box.is_heavy,
      isOverweight: box.is_overweight,
      labelType: box.label_type,
      shipmentId: box.shipment_id,
      trackingNumber: box.tracking_number,
      carrierType: box.carrier_type
    };
    
    if (userRole === 'ops_manager') {
      verification.packingLogId = box.packing_log_id;
      verification.labelGeneratedAt = box.label_generated_at;
      verification.labelPayloadJson = box.label_payload_json;
      verification.qrPayload = box.qr_payload;
      verification.shipmentDetailLink = `/ops/shipments/${box.shipment_id}`;
    }
    
    res.json({ verification, userRole });
  } catch (error) {
    console.error('Error fetching box verification:', error);
    res.status(500).json({ error: 'Failed to fetch box verification' });
  }
});

// =====================================================
// SAFE MODE ROUTES (Auto Self-Healing)
// =====================================================

router.get('/sites/:siteId/safe-mode-status', async (req, res) => {
  try {
    const status = await opsAutoSafeModeService.checkSiteStatus(req.params.siteId);
    res.json(status);
  } catch (error) {
    console.error('Error checking safe mode status:', error);
    res.status(500).json({ error: 'Failed to check safe mode status' });
  }
});

// =====================================================
// SLA TRACKER ROUTES (Kroc-Standard Timing)
// =====================================================

router.post('/tasks/:taskId/complete-with-sla', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'partner';
    const userName = req.headers['x-user-name'] || 'Partner';
    const { taskType, startTime, endTime, qualityScore } = req.body;
    
    const slaResult = await opsSLATrackerService.recordTaskCompletion(
      req.params.taskId,
      taskType || 'weekly',
      startTime,
      endTime || new Date().toISOString(),
      userId,
      userName
    );

    if (slaResult.metBenchmark && qualityScore >= 80) {
      await opsStreakMultiplierService.recordVisitQuality(
        userId, userName, req.params.taskId, true, qualityScore
      );
    } else {
      await opsStreakMultiplierService.recordVisitQuality(
        userId, userName, req.params.taskId, slaResult.metBenchmark, qualityScore || 0
      );
    }

    const streakBonus = await opsStreakMultiplierService.getUserStreakBonus(userId);
    
    res.json({ 
      sla: slaResult,
      streak: streakBonus,
      message: slaResult.metBenchmark 
        ? `Precision Bonus earned! Task completed in ${slaResult.durationMins} min (benchmark: ${slaResult.benchmark} min)`
        : `Task completed in ${slaResult.durationMins} min (benchmark: ${slaResult.benchmark} min)`
    });
  } catch (error) {
    console.error('Error recording SLA completion:', error);
    res.status(500).json({ error: 'Failed to record SLA completion' });
  }
});

router.get('/sites/:siteId/efficiency-score', async (req, res) => {
  try {
    const score = await opsSLATrackerService.getSiteEfficiencyScore(req.params.siteId);
    res.json(score);
  } catch (error) {
    console.error('Error getting efficiency score:', error);
    res.status(500).json({ error: 'Failed to get efficiency score' });
  }
});

// =====================================================
// ESCALATION ROUTES (Building Manager Alerts)
// =====================================================

router.post('/sites/:siteId/check-escalation', requireRole('ops_manager'), async (req, res) => {
  try {
    const { issueType, issueId, createdAt } = req.body;
    const result = await opsEscalationService.checkAndEscalate(
      req.params.siteId,
      issueType,
      issueId,
      createdAt
    );
    res.json(result);
  } catch (error) {
    console.error('Error checking escalation:', error);
    res.status(500).json({ error: 'Failed to check escalation' });
  }
});

router.get('/escalations/pending', requireRole('ops_manager'), async (req, res) => {
  try {
    const escalations = await opsEscalationService.getPendingEscalations();
    res.json({ escalations });
  } catch (error) {
    console.error('Error getting pending escalations:', error);
    res.status(500).json({ error: 'Failed to get pending escalations' });
  }
});

// =====================================================
// STREAK MULTIPLIER ROUTES (Lucky Drops Enhancement)
// =====================================================

router.get('/users/:userId/streak', async (req, res) => {
  try {
    const streak = await opsStreakMultiplierService.getUserStreakBonus(req.params.userId);
    const penalty = await opsOverweightService.getUserPenalty(req.params.userId);
    
    const netBonus = Math.max(0, streak.bonusPercent - penalty.penaltyPercent);
    
    res.json({
      streak: streak.streak,
      streakBonusPercent: streak.bonusPercent,
      penaltyPercent: penalty.penaltyPercent,
      penaltyVisitsRemaining: penalty.visitsRemaining,
      netLuckyDropsModifier: netBonus,
      message: penalty.penaltyPercent > 0 
        ? `Lucky Drops: +${streak.bonusPercent}% streak bonus, -${penalty.penaltyPercent}% penalty = ${netBonus >= 0 ? '+' : ''}${netBonus}% net`
        : `Lucky Drops: +${streak.bonusPercent}% streak bonus`
    });
  } catch (error) {
    console.error('Error getting user streak:', error);
    res.status(500).json({ error: 'Failed to get user streak' });
  }
});

router.post('/packing-logs/:packingLogId/kit-scan', async (req, res) => {
  try {
    const { kitType } = req.body;
    if (!['C', 'D'].includes(kitType?.toUpperCase())) {
      return res.status(400).json({ error: 'kitType must be C or D' });
    }
    await opsPackingLogsService.recordKitScan(req.params.packingLogId, kitType.toUpperCase());
    res.json({ success: true, message: `KIT ${kitType.toUpperCase()} scan recorded` });
  } catch (error) {
    console.error('Error recording kit scan:', error);
    res.status(500).json({ error: 'Failed to record kit scan' });
  }
});

// =====================================================
// PHOTO GUARDRAILS ROUTES
// =====================================================

router.post('/photos/validate', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'unknown';
    const userName = req.headers['x-user-name'] || 'Unknown';
    const { sizeBytes, hasGpsMetadata, hasTimestamp, requiresGps, requiresTimestamp, context, entityId } = req.body;
    
    const validation = opsPhotoGuardrailsService.validatePhoto({
      sizeBytes, hasGpsMetadata, hasTimestamp, requiresGps, requiresTimestamp
    });
    
    if (!validation.valid) {
      await opsPhotoGuardrailsService.logRejection(userId, userName, { type: context, entityId }, validation.errors);
      return res.status(400).json({
        valid: false,
        rejected: true,
        errors: validation.errors,
        message: 'Photo does not meet proof-of-work requirements. Please retake.'
      });
    }
    
    res.json({ valid: true, validated: true, message: 'Photo meets all requirements' });
  } catch (error) {
    console.error('Error validating photo:', error);
    res.status(500).json({ error: 'Failed to validate photo' });
  }
});

// =====================================================
// FLEET INTEGRITY SCORE ROUTES
// =====================================================

router.get('/fleet/integrity-score', async (req, res) => {
  try {
    const score = await opsFleetIntegrityService.calculateScore();
    res.json(score);
  } catch (error) {
    console.error('Error calculating fleet integrity score:', error);
    res.status(500).json({ error: 'Failed to calculate fleet integrity score' });
  }
});

router.get('/sites/:siteId/integrity-score', async (req, res) => {
  try {
    const score = await opsFleetIntegrityService.getSiteScore(req.params.siteId);
    res.json(score);
  } catch (error) {
    console.error('Error calculating site integrity score:', error);
    res.status(500).json({ error: 'Failed to calculate site integrity score' });
  }
});

// =====================================================
// VERIFICATION LOCK ROUTES
// =====================================================

router.get('/tasks/:taskId/verification-status', async (req, res) => {
  try {
    const { visitType } = req.query;
    const status = await opsVerificationLockService.canCloseVisit(req.params.taskId, visitType);
    res.json(status);
  } catch (error) {
    console.error('Error checking verification status:', error);
    res.status(500).json({ error: 'Failed to check verification status' });
  }
});

router.post('/tasks/:taskId/verify-close', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'system';
    const { visitType } = req.body;
    
    const canClose = await opsVerificationLockService.canCloseVisit(req.params.taskId, visitType);
    
    if (!canClose.canClose) {
      return res.status(403).json({
        blocked: true,
        ...canClose
      });
    }
    
    await opsVerificationLockService.markVerified(req.params.taskId, userId);
    res.json({ verified: true, message: 'Visit verified and can be closed' });
  } catch (error) {
    console.error('Error verifying task closure:', error);
    res.status(500).json({ error: 'Failed to verify task closure' });
  }
});

// =====================================================
// BUILDING COMMAND DASHBOARD ROUTES (Read-Only)
// =====================================================

router.get('/building-command/:siteId', async (req, res) => {
  try {
    const data = await opsBuildingCommandService.getDashboardData(req.params.siteId);
    
    if (data.error) {
      return res.status(404).json({ error: data.error });
    }
    
    res.json({
      dashboard: data,
      readOnly: true,
      disclaimer: 'This is a read-only view for building management. Contact JOLT Operations for support.'
    });
  } catch (error) {
    console.error('Error fetching building command dashboard:', error);
    res.status(500).json({ error: 'Failed to fetch building command dashboard' });
  }
});

// =====================================================
// PHASE 3: SHIPPING HARDENING ROUTES
// =====================================================

// --- QC GATE EVENTS ---

router.post('/boxes/:boxRecordId/qc-gate', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    const { gateType, passFail, measuredValue, notes, photoId } = req.body;
    
    if (!gateType || !passFail) {
      return res.status(400).json({ error: 'gateType and passFail are required' });
    }
    
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    const shipment = await opsShipmentsService.getById(box.shipment_id);
    
    const event = await qcGateEventsService.record({
      tenantId: shipment?.tenant_id || 'JOLT_INTERNAL',
      siteId: box.site_id,
      shipmentId: box.shipment_id,
      boxId: box.box_id,
      boxRecordId: req.params.boxRecordId,
      gateType,
      passFail,
      measuredValue,
      notes,
      actorUserId: userId,
      actorUserName: userName,
      photoId
    });
    
    res.json({ event, message: 'QC gate recorded' });
  } catch (error) {
    console.error('Error recording QC gate:', error);
    res.status(500).json({ error: 'Failed to record QC gate' });
  }
});

router.get('/boxes/:boxRecordId/qc-gates', async (req, res) => {
  try {
    const events = await qcGateEventsService.getByBoxRecordId(req.params.boxRecordId);
    const summary = await qcGateEventsService.getQCSummary(req.params.boxRecordId);
    res.json({ events, summary });
  } catch (error) {
    console.error('Error fetching QC gates:', error);
    res.status(500).json({ error: 'Failed to fetch QC gates' });
  }
});

// --- BOX CONTENTS SNAPSHOT ---

router.post('/boxes/:boxRecordId/contents', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { items } = req.body;
    
    if (!items || !Array.isArray(items)) {
      return res.status(400).json({ error: 'items array is required' });
    }
    
    const isLocked = await boxContentsSnapshotService.isLocked(req.params.boxRecordId);
    if (isLocked) {
      return res.status(403).json({ error: 'Box contents are locked (label already generated). Use correction events.' });
    }
    
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    const shipment = await opsShipmentsService.getById(box.shipment_id);
    
    const snapshots = await boxContentsSnapshotService.bulkCreate(
      items, req.params.boxRecordId, box.shipment_id,
      shipment?.tenant_id || 'JOLT_INTERNAL', box.site_id, userId
    );
    
    res.json({ snapshots, message: 'Box contents recorded' });
  } catch (error) {
    console.error('Error recording box contents:', error);
    res.status(500).json({ error: 'Failed to record box contents' });
  }
});

router.get('/boxes/:boxRecordId/contents', async (req, res) => {
  try {
    const contents = await boxContentsSnapshotService.getByBoxRecordId(req.params.boxRecordId);
    const isLocked = await boxContentsSnapshotService.isLocked(req.params.boxRecordId);
    res.json({ contents, isLocked });
  } catch (error) {
    console.error('Error fetching box contents:', error);
    res.status(500).json({ error: 'Failed to fetch box contents' });
  }
});

// --- BOX MANIFEST ---

router.get('/boxes/:boxRecordId/manifest', async (req, res) => {
  try {
    const manifest = await manifestService.generateBoxManifest(req.params.boxRecordId);
    if (!manifest) {
      return res.status(404).json({ error: 'Box not found' });
    }
    res.json({ manifest });
  } catch (error) {
    console.error('Error generating box manifest:', error);
    res.status(500).json({ error: 'Failed to generate box manifest' });
  }
});

router.get('/shipments/:shipmentId/manifest', async (req, res) => {
  try {
    const manifest = await manifestService.generateShipmentManifest(req.params.shipmentId);
    if (!manifest) {
      return res.status(404).json({ error: 'Shipment not found' });
    }
    res.json({ manifest });
  } catch (error) {
    console.error('Error generating shipment manifest:', error);
    res.status(500).json({ error: 'Failed to generate shipment manifest' });
  }
});

// --- LABEL LOCK (freeze contents) ---

router.post('/boxes/:boxRecordId/lock-label', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userName = req.headers['x-user-name'] || 'Ops Manager';
    
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    const allPassed = await qcGateEventsService.allGatesPassed(req.params.boxRecordId);
    if (!allPassed) {
      return res.status(403).json({ error: 'All required QC gates must pass before label lock' });
    }
    
    const pool = (await import('./db.js')).getPool();
    await pool.query(
      `UPDATE ops_shipment_boxes SET 
        contents_locked_at = NOW(), 
        label_generated_at = NOW(),
        status = 'labeled'
       WHERE box_record_id = $1`,
      [req.params.boxRecordId]
    );
    
    await opsAuditLogService.log(userId, userName, 'label_locked', 'box', req.params.boxRecordId, {
      shipmentId: box.shipment_id, siteId: box.site_id
    });
    
    res.json({ message: 'Label locked, contents frozen', boxRecordId: req.params.boxRecordId });
  } catch (error) {
    console.error('Error locking label:', error);
    res.status(500).json({ error: 'Failed to lock label' });
  }
});

// --- DRIVER BOX SCAN CUSTODY ---

router.post('/deliveries/:deliveryId/scan-box', requireRole('driver', 'ops_manager'), async (req, res) => {
  try {
    const driverId = req.headers['x-user-id'];
    const driverName = req.headers['x-user-name'] || 'Driver';
    const { boxRecordId, gpsLatitude, gpsLongitude, clientTimestamp } = req.body;
    
    if (!boxRecordId) {
      return res.status(400).json({ error: 'boxRecordId is required' });
    }
    
    const delivery = await opsDeliveryRecordsService.getByDeliveryId(req.params.deliveryId);
    if (!delivery) {
      return res.status(404).json({ error: 'Delivery not found' });
    }
    
    const box = await opsShipmentBoxesService.getByBoxRecordId(boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    if (box.shipment_id !== delivery.shipment_id) {
      return res.status(400).json({ error: 'Box does not belong to this shipment' });
    }
    
    const shipment = await opsShipmentsService.getById(delivery.shipment_id);
    
    const scan = await boxScanCustodyService.recordScan({
      tenantId: shipment?.tenant_id || 'JOLT_INTERNAL',
      siteId: delivery.site_id,
      shipmentId: delivery.shipment_id,
      boxRecordId,
      deliveryId: req.params.deliveryId,
      driverId,
      driverName,
      scanType: 'delivery',
      gpsLatitude,
      gpsLongitude,
      clientTimestamp
    });
    
    res.json({ scan, message: 'Box scanned for delivery' });
  } catch (error) {
    console.error('Error scanning box:', error);
    res.status(500).json({ error: 'Failed to scan box' });
  }
});

router.get('/deliveries/:deliveryId/scanned-boxes', async (req, res) => {
  try {
    const scans = await boxScanCustodyService.getByDeliveryId(req.params.deliveryId);
    const delivery = await opsDeliveryRecordsService.getByDeliveryId(req.params.deliveryId);
    
    if (!delivery) {
      return res.status(404).json({ error: 'Delivery not found' });
    }
    
    const verification = await boxScanCustodyService.verifyAllBoxesScanned(
      delivery.shipment_id, req.params.deliveryId
    );
    
    res.json({ scans, verification });
  } catch (error) {
    console.error('Error fetching scanned boxes:', error);
    res.status(500).json({ error: 'Failed to fetch scanned boxes' });
  }
});

// --- PER-BOX ACCEPT/REFUSE ---

router.post('/boxes/:boxRecordId/accept', requireRole('partner', 'technician', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userName = req.headers['x-user-name'] || 'Partner';
    
    const pool = (await import('./db.js')).getPool();
    await pool.query(
      `UPDATE ops_shipment_boxes SET 
        partner_accepted = TRUE, 
        partner_accepted_at = NOW(),
        partner_accepted_by = $2
       WHERE box_record_id = $1`,
      [req.params.boxRecordId, userId]
    );
    
    await opsAuditLogService.log(userId, userName, 'box_accepted', 'box', req.params.boxRecordId, {});
    
    res.json({ message: 'Box accepted', boxRecordId: req.params.boxRecordId });
  } catch (error) {
    console.error('Error accepting box:', error);
    res.status(500).json({ error: 'Failed to accept box' });
  }
});

router.post('/boxes/:boxRecordId/refuse', requireRole('partner', 'technician', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userName = req.headers['x-user-name'] || 'Partner';
    const { reason, photo, notes } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Reason is required' });
    }
    if (!photo) {
      return res.status(400).json({ error: 'Photo is required' });
    }
    
    const box = await opsShipmentBoxesService.getByBoxRecordId(req.params.boxRecordId);
    if (!box) {
      return res.status(404).json({ error: 'Box not found' });
    }
    
    const pool = (await import('./db.js')).getPool();
    await pool.query(
      `UPDATE ops_shipment_boxes SET 
        partner_refused = TRUE, 
        refusal_reason = $2,
        refusal_photo = $3,
        refusal_notes = $4
       WHERE box_record_id = $1`,
      [req.params.boxRecordId, reason, photo, notes]
    );
    
    const shipment = await opsShipmentsService.getById(box.shipment_id);
    const tenantId = shipment?.tenant_id || 'JOLT_INTERNAL';
    
    const incident = await opsIncidentsService.create({
      siteId: box.site_id,
      type: reason,
      severity: reason === 'wet_leak' ? 'critical' : 'high',
      title: `Box Refused: ${reason.replace(/_/g, ' ').toUpperCase()} - Box ${box.box_id}`,
      description: notes || `Partner refused box with reason: ${reason}`,
      photos: [photo],
      relatedShipmentId: box.shipment_id,
      autoCreated: true
    });
    
    await playbookTasksService.createFromIncident(
      incident.incident_id, reason, tenantId, box.site_id
    );
    
    await opsAuditLogService.log(userId, userName, 'box_refused', 'box', req.params.boxRecordId, { reason, notes });
    
    res.json({ message: 'Box refused, incident and playbook tasks created', boxRecordId: req.params.boxRecordId, incidentId: incident.incident_id });
  } catch (error) {
    console.error('Error refusing box:', error);
    res.status(500).json({ error: 'Failed to refuse box' });
  }
});

// --- ZONE PAR TARGETS ---

router.get('/sites/:siteId/par-targets', async (req, res) => {
  try {
    const parTargets = await zoneParTargetsService.getBySiteId(req.params.siteId);
    res.json({ parTargets });
  } catch (error) {
    console.error('Error fetching PAR targets:', error);
    res.status(500).json({ error: 'Failed to fetch PAR targets' });
  }
});

router.post('/sites/:siteId/par-targets', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { zone, sku, itemName, unit, minQty, targetQty, reorderPoint } = req.body;
    
    if (!zone || !sku || !minQty || !targetQty) {
      return res.status(400).json({ error: 'zone, sku, minQty, and targetQty are required' });
    }
    
    const site = await opsSitesService.getBySiteId(req.params.siteId);
    if (!site) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const parTarget = await zoneParTargetsService.create({
      tenantId: site.tenant_id || 'JOLT_INTERNAL',
      siteId: req.params.siteId,
      zone, sku, itemName, unit, minQty, targetQty, reorderPoint,
      createdBy: userId
    });
    
    res.json({ parTarget, message: 'PAR target created' });
  } catch (error) {
    console.error('Error creating PAR target:', error);
    res.status(500).json({ error: 'Failed to create PAR target' });
  }
});

router.post('/sites/:siteId/calculate-deltas', async (req, res) => {
  try {
    const { currentCounts } = req.body;
    
    if (!currentCounts) {
      return res.status(400).json({ error: 'currentCounts object is required' });
    }
    
    const deltas = await zoneParTargetsService.calculateDeltas(req.params.siteId, currentCounts);
    res.json({ deltas });
  } catch (error) {
    console.error('Error calculating deltas:', error);
    res.status(500).json({ error: 'Failed to calculate deltas' });
  }
});

// --- REFILL COUNTS ---

router.post('/sites/:siteId/refill-counts', requireRole('partner', 'technician', 'ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { submissionId, counts } = req.body;
    
    if (!counts || !Array.isArray(counts)) {
      return res.status(400).json({ error: 'counts array is required' });
    }
    
    const site = await opsSitesService.getBySiteId(req.params.siteId);
    if (!site) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const recorded = [];
    for (const count of counts) {
      const result = await refillCountsService.record({
        tenantId: site.tenant_id || 'JOLT_INTERNAL',
        siteId: req.params.siteId,
        submissionId,
        zone: count.zone,
        sku: count.sku,
        itemName: count.itemName,
        countBefore: count.countBefore,
        countAfter: count.countAfter,
        parTargetQty: count.parTargetQty,
        countedBy: userId,
        photoProof: count.photoProof
      });
      recorded.push(result);
    }
    
    res.json({ counts: recorded, message: 'Refill counts recorded' });
  } catch (error) {
    console.error('Error recording refill counts:', error);
    res.status(500).json({ error: 'Failed to record refill counts' });
  }
});

router.get('/sites/:siteId/refill-counts', async (req, res) => {
  try {
    const latest = await refillCountsService.getLatestBySite(req.params.siteId);
    const consumption = await refillCountsService.getConsumptionHistory(req.params.siteId, 30);
    res.json({ latestCounts: latest, consumptionHistory: consumption });
  } catch (error) {
    console.error('Error fetching refill counts:', error);
    res.status(500).json({ error: 'Failed to fetch refill counts' });
  }
});

// --- SHIPMENT PROPOSALS ---

router.get('/shipment-proposals', requireRole('ops_manager'), async (req, res) => {
  try {
    const { tenantId } = req.query;
    const proposals = await shipmentProposalsService.getPending(tenantId);
    res.json({ proposals });
  } catch (error) {
    console.error('Error fetching shipment proposals:', error);
    res.status(500).json({ error: 'Failed to fetch shipment proposals' });
  }
});

router.post('/sites/:siteId/generate-proposal', requireRole('ops_manager'), async (req, res) => {
  try {
    const site = await opsSitesService.getBySiteId(req.params.siteId);
    if (!site) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const proposal = await shipmentProposalsService.generateFromConsumption(
      req.params.siteId, site.tenant_id || 'JOLT_INTERNAL'
    );
    
    if (!proposal) {
      return res.json({ message: 'No replenishment needed at this time', proposal: null });
    }
    
    res.json({ proposal, message: 'Shipment proposal generated' });
  } catch (error) {
    console.error('Error generating shipment proposal:', error);
    res.status(500).json({ error: 'Failed to generate shipment proposal' });
  }
});

router.post('/shipment-proposals/:proposalId/approve', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const proposal = await shipmentProposalsService.approve(req.params.proposalId, userId);
    res.json({ proposal, message: 'Proposal approved' });
  } catch (error) {
    console.error('Error approving proposal:', error);
    res.status(500).json({ error: 'Failed to approve proposal' });
  }
});

// --- PLAYBOOK TASKS ---

router.get('/incidents/:incidentId/playbook-tasks', async (req, res) => {
  try {
    const tasks = await playbookTasksService.getByIncidentId(req.params.incidentId);
    res.json({ tasks });
  } catch (error) {
    console.error('Error fetching playbook tasks:', error);
    res.status(500).json({ error: 'Failed to fetch playbook tasks' });
  }
});

router.get('/sites/:siteId/playbook-tasks', async (req, res) => {
  try {
    const tasks = await playbookTasksService.getPendingBySite(req.params.siteId);
    res.json({ tasks });
  } catch (error) {
    console.error('Error fetching playbook tasks:', error);
    res.status(500).json({ error: 'Failed to fetch playbook tasks' });
  }
});

router.post('/playbook-tasks/:taskId/complete', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { completionNotes } = req.body;
    
    const task = await playbookTasksService.complete(req.params.taskId, userId, completionNotes);
    res.json({ task, message: 'Playbook task completed' });
  } catch (error) {
    console.error('Error completing playbook task:', error);
    res.status(500).json({ error: 'Failed to complete playbook task' });
  }
});

// --- ACCEPTANCE WINDOW ESCALATION ---

router.post('/check-acceptance-windows', requireRole('ops_manager'), async (req, res) => {
  try {
    const escalated = await acceptanceWindowService.checkAndEscalate();
    res.json({ escalated, message: `${escalated.length} deliveries escalated` });
  } catch (error) {
    console.error('Error checking acceptance windows:', error);
    res.status(500).json({ error: 'Failed to check acceptance windows' });
  }
});

// --- EVIDENCE PACKETS ---

router.post('/evidence-packets/generate', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { entityType, entityId } = req.body;
    
    if (!entityType || !entityId) {
      return res.status(400).json({ error: 'entityType and entityId are required' });
    }
    
    const packet = await evidencePacketService.generate(entityType, entityId, userId);
    
    if (!packet) {
      return res.status(404).json({ error: 'Entity not found' });
    }
    
    res.json({ packet, message: 'Evidence packet generated' });
  } catch (error) {
    console.error('Error generating evidence packet:', error);
    res.status(500).json({ error: 'Failed to generate evidence packet' });
  }
});

router.get('/evidence-packets/:entityType/:entityId', async (req, res) => {
  try {
    const packets = await evidencePacketService.getByEntityId(
      req.params.entityType, req.params.entityId
    );
    res.json({ packets });
  } catch (error) {
    console.error('Error fetching evidence packets:', error);
    res.status(500).json({ error: 'Failed to fetch evidence packets' });
  }
});

// --- GOLDEN PHOTOS ---

router.get('/sites/:siteId/golden-photos', async (req, res) => {
  try {
    const photos = await goldenPhotosService.getBySiteId(req.params.siteId);
    res.json({ goldenPhotos: photos });
  } catch (error) {
    console.error('Error fetching golden photos:', error);
    res.status(500).json({ error: 'Failed to fetch golden photos' });
  }
});

router.post('/sites/:siteId/golden-photos', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { zone, photoUrl, description } = req.body;
    
    if (!zone || !photoUrl) {
      return res.status(400).json({ error: 'zone and photoUrl are required' });
    }
    
    const site = await opsSitesService.getBySiteId(req.params.siteId);
    if (!site) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const photo = await goldenPhotosService.upload({
      tenantId: site.tenant_id || 'JOLT_INTERNAL',
      siteId: req.params.siteId,
      zone, photoUrl, description,
      uploadedBy: userId
    });
    
    res.json({ goldenPhoto: photo, message: 'Golden photo uploaded' });
  } catch (error) {
    console.error('Error uploading golden photo:', error);
    res.status(500).json({ error: 'Failed to upload golden photo' });
  }
});

// =====================================================
// PHASE 4: PILOT READINESS + WEEKLY CADENCE + KPI ROUTES
// =====================================================

// --- GO-LIVE CERTIFICATE / ONBOARDING WIZARD ---

router.post('/onboarding/start', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { tenantId, siteId } = req.body;
    
    if (!tenantId || !siteId) {
      return res.status(400).json({ error: 'tenantId and siteId are required' });
    }
    
    const existing = await goLiveCertificateService.getBySiteId(siteId);
    if (existing && existing.status === 'live') {
      return res.status(400).json({ error: 'Site is already live' });
    }
    
    const certificate = await goLiveCertificateService.create(tenantId, siteId, userId);
    res.json({ certificate, message: 'Onboarding started' });
  } catch (error) {
    console.error('Error starting onboarding:', error);
    res.status(500).json({ error: 'Failed to start onboarding' });
  }
});

router.get('/onboarding/:certificateId', requireRole('ops_manager'), async (req, res) => {
  try {
    const certificate = await goLiveCertificateService.getById(req.params.certificateId);
    if (!certificate) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const dryRunStatus = await goLiveCertificateService.getDryRunStatus(req.params.certificateId);
    res.json({ certificate, dryRunStatus, requiredChecks: goLiveCertificateService.DRY_RUN_CHECKS });
  } catch (error) {
    console.error('Error fetching onboarding status:', error);
    res.status(500).json({ error: 'Failed to fetch onboarding status' });
  }
});

router.get('/sites/:siteId/onboarding', requireRole('ops_manager'), async (req, res) => {
  try {
    const certificate = await goLiveCertificateService.getBySiteId(req.params.siteId);
    if (!certificate) {
      return res.json({ certificate: null, message: 'No onboarding started for this site' });
    }
    
    const dryRunStatus = await goLiveCertificateService.getDryRunStatus(certificate.certificate_id);
    res.json({ certificate, dryRunStatus, requiredChecks: goLiveCertificateService.DRY_RUN_CHECKS });
  } catch (error) {
    console.error('Error fetching site onboarding:', error);
    res.status(500).json({ error: 'Failed to fetch site onboarding' });
  }
});

router.post('/onboarding/:certificateId/step', requireRole('ops_manager'), async (req, res) => {
  try {
    const { stepName, stepData } = req.body;
    
    if (!stepName) {
      return res.status(400).json({ error: 'stepName is required' });
    }
    
    const certificate = await goLiveCertificateService.updateOnboardingStep(
      req.params.certificateId, stepName, stepData || {}
    );
    
    res.json({ certificate, message: `Step ${stepName} updated` });
  } catch (error) {
    console.error('Error updating onboarding step:', error);
    res.status(500).json({ error: 'Failed to update onboarding step' });
  }
});

router.post('/onboarding/:certificateId/dry-run', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { checkType, passed, resultData } = req.body;
    
    if (!checkType || passed === undefined) {
      return res.status(400).json({ error: 'checkType and passed are required' });
    }
    
    const result = await goLiveCertificateService.recordDryRunCheck(
      req.params.certificateId, checkType, passed, resultData, userId
    );
    
    if (!result) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    res.json({ 
      result, 
      message: passed ? 'Check passed!' : 'Check failed - please retry',
      allChecksPassed: result.allPassed
    });
  } catch (error) {
    console.error('Error recording dry-run check:', error);
    res.status(500).json({ error: 'Failed to record dry-run check' });
  }
});

router.post('/onboarding/:certificateId/mark-live', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    
    const result = await goLiveCertificateService.markLive(req.params.certificateId, userId);
    
    if (result.error) {
      return res.status(400).json({ error: result.error });
    }
    
    res.json({ success: true, siteId: result.siteId, message: 'Site marked LIVE!' });
  } catch (error) {
    console.error('Error marking site live:', error);
    res.status(500).json({ error: 'Failed to mark site live' });
  }
});

router.post('/onboarding/:certificateId/update-zones', requireRole('ops_manager'), async (req, res) => {
  try {
    const { zonesConfigured, parTargetsCount } = req.body;
    
    await goLiveCertificateService.updateZonesAndPAR(
      req.params.certificateId, zonesConfigured || [], parTargetsCount || 0
    );
    
    res.json({ message: 'Zones and PAR targets updated' });
  } catch (error) {
    console.error('Error updating zones:', error);
    res.status(500).json({ error: 'Failed to update zones' });
  }
});

router.post('/onboarding/:certificateId/invite-user', requireRole('ops_manager'), async (req, res) => {
  try {
    const { userId: invitedUserId, role, name, email } = req.body;
    
    const users = await goLiveCertificateService.addInvitedUser(req.params.certificateId, {
      userId: invitedUserId, role, name, email
    });
    
    res.json({ users, message: 'User invitation recorded' });
  } catch (error) {
    console.error('Error inviting user:', error);
    res.status(500).json({ error: 'Failed to invite user' });
  }
});

// --- KPI SCOREBOARD ---

router.post('/sites/:siteId/compute-kpis', requireRole('ops_manager'), async (req, res) => {
  try {
    const { weekStart } = req.body;
    
    if (!weekStart) {
      return res.status(400).json({ error: 'weekStart date is required' });
    }
    
    const kpis = await kpiScoreboardService.computeWeeklyKPIs(req.params.siteId, weekStart);
    
    if (!kpis) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    res.json({ kpis, message: 'KPIs computed' });
  } catch (error) {
    console.error('Error computing KPIs:', error);
    res.status(500).json({ error: 'Failed to compute KPIs' });
  }
});

router.get('/sites/:siteId/kpi-snapshot', async (req, res) => {
  try {
    const { weekStart } = req.query;
    
    if (!weekStart) {
      return res.status(400).json({ error: 'weekStart query parameter is required' });
    }
    
    const snapshot = await kpiScoreboardService.getWeeklySnapshot(req.params.siteId, weekStart);
    res.json({ snapshot });
  } catch (error) {
    console.error('Error fetching KPI snapshot:', error);
    res.status(500).json({ error: 'Failed to fetch KPI snapshot' });
  }
});

router.get('/sites/:siteId/training-flags', requireRole('ops_manager'), async (req, res) => {
  try {
    const { acknowledged } = req.query;
    const flags = await kpiScoreboardService.getTrainingFlags(
      req.params.siteId, acknowledged === 'true'
    );
    res.json({ flags });
  } catch (error) {
    console.error('Error fetching training flags:', error);
    res.status(500).json({ error: 'Failed to fetch training flags' });
  }
});

router.post('/training-flags/:flagId/acknowledge', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    await kpiScoreboardService.acknowledgeFlag(req.params.flagId, userId);
    res.json({ message: 'Flag acknowledged' });
  } catch (error) {
    console.error('Error acknowledging flag:', error);
    res.status(500).json({ error: 'Failed to acknowledge flag' });
  }
});

// --- WEEKLY CADENCE ---

router.post('/weekly-cadence/generate', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { tenantId, weekStart } = req.body;
    
    if (!tenantId || !weekStart) {
      return res.status(400).json({ error: 'tenantId and weekStart are required' });
    }
    
    const plan = await weeklyCadenceService.generateWeeklyPlan(tenantId, weekStart, userId);
    res.json({ plan, message: 'Weekly plan generated' });
  } catch (error) {
    console.error('Error generating weekly plan:', error);
    res.status(500).json({ error: 'Failed to generate weekly plan' });
  }
});

router.get('/weekly-cadence/this-week', requireRole('ops_manager'), async (req, res) => {
  try {
    const { tenantId } = req.query;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'tenantId query parameter is required' });
    }
    
    const plan = await weeklyCadenceService.getThisWeekPlan(tenantId);
    
    if (!plan) {
      return res.json({ plan: null, message: 'No plan for this week. Generate one to get started.' });
    }
    
    const workItems = await weeklyCadenceService.getWorkItems(plan.plan_id);
    res.json({ plan, workItems });
  } catch (error) {
    console.error('Error fetching this week plan:', error);
    res.status(500).json({ error: 'Failed to fetch this week plan' });
  }
});

router.get('/weekly-cadence/:planId/work-items', requireRole('ops_manager'), async (req, res) => {
  try {
    const { itemType, status, siteId } = req.query;
    const workItems = await weeklyCadenceService.getWorkItems(req.params.planId, { itemType, status, siteId });
    res.json({ workItems });
  } catch (error) {
    console.error('Error fetching work items:', error);
    res.status(500).json({ error: 'Failed to fetch work items' });
  }
});

router.post('/weekly-cadence/work-items/:workItemId/complete', requireRole('ops_manager'), async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    await weeklyCadenceService.completeWorkItem(req.params.workItemId, userId);
    res.json({ message: 'Work item completed' });
  } catch (error) {
    console.error('Error completing work item:', error);
    res.status(500).json({ error: 'Failed to complete work item' });
  }
});

router.get('/weekly-cadence/exceptions', requireRole('ops_manager'), async (req, res) => {
  try {
    const { tenantId } = req.query;
    
    if (!tenantId) {
      return res.status(400).json({ error: 'tenantId query parameter is required' });
    }
    
    const exceptions = await weeklyCadenceService.getExceptionsQueue(tenantId);
    res.json({ exceptions });
  } catch (error) {
    console.error('Error fetching exceptions:', error);
    res.status(500).json({ error: 'Failed to fetch exceptions' });
  }
});

// --- LANDLORD TRUST REPORTING ---

router.post('/sites/:siteId/generate-digest', requireRole('ops_manager'), async (req, res) => {
  try {
    const { weekStart } = req.body;
    
    if (!weekStart) {
      return res.status(400).json({ error: 'weekStart is required' });
    }
    
    const digest = await landlordDigestService.generateDigest(req.params.siteId, weekStart);
    
    if (!digest) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    res.json({ digest, message: 'Landlord digest generated' });
  } catch (error) {
    console.error('Error generating landlord digest:', error);
    res.status(500).json({ error: 'Failed to generate landlord digest' });
  }
});

router.get('/landlord/sites/:siteId/digest', async (req, res) => {
  try {
    const userRole = req.headers['x-user-role'] || 'partner';
    const { weekStart } = req.query;
    
    if (!weekStart) {
      const digests = await landlordDigestService.getRecentDigests(req.params.siteId, 4);
      return res.json({ 
        digests, 
        readOnly: true,
        disclaimer: 'This is a read-only summary for building management.'
      });
    }
    
    const digest = await landlordDigestService.getDigest(req.params.siteId, weekStart);
    
    if (!digest) {
      return res.status(404).json({ error: 'Digest not found for this week' });
    }
    
    res.json({ 
      digest, 
      readOnly: true,
      disclaimer: 'This is a read-only summary for building management.'
    });
  } catch (error) {
    console.error('Error fetching landlord digest:', error);
    res.status(500).json({ error: 'Failed to fetch landlord digest' });
  }
});

router.get('/landlord/sites/:siteId/weekly-summary', async (req, res) => {
  try {
    const today = new Date();
    const dayOfWeek = today.getDay();
    const weekStart = new Date(today);
    weekStart.setDate(today.getDate() - dayOfWeek);
    weekStart.setHours(0, 0, 0, 0);
    
    let digest = await landlordDigestService.getDigest(req.params.siteId, weekStart.toISOString().split('T')[0]);
    
    if (!digest) {
      digest = await landlordDigestService.generateDigest(req.params.siteId, weekStart.toISOString().split('T')[0]);
    }
    
    if (!digest) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    res.json({
      siteId: req.params.siteId,
      siteName: digest.siteName || digest.site_name,
      weekOf: weekStart.toISOString().split('T')[0],
      summary: {
        maintenanceVisits: {
          completed: digest.refills?.completed || digest.refills_completed || 0,
          overdue: digest.refills?.overdue || digest.refills_overdue || 0,
          status: (digest.refills?.overdue || digest.refills_overdue || 0) > 0 ? 'attention' : 'good'
        },
        supplyDeliveries: {
          accepted: digest.deliveries?.accepted || digest.deliveries_accepted || 0,
          pending: digest.deliveries?.pending || digest.deliveries_pending || 0,
          status: (digest.deliveries?.pending || digest.deliveries_pending || 0) > 0 ? 'pending' : 'good'
        },
        openIssues: digest.incidents?.open || digest.open_incidents || 0,
        complianceStreak: digest.complianceStreak || digest.compliance_streak || 0,
        overallStatus: digest.overallStatus || digest.overall_status || 'good'
      },
      textSummary: digest.summary || digest.digest_summary || 'Your machine is operating normally.',
      definitions: digest.definitions || landlordDigestService.getDefinitions(),
      readOnly: true,
      generatedAt: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching landlord weekly summary:', error);
    res.status(500).json({ error: 'Failed to fetch weekly summary' });
  }
});

export default router;
