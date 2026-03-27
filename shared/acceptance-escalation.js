import { getPool } from './db.js';

const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

const REFUSAL_PLAYBOOKS = {
  wet_leak: {
    incidentType: 'wet_leak',
    severity: 'critical',
    tasks: [
      { type: 'reship', title: 'Expedite replacement shipment', dueHours: 24 },
      { type: 'hub_audit', title: 'Review hub packing procedures', dueHours: 48 },
      { type: 'claim_evidence', title: 'Collect claim evidence packet', dueHours: 72 }
    ]
  },
  missing_box: {
    incidentType: 'missing_box',
    severity: 'high',
    tasks: [
      { type: 'reconcile', title: 'Reconcile expected vs received boxes', dueHours: 24 },
      { type: 'driver_review', title: 'Review driver scan history', dueHours: 24 },
      { type: 'carrier_tracking', title: 'Check carrier tracking status', dueHours: 48 }
    ]
  },
  wrong_items: {
    incidentType: 'item_mismatch',
    severity: 'high',
    tasks: [
      { type: 'manifest_review', title: 'Compare manifest vs received items', dueHours: 24 },
      { type: 'site_validation', title: 'Validate tenant/site assignment', dueHours: 24 }
    ]
  },
  damaged_packaging: {
    incidentType: 'damaged_packaging',
    severity: 'medium',
    tasks: [
      { type: 'evidence_packet', title: 'Generate damage evidence packet', dueHours: 24 },
      { type: 'carrier_claim', title: 'File carrier damage claim', dueHours: 72 }
    ]
  }
};

export const acceptanceEscalationService = {
  DEFAULT_WINDOW_HOURS: 24,
  
  async getAcceptanceWindow(siteId) {
    const pool = getPool();
    try {
      const result = await pool.query(
        `SELECT acceptance_window_hours FROM ops_site_configs WHERE site_id = $1`,
        [siteId]
      );
      return result.rows[0]?.acceptance_window_hours || this.DEFAULT_WINDOW_HOURS;
    } catch (e) {
      return this.DEFAULT_WINDOW_HOURS;
    }
  },
  
  async findOverdueDeliveries() {
    const pool = getPool();
    
    const result = await pool.query(`
      SELECT 
        dr.delivery_record_id, dr.shipment_id, dr.site_id, dr.created_at as pod_time,
        s.tenant_id, s.venue_name,
        COALESCE(sc.acceptance_window_hours, $1) as window_hours,
        EXTRACT(EPOCH FROM (NOW() - dr.created_at)) / 3600 as hours_elapsed
      FROM ops_delivery_records dr
      JOIN ops_shipments sh ON dr.shipment_id = sh.shipment_id
      JOIN ops_sites s ON dr.site_id = s.site_id
      LEFT JOIN ops_site_configs sc ON dr.site_id = sc.site_id
      WHERE dr.status = 'delivered'
        AND dr.accepted_at IS NULL
        AND dr.access_denied = FALSE
        AND EXTRACT(EPOCH FROM (NOW() - dr.created_at)) / 3600 > COALESCE(sc.acceptance_window_hours, $1)
        AND NOT EXISTS (
          SELECT 1 FROM ops_incidents i 
          WHERE i.type = 'acceptance_overdue'
          AND i.linked_entity_id = dr.delivery_record_id
          AND i.created_at > NOW() - INTERVAL '7 days'
        )
    `, [this.DEFAULT_WINDOW_HOURS]);
    
    return result.rows;
  },
  
  async createEscalation(delivery) {
    const pool = getPool();
    const incidentId = generateId('INC');
    
    await pool.query(`
      INSERT INTO ops_incidents (
        incident_id, tenant_id, site_id, type, severity, title, description,
        status, sla_due_at, linked_entity_type, linked_entity_id, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
    `, [
      incidentId,
      delivery.tenant_id,
      delivery.site_id,
      'acceptance_overdue',
      'high',
      `Delivery awaiting acceptance: ${delivery.venue_name}`,
      `POD submitted ${Math.round(delivery.hours_elapsed)} hours ago. Acceptance window of ${delivery.window_hours}h exceeded.`,
      'open',
      new Date(Date.now() + 24 * 60 * 60 * 1000),
      'delivery_record',
      delivery.delivery_record_id
    ]);
    
    const tasks = [
      { title: 'Contact partner to confirm receipt', dueHours: 4 },
      { title: 'Verify delivery was successful', dueHours: 8 },
      { title: 'Follow-up call if no response', dueHours: 24 }
    ];
    
    for (const task of tasks) {
      const taskId = generateId('TASK');
      await pool.query(`
        INSERT INTO ops_weekly_tasks (
          task_id, site_id, task_type, status, due_date,
          title, linked_incident_id, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT DO NOTHING
      `, [
        taskId,
        delivery.site_id,
        'escalation',
        'pending',
        new Date(Date.now() + task.dueHours * 60 * 60 * 1000),
        task.title,
        incidentId
      ]);
    }
    
    return { incidentId, tasksCreated: tasks.length };
  },
  
  async runEscalationCheck() {
    const overdueDeliveries = await this.findOverdueDeliveries();
    const results = [];
    
    for (const delivery of overdueDeliveries) {
      try {
        const result = await this.createEscalation(delivery);
        results.push({ ...delivery, ...result, success: true });
      } catch (e) {
        results.push({ ...delivery, success: false, error: e.message });
      }
    }
    
    return {
      checkedAt: new Date(),
      overdueCount: overdueDeliveries.length,
      escalationsCreated: results.filter(r => r.success).length,
      results
    };
  }
};

export const refusalPlaybookService = {
  async executePlaybook(refusalData) {
    const { siteId, tenantId, shipmentId, boxId, refusalReason, refusedBy, refusalPhoto } = refusalData;
    const pool = getPool();
    
    const playbook = REFUSAL_PLAYBOOKS[refusalReason];
    if (!playbook) {
      console.log(`[Playbook] No playbook for reason: ${refusalReason}`);
      return { success: false, reason: 'no_playbook_defined' };
    }
    
    const incidentId = generateId('INC');
    
    await pool.query(`
      INSERT INTO ops_incidents (
        incident_id, tenant_id, site_id, type, severity, title, description,
        status, sla_due_at, linked_entity_type, linked_entity_id, photos,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
    `, [
      incidentId,
      tenantId,
      siteId,
      playbook.incidentType,
      playbook.severity,
      `${playbook.incidentType.replace('_', ' ').toUpperCase()}: Box ${boxId} refused`,
      `Shipment ${shipmentId} box refused. Reason: ${refusalReason}. Refused by: ${refusedBy}.`,
      'open',
      new Date(Date.now() + 24 * 60 * 60 * 1000),
      'shipment_box',
      boxId,
      JSON.stringify(refusalPhoto ? [refusalPhoto] : [])
    ]);
    
    const createdTasks = [];
    for (const taskDef of playbook.tasks) {
      const taskId = generateId('TASK');
      await pool.query(`
        INSERT INTO ops_weekly_tasks (
          task_id, site_id, task_type, status, due_date,
          title, linked_incident_id, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT DO NOTHING
      `, [
        taskId,
        siteId,
        taskDef.type,
        'pending',
        new Date(Date.now() + taskDef.dueHours * 60 * 60 * 1000),
        taskDef.title,
        incidentId
      ]);
      createdTasks.push({ taskId, ...taskDef });
    }
    
    return {
      success: true,
      incidentId,
      playbook: playbook.incidentType,
      tasksCreated: createdTasks.length,
      tasks: createdTasks
    };
  }
};

export const custodyScanService = {
  async recordScan(scanData) {
    const { shipmentId, boxId, scannedBy, gpsLat, gpsLng, scanType } = scanData;
    const pool = getPool();
    
    const scanId = generateId('SCAN');
    
    await pool.query(`
      INSERT INTO box_scan_custody (
        scan_id, shipment_id, box_id, scanned_by, scan_type,
        gps_lat, gps_lng, scanned_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
    `, [scanId, shipmentId, boxId, scannedBy, scanType, gpsLat, gpsLng]);
    
    return { scanId };
  },
  
  async getExpectedBoxes(shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT box_record_id, box_id, box_sequence, status
       FROM ops_shipment_boxes
       WHERE shipment_id = $1
       ORDER BY box_sequence`,
      [shipmentId]
    );
    return result.rows;
  },
  
  async getScannedBoxes(shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT DISTINCT box_id FROM box_scan_custody
       WHERE shipment_id = $1`,
      [shipmentId]
    );
    return result.rows.map(r => r.box_id);
  },
  
  async validatePODComplete(shipmentId) {
    const expectedBoxes = await this.getExpectedBoxes(shipmentId);
    const scannedBoxes = await this.getScannedBoxes(shipmentId);
    
    const scannedSet = new Set(scannedBoxes);
    const missingScans = expectedBoxes.filter(b => !scannedSet.has(b.box_id));
    
    return {
      complete: missingScans.length === 0,
      expectedCount: expectedBoxes.length,
      scannedCount: scannedBoxes.length,
      missingScans: missingScans.map(b => b.box_id)
    };
  },
  
  async createMissingScanIncident(shipmentId, siteId, tenantId, missingBoxes) {
    const pool = getPool();
    const incidentId = generateId('INC');
    
    await pool.query(`
      INSERT INTO ops_incidents (
        incident_id, tenant_id, site_id, type, severity, title, description,
        status, linked_entity_type, linked_entity_id, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
    `, [
      incidentId,
      tenantId,
      siteId,
      'missing_scan',
      'high',
      `Missing custody scans: ${missingBoxes.length} boxes`,
      `Shipment ${shipmentId} POD completed without all box scans. Missing: ${missingBoxes.join(', ')}`,
      'open',
      'shipment',
      shipmentId
    ]);
    
    return incidentId;
  }
};
