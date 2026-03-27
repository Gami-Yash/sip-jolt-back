import { getPool } from '../db.js';

const generateId = (prefix) => `${prefix}-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

// =====================================================
// OPS USERS SERVICE
// =====================================================

export const opsUsersService = {
  async getByUserId(userId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_users WHERE user_id = $1',
      [userId]
    );
    return result.rows[0] || null;
  },

  async getByRole(role) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_users WHERE role = $1 AND is_active = TRUE ORDER BY name',
      [role]
    );
    return result.rows;
  },

  async create(data) {
    const pool = getPool();
    const userId = data.userId || generateId('USR');
    const result = await pool.query(
      `INSERT INTO ops_users (user_id, name, email, phone, role, assigned_sites)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [userId, data.name, data.email || null, data.phone || null, data.role || 'partner', JSON.stringify(data.assignedSites || [])]
    );
    return result.rows[0];
  },

  async update(userId, data) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_users SET
        name = COALESCE($2, name),
        email = COALESCE($3, email),
        phone = COALESCE($4, phone),
        role = COALESCE($5, role),
        assigned_sites = COALESCE($6, assigned_sites),
        is_active = COALESCE($7, is_active),
        updated_at = NOW()
       WHERE user_id = $1 RETURNING *`,
      [userId, data.name, data.email, data.phone, data.role, data.assignedSites ? JSON.stringify(data.assignedSites) : null, data.isActive]
    );
    return result.rows[0];
  },

  async updateLastLogin(userId) {
    const pool = getPool();
    await pool.query(
      'UPDATE ops_users SET last_login_at = NOW() WHERE user_id = $1',
      [userId]
    );
  }
};

// =====================================================
// SITES SERVICE
// =====================================================

export const opsSitesService = {
  async getAll() {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_sites ORDER BY venue_name'
    );
    return result.rows;
  },

  async getBySiteId(siteId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_sites WHERE site_id = $1',
      [siteId]
    );
    return result.rows[0] || null;
  },

  async getByStatus(status) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_sites WHERE status = $1 ORDER BY venue_name',
      [status]
    );
    return result.rows;
  },

  async create(data) {
    const pool = getPool();
    const siteId = data.siteId || generateId('SITE');
    const result = await pool.query(
      `INSERT INTO ops_sites (
        site_id, venue_name, address, primary_contact_name, primary_contact_phone,
        backup_contact_name, backup_contact_phone, closet_location, access_instructions, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        siteId, data.venueName, data.address,
        data.primaryContactName || null, data.primaryContactPhone || null,
        data.backupContactName || null, data.backupContactPhone || null,
        data.closetLocation || null, data.accessInstructions || null,
        data.status || 'pending_setup'
      ]
    );
    
    // Create default site config
    await pool.query(
      `INSERT INTO ops_site_configs (site_id) VALUES ($1) ON CONFLICT (site_id) DO NOTHING`,
      [siteId]
    );
    
    // Create default box configs
    const defaultBoxes = [
      { boxId: 'A', descriptor: 'LIQUIDS (SYRUP)' },
      { boxId: 'B1', descriptor: 'POWDERS (MATCHA MIX + DAIRY)' },
      { boxId: 'B2', descriptor: 'POWDERS (OAT)' },
      { boxId: 'CD', descriptor: 'OUTER BOX WITH TWO INNER KITS (KIT C + KIT D)' },
      { boxId: 'E', descriptor: 'CUPS ONLY' }
    ];
    
    for (const box of defaultBoxes) {
      await pool.query(
        `INSERT INTO ops_box_configs (site_id, box_id, descriptor) VALUES ($1, $2, $3)`,
        [siteId, box.boxId, box.descriptor]
      );
    }
    
    return result.rows[0];
  },

  async update(siteId, data) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_sites SET
        venue_name = COALESCE($2, venue_name),
        address = COALESCE($3, address),
        primary_contact_name = COALESCE($4, primary_contact_name),
        primary_contact_phone = COALESCE($5, primary_contact_phone),
        backup_contact_name = COALESCE($6, backup_contact_name),
        backup_contact_phone = COALESCE($7, backup_contact_phone),
        closet_location = COALESCE($8, closet_location),
        access_instructions = COALESCE($9, access_instructions),
        status = COALESCE($10, status),
        updated_at = NOW()
       WHERE site_id = $1 RETURNING *`,
      [
        siteId, data.venueName, data.address,
        data.primaryContactName, data.primaryContactPhone,
        data.backupContactName, data.backupContactPhone,
        data.closetLocation, data.accessInstructions, data.status
      ]
    );
    return result.rows[0];
  },

  async completeDay1(siteId, userId, goldenPhotos) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_sites SET
        status = 'ready',
        day1_completed_at = NOW(),
        day1_completed_by = $2,
        golden_photos = $3,
        updated_at = NOW()
       WHERE site_id = $1 RETURNING *`,
      [siteId, userId, JSON.stringify(goldenPhotos || [])]
    );
    return result.rows[0];
  },

  async getWithConfig(siteId) {
    const pool = getPool();
    const siteResult = await pool.query('SELECT * FROM ops_sites WHERE site_id = $1', [siteId]);
    if (!siteResult.rows[0]) return null;
    
    const configResult = await pool.query('SELECT * FROM ops_site_configs WHERE site_id = $1', [siteId]);
    const boxesResult = await pool.query('SELECT * FROM ops_box_configs WHERE site_id = $1 ORDER BY box_id', [siteId]);
    
    return {
      ...siteResult.rows[0],
      config: configResult.rows[0] || null,
      boxConfigs: boxesResult.rows
    };
  }
};

// =====================================================
// SITE CONFIG SERVICE
// =====================================================

export const opsSiteConfigService = {
  async getBySiteId(siteId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_site_configs WHERE site_id = $1',
      [siteId]
    );
    return result.rows[0] || null;
  },

  async update(siteId, data) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_site_configs SET
        weekly_due_day = COALESCE($2, weekly_due_day),
        weekly_due_hour = COALESCE($3, weekly_due_hour),
        overdue_threshold_hours = COALESCE($4, overdue_threshold_hours),
        skip_next_cups_drop = COALESCE($5, skip_next_cups_drop),
        skip_cups_reason = $6,
        skip_cups_expires_at = $7,
        zones_labeled = COALESCE($8, zones_labeled),
        thresholds = COALESCE($9, thresholds),
        updated_at = NOW()
       WHERE site_id = $1 RETURNING *`,
      [
        siteId, data.weeklyDueDay, data.weeklyDueHour,
        data.overdueThresholdHours, data.skipNextCupsDrop,
        data.skipCupsReason || null, data.skipCupsExpiresAt || null,
        data.zonesLabeled ? JSON.stringify(data.zonesLabeled) : null,
        data.thresholds ? JSON.stringify(data.thresholds) : null
      ]
    );
    return result.rows[0];
  },

  async setA50Fallback(siteId, active, reason = null) {
    const pool = getPool();
    if (active) {
      await pool.query(
        `UPDATE ops_site_configs SET
          a50_fallback_active = TRUE,
          a50_activated_at = NOW(),
          consecutive_soft_reports = 0,
          updated_at = NOW()
         WHERE site_id = $1`,
        [siteId]
      );
    } else {
      await pool.query(
        `UPDATE ops_site_configs SET
          a50_fallback_active = FALSE,
          a50_activated_at = NULL,
          consecutive_bricked_reports = 0,
          updated_at = NOW()
         WHERE site_id = $1`,
        [siteId]
      );
    }
  },

  async setCupsDropHold(siteId, active, reason = null) {
    const pool = getPool();
    await pool.query(
      `UPDATE ops_site_configs SET
        cups_drop_hold_active = $2,
        cups_drop_hold_reason = $3,
        updated_at = NOW()
       WHERE site_id = $1`,
      [siteId, active, reason]
    );
  },

  async getBoxConfig(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT ingredients_boxes_default, cups_box_default, box_a_split_enabled, box_a_count_default
       FROM ops_site_configs WHERE site_id = $1`,
      [siteId]
    );
    if (!result.rows[0]) {
      return {
        ingredientsBoxesDefault: ['A', 'B1', 'B2', 'CD'],
        cupsBoxDefault: 'E',
        boxASplitEnabled: false,
        boxACountDefault: 1
      };
    }
    return {
      ingredientsBoxesDefault: result.rows[0].ingredients_boxes_default || ['A', 'B1', 'B2', 'CD'],
      cupsBoxDefault: result.rows[0].cups_box_default || 'E',
      boxASplitEnabled: result.rows[0].box_a_split_enabled || false,
      boxACountDefault: result.rows[0].box_a_count_default || 1
    };
  },

  async updateBoxConfig(siteId, config, userId, userName) {
    const pool = getPool();
    
    const existingConfig = await this.getBoxConfig(siteId);

    const checkExists = await pool.query(
      `SELECT id FROM ops_site_configs WHERE site_id = $1`, [siteId]
    );

    if (checkExists.rows.length === 0) {
      await pool.query(
        `INSERT INTO ops_site_configs (site_id, ingredients_boxes_default, cups_box_default, box_a_split_enabled, box_a_count_default)
         VALUES ($1, $2, $3, $4, $5)`,
        [siteId, JSON.stringify(config.ingredientsBoxesDefault), config.cupsBoxDefault, config.boxASplitEnabled, config.boxACountDefault]
      );
    } else {
      await pool.query(
        `UPDATE ops_site_configs SET
          ingredients_boxes_default = $2,
          cups_box_default = $3,
          box_a_split_enabled = $4,
          box_a_count_default = $5,
          updated_at = NOW()
         WHERE site_id = $1`,
        [siteId, JSON.stringify(config.ingredientsBoxesDefault), config.cupsBoxDefault, config.boxASplitEnabled, config.boxACountDefault]
      );
    }

    await opsAuditLogService.log(
      userId, userName, 'BOX_CONFIG_UPDATED',
      'site', siteId, { previous: existingConfig, new: config }
    );

    return await this.getBoxConfig(siteId);
  },

  async checkDeviation(siteId, selectedBoxes, shipmentType) {
    const config = await this.getBoxConfig(siteId);
    
    if (shipmentType === 'cups') {
      const expected = [config.cupsBoxDefault];
      const actual = selectedBoxes.sort();
      return {
        hasDeviation: JSON.stringify(expected) !== JSON.stringify(actual),
        expected,
        actual
      };
    } else if (shipmentType === 'ingredients') {
      const expected = [...config.ingredientsBoxesDefault].sort();
      const actual = selectedBoxes.sort();
      return {
        hasDeviation: JSON.stringify(expected) !== JSON.stringify(actual),
        expected,
        actual
      };
    }
    
    return { hasDeviation: false, expected: [], actual: selectedBoxes };
  }
};

// =====================================================
// WEEKLY TASKS SERVICE
// =====================================================

export const opsWeeklyTasksService = {
  async getAll(filters = {}) {
    const pool = getPool();
    let query = 'SELECT t.*, s.venue_name, s.address FROM ops_weekly_tasks t JOIN ops_sites s ON t.site_id = s.site_id WHERE 1=1';
    const params = [];
    
    if (filters.siteId) {
      params.push(filters.siteId);
      query += ` AND t.site_id = $${params.length}`;
    }
    if (filters.status) {
      params.push(filters.status);
      query += ` AND t.status = $${params.length}`;
    }
    
    query += ' ORDER BY t.due_date DESC';
    
    const result = await pool.query(query, params);
    return result.rows;
  },

  async getByTaskId(taskId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_weekly_tasks WHERE task_id = $1',
      [taskId]
    );
    return result.rows[0] || null;
  },

  async getPending(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM ops_weekly_tasks 
       WHERE site_id = $1 AND status IN ('pending', 'in_progress')
       ORDER BY due_date DESC LIMIT 1`,
      [siteId]
    );
    return result.rows[0] || null;
  },

  async create(siteId, dueDate, assignedTo = null) {
    const pool = getPool();
    const taskId = generateId('TASK');
    const result = await pool.query(
      `INSERT INTO ops_weekly_tasks (task_id, site_id, due_date, assigned_to)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [taskId, siteId, dueDate, assignedTo]
    );
    return result.rows[0];
  },

  async updateStatus(taskId, status, userId = null) {
    const pool = getPool();
    let query = 'UPDATE ops_weekly_tasks SET status = $2, updated_at = NOW()';
    const params = [taskId, status];
    
    if (status === 'in_progress') {
      query += ', started_at = NOW()';
    } else if (status === 'completed') {
      params.push(userId);
      query += `, completed_at = NOW(), completed_by = $${params.length}`;
    }
    
    query += ' WHERE task_id = $1 RETURNING *';
    
    const result = await pool.query(query, params);
    return result.rows[0];
  },

  async markAlertCreated(taskId) {
    const pool = getPool();
    await pool.query(
      'UPDATE ops_weekly_tasks SET alert_created_at = NOW(), updated_at = NOW() WHERE task_id = $1',
      [taskId]
    );
  },

  async markEmergencyTaskCreated(taskId) {
    const pool = getPool();
    await pool.query(
      'UPDATE ops_weekly_tasks SET emergency_task_created_at = NOW(), updated_at = NOW() WHERE task_id = $1',
      [taskId]
    );
  },

  async getOverdue() {
    const pool = getPool();
    const result = await pool.query(
      `SELECT t.*, s.venue_name, c.overdue_threshold_hours
       FROM ops_weekly_tasks t 
       JOIN ops_sites s ON t.site_id = s.site_id
       JOIN ops_site_configs c ON t.site_id = c.site_id
       WHERE t.status IN ('pending', 'in_progress')
       AND t.due_date < NOW() - (c.overdue_threshold_hours || ' hours')::INTERVAL`
    );
    return result.rows;
  },

  async checkAndCreateOverdueAlerts() {
    const pool = getPool();
    const alerts = { created48h: [], created72h: [] };
    
    // Get tasks overdue by 48+ hours without an alert
    const overdue48h = await pool.query(
      `SELECT t.*, s.venue_name 
       FROM ops_weekly_tasks t 
       JOIN ops_sites s ON t.site_id = s.site_id
       WHERE t.status IN ('pending', 'in_progress')
       AND t.due_date < NOW() - INTERVAL '48 hours'
       AND t.alert_created_at IS NULL`
    );
    
    for (const task of overdue48h.rows) {
      // Create incident for 48h overdue
      const incidentId = generateId('INC');
      await pool.query(
        `INSERT INTO ops_incidents (incident_id, site_id, type, severity, description, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [incidentId, task.site_id, 'overdue_task_48h', 'high', 
         `Weekly refill/clean task overdue by 48+ hours at ${task.venue_name}. Attention needed.`,
         'system']
      );
      await this.markAlertCreated(task.task_id);
      alerts.created48h.push({ taskId: task.task_id, incidentId, siteName: task.venue_name });
    }
    
    // Get tasks overdue by 72+ hours without emergency task
    const overdue72h = await pool.query(
      `SELECT t.*, s.venue_name 
       FROM ops_weekly_tasks t 
       JOIN ops_sites s ON t.site_id = s.site_id
       WHERE t.status IN ('pending', 'in_progress')
       AND t.due_date < NOW() - INTERVAL '72 hours'
       AND t.emergency_task_created_at IS NULL`
    );
    
    for (const task of overdue72h.rows) {
      // Create critical incident for 72h overdue
      const incidentId = generateId('INC');
      await pool.query(
        `INSERT INTO ops_incidents (incident_id, site_id, type, severity, description, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [incidentId, task.site_id, 'overdue_task_72h', 'critical', 
         `EMERGENCY: Weekly refill/clean task overdue by 72+ hours at ${task.venue_name}. Safety buffer shipment review required.`,
         'system']
      );
      await this.markEmergencyTaskCreated(task.task_id);
      alerts.created72h.push({ taskId: task.task_id, incidentId, siteName: task.venue_name });
    }
    
    return alerts;
  }
};

// =====================================================
// WEEKLY SUBMISSIONS SERVICE
// =====================================================

export const opsWeeklySubmissionsService = {
  async getByTaskId(taskId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_weekly_submissions WHERE task_id = $1',
      [taskId]
    );
    return result.rows[0] || null;
  },

  async getBySiteId(siteId, limit = 10) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM ops_weekly_submissions WHERE site_id = $1 ORDER BY submitted_at DESC LIMIT $2`,
      [siteId, limit]
    );
    return result.rows;
  },

  async create(data) {
    const pool = getPool();
    const submissionId = generateId('SUB');
    const result = await pool.query(
      `INSERT INTO ops_weekly_submissions (
        submission_id, task_id, site_id, submitted_by,
        before_photo, after_photo, close_up_photos,
        checklist, matcha_condition, issue_flags, issue_notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [
        submissionId, data.taskId, data.siteId, data.submittedBy,
        data.beforePhoto, data.afterPhoto, JSON.stringify(data.closeUpPhotos || []),
        JSON.stringify(data.checklist || {}), data.matchaCondition,
        JSON.stringify(data.issueFlags || {}), data.issueNotes || null
      ]
    );
    
    // Update task status
    await opsWeeklyTasksService.updateStatus(data.taskId, 'completed', data.submittedBy);
    
    // Handle matcha condition tracking for A-50 fallback
    await handleMatchaCondition(data.siteId, data.matchaCondition);
    
    // Auto-create incidents for issues
    if (data.issueFlags) {
      await createIncidentsFromIssues(data.siteId, data.taskId, data.issueFlags, data.submittedBy);
    }
    
    return result.rows[0];
  },

  async getRecent(limit = 20) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT ws.*, s.venue_name 
       FROM ops_weekly_submissions ws
       JOIN ops_sites s ON ws.site_id = s.site_id
       ORDER BY ws.submitted_at DESC LIMIT $1`,
      [limit]
    );
    return result.rows;
  }
};

// Helper: Handle matcha condition for A-50 fallback
async function handleMatchaCondition(siteId, condition) {
  const pool = getPool();
  const config = await opsSiteConfigService.getBySiteId(siteId);
  if (!config) return;
  
  if (condition === 'hard_bricked') {
    const newCount = (config.consecutive_bricked_reports || 0) + 1;
    await pool.query(
      `UPDATE ops_site_configs SET 
        consecutive_bricked_reports = $2, 
        consecutive_soft_reports = 0,
        updated_at = NOW()
       WHERE site_id = $1`,
      [siteId, newCount]
    );
    
    // Trigger A-50 if 2 consecutive bricked
    if (newCount >= 2 && !config.a50_fallback_active) {
      await opsSiteConfigService.setA50Fallback(siteId, true);
      
      // Create incident for this
      await opsIncidentsService.create({
        siteId,
        type: 'a50_matcha_fallback',
        severity: 'medium',
        title: 'A-50 Matcha Fallback Activated',
        description: `Site reported "Hard/Bricked" matcha condition for 2 consecutive weeks. 30-day exception mode enabled.`,
        autoCreated: true
      });
    }
  } else {
    // Soft/normal condition
    const newSoftCount = (config.consecutive_soft_reports || 0) + 1;
    await pool.query(
      `UPDATE ops_site_configs SET 
        consecutive_soft_reports = $2, 
        consecutive_bricked_reports = 0,
        updated_at = NOW()
       WHERE site_id = $1`,
      [siteId, newSoftCount]
    );
    
    // Clear A-50 if 3 consecutive soft reports
    if (newSoftCount >= 3 && config.a50_fallback_active) {
      await opsSiteConfigService.setA50Fallback(siteId, false);
    }
  }
}

// Helper: Create incidents from weekly issues
async function createIncidentsFromIssues(siteId, taskId, issueFlags, userId) {
  if (issueFlags.leakWetBox) {
    await opsIncidentsService.create({
      siteId,
      type: 'wet_leak_refusal',
      severity: 'high',
      title: 'Wet/Leak Issue Reported',
      description: 'Weekly refill submission flagged wet or leaking box detected.',
      relatedTaskId: taskId,
      autoCreated: true,
      createdBy: userId
    });
  }
  
  if (issueFlags.messyCloset) {
    await opsIncidentsService.create({
      siteId,
      type: 'site_fail_messy',
      severity: 'medium',
      title: 'Messy Closet Issue',
      description: 'Weekly refill submission flagged disorganized or messy closet.',
      relatedTaskId: taskId,
      autoCreated: true,
      createdBy: userId
    });
  }
  
  if (issueFlags.accessIssue) {
    await opsIncidentsService.create({
      siteId,
      type: 'access_denied',
      severity: 'medium',
      title: 'Access Issue Reported',
      description: 'Weekly refill submission flagged access problems.',
      relatedTaskId: taskId,
      autoCreated: true,
      createdBy: userId
    });
  }
}

// =====================================================
// BOX DESCRIPTORS CONSTANT
// =====================================================

export const BOX_DESCRIPTORS = {
  'A': 'LIQUIDS (SYRUP)',
  'B1': 'POWDERS (MATCHA MIX + DAIRY)',
  'B2': 'POWDERS (OAT)',
  'CD': 'CUPS + DAIRY KITS',
  'E': 'CUPS ONLY'
};

export const SHIPMENT_TYPE_BOXES = {
  'ingredients': ['A', 'B1', 'B2', 'CD'],
  'cups': ['E'],
  'emergency': [] // User selects
};

// =====================================================
// SHIPMENTS SERVICE
// =====================================================

export const opsShipmentsService = {
  async getAll(filters = {}) {
    const pool = getPool();
    let query = 'SELECT sh.*, s.venue_name, s.address FROM ops_shipments sh JOIN ops_sites s ON sh.site_id = s.site_id WHERE 1=1';
    const params = [];
    
    if (filters.siteId) {
      params.push(filters.siteId);
      query += ` AND sh.site_id = $${params.length}`;
    }
    if (filters.status) {
      params.push(filters.status);
      query += ` AND sh.status = $${params.length}`;
    }
    if (filters.shipmentType) {
      params.push(filters.shipmentType);
      query += ` AND sh.shipment_type = $${params.length}`;
    }
    
    query += ' ORDER BY sh.created_at DESC';
    
    const result = await pool.query(query, params);
    return result.rows;
  },

  async getByShipmentId(shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_shipments WHERE shipment_id = $1',
      [shipmentId]
    );
    return result.rows[0] || null;
  },

  async create(data) {
    const pool = getPool();
    const shipmentId = generateId('SHIP');
    
    // Check if cups drop hold is active
    if (data.shipmentType === 'cups') {
      const config = await opsSiteConfigService.getBySiteId(data.siteId);
      if (config && (config.cups_drop_hold_active || config.skip_next_cups_drop)) {
        throw new Error('CUPS_DROP_BLOCKED: Site has cups drop hold or skip active');
      }
    }
    
    const result = await pool.query(
      `INSERT INTO ops_shipments (
        shipment_id, site_id, shipment_type, carrier_type, tracking_number,
        total_boxes, expected_delivery_date, created_by, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        shipmentId, data.siteId, data.shipmentType, data.carrierType || 'milk_run',
        data.trackingNumber || null, data.totalBoxes || 0,
        data.expectedDeliveryDate || null, data.createdBy, data.notes || null
      ]
    );
    return result.rows[0];
  },

  async updateStatus(shipmentId, status, userId = null, details = {}) {
    const pool = getPool();
    let query = 'UPDATE ops_shipments SET status = $2, updated_at = NOW()';
    const params = [shipmentId, status];
    
    if (status === 'packed') {
      params.push(userId);
      query += `, packed_at = NOW(), packed_by = $${params.length}`;
    } else if (status === 'shipped') {
      params.push(userId);
      query += `, shipped_at = NOW(), shipped_by = $${params.length}`;
    } else if (status === 'delivered') {
      query += ', delivered_at = NOW()';
    } else if (status === 'refused') {
      query += ', refused_at = NOW()';
      if (details.refusalReason) {
        params.push(details.refusalReason);
        query += `, refusal_reason = $${params.length}`;
      }
    }
    
    query += ' WHERE shipment_id = $1 RETURNING *';
    
    const result = await pool.query(query, params);
    return result.rows[0];
  },

  async getWithBoxes(shipmentId) {
    const pool = getPool();
    const shipmentResult = await pool.query(
      'SELECT sh.*, s.venue_name, s.address FROM ops_shipments sh JOIN ops_sites s ON sh.site_id = s.site_id WHERE shipment_id = $1', 
      [shipmentId]
    );
    if (!shipmentResult.rows[0]) return null;
    
    const boxesResult = await pool.query(
      'SELECT * FROM ops_shipment_boxes WHERE shipment_id = $1 ORDER BY box_id, box_number',
      [shipmentId]
    );
    
    return {
      ...shipmentResult.rows[0],
      boxes: boxesResult.rows
    };
  },

  async createWithBoxes(data) {
    const pool = getPool();
    const shipmentId = generateId('SHIP');
    
    // Check if cups drop hold is active for CUPS shipments
    if (data.shipmentType === 'cups') {
      const config = await opsSiteConfigService.getBySiteId(data.siteId);
      if (config && (config.cups_drop_hold_active || config.skip_next_cups_drop)) {
        throw new Error('CUPS_DROP_BLOCKED: Site has cups drop hold or skip active');
      }
    }
    
    // Get box configuration - either provided or default for shipment type
    let boxConfig = data.boxes || [];
    if (boxConfig.length === 0) {
      const defaultBoxIds = SHIPMENT_TYPE_BOXES[data.shipmentType] || [];
      boxConfig = defaultBoxIds.map(boxId => ({ boxId, total: 1 }));
    }
    
    // Calculate total box count
    const totalBoxCount = boxConfig.reduce((sum, box) => sum + (box.total || 1), 0);
    
    // Create shipment
    const shipmentResult = await pool.query(
      `INSERT INTO ops_shipments (
        shipment_id, site_id, shipment_type, carrier_type, tracking_number,
        total_boxes, planned_ship_date, expected_delivery_date, created_by, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        shipmentId, data.siteId, data.shipmentType, data.carrierType || 'milk_run',
        data.trackingNumber || null, totalBoxCount,
        data.plannedShipDate || null, data.expectedDeliveryDate || null,
        data.createdBy, data.notes || null
      ]
    );
    
    const shipment = shipmentResult.rows[0];
    const createdBoxes = [];
    
    // Create boxes with position/total
    for (const box of boxConfig) {
      const boxId = box.boxId;
      const total = box.total || 1;
      const descriptor = BOX_DESCRIPTORS[boxId] || `Box ${boxId}`;
      
      for (let position = 1; position <= total; position++) {
        const boxRecordId = generateId('BOX');
        const isHeavy = false;
        const hasLiquids = boxId === 'A';
        const hasInnerKits = boxId === 'CD';
        
        const boxResult = await pool.query(
          `INSERT INTO ops_shipment_boxes (
            box_record_id, shipment_id, site_id, box_id, descriptor,
            box_number, total_in_set, status, is_heavy, has_liquids, has_inner_kits
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING *`,
          [
            boxRecordId, shipmentId, data.siteId, boxId, descriptor,
            position, total, 'pending', isHeavy, hasLiquids, hasInnerKits
          ]
        );
        createdBoxes.push(boxResult.rows[0]);
      }
    }
    
    return {
      ...shipment,
      boxes: createdBoxes
    };
  }
};

// =====================================================
// SHIPMENT BOXES SERVICE
// =====================================================

export const opsShipmentBoxesService = {
  async getByShipmentId(shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_shipment_boxes WHERE shipment_id = $1 ORDER BY box_number',
      [shipmentId]
    );
    return result.rows;
  },

  async create(data) {
    const pool = getPool();
    const boxRecordId = generateId('BOX');
    const isHeavy = data.weight && parseFloat(data.weight) > 40;
    const hasLiquids = data.boxId === 'A';
    const hasInnerKits = data.boxId === 'CD';
    
    const result = await pool.query(
      `INSERT INTO ops_shipment_boxes (
        box_record_id, shipment_id, site_id, box_id, descriptor,
        box_number, total_in_set, batch_id, pack_date, weight,
        is_heavy, has_liquids, has_inner_kits
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [
        boxRecordId, data.shipmentId, data.siteId, data.boxId, data.descriptor,
        data.boxNumber, data.totalInSet, data.batchId || null,
        data.packDate || new Date(), data.weight || null,
        isHeavy, hasLiquids, hasInnerKits
      ]
    );
    
    // Update shipment total boxes
    await pool.query(
      'UPDATE ops_shipments SET total_boxes = total_boxes + 1 WHERE shipment_id = $1',
      [data.shipmentId]
    );
    
    return result.rows[0];
  },

  async updatePackingLog(boxRecordId, packingLog) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_shipment_boxes SET 
        packing_log = $2,
        updated_at = NOW()
       WHERE box_record_id = $1 RETURNING *`,
      [boxRecordId, JSON.stringify(packingLog)]
    );
    return result.rows[0];
  },

  async getByBoxRecordId(boxRecordId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT b.*, s.venue_name, s.address, s.primary_contact_name, sh.carrier_type, sh.tracking_number, sh.shipment_type
       FROM ops_shipment_boxes b 
       JOIN ops_sites s ON b.site_id = s.site_id
       JOIN ops_shipments sh ON b.shipment_id = sh.shipment_id
       WHERE b.box_record_id = $1`,
      [boxRecordId]
    );
    return result.rows[0] || null;
  },

  async updateStatus(boxRecordId, status) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_shipment_boxes SET status = $2, updated_at = NOW()
       WHERE box_record_id = $1 RETURNING *`,
      [boxRecordId, status]
    );
    return result.rows[0];
  },

  async markLabelGenerated(boxRecordId, labelType, qrPayload, labelPayloadJson = null) {
    const pool = getPool();
    
    const boxCheck = await pool.query(
      `SELECT box_id FROM ops_shipment_boxes WHERE box_record_id = $1`, [boxRecordId]
    );
    const boxId = boxCheck.rows[0]?.box_id?.toUpperCase() || '';
    
    if (boxId === 'CD' || boxId === 'C/D' || boxId === 'C-D') {
      const kitCheck = await opsPackingLogsService.checkKitCDVerified(boxRecordId);
      if (!kitCheck.verified) {
        throw new Error(`HUB_AND_SPOKE_VIOLATION: ${kitCheck.reason}. Cannot generate label until both KIT C and KIT D are QR-scanned.`);
      }
    }
    
    const result = await pool.query(
      `UPDATE ops_shipment_boxes SET 
        status = 'labeled',
        label_generated_at = NOW(),
        label_type = $2,
        qr_payload = $3,
        label_payload_json = $4,
        updated_at = NOW()
       WHERE box_record_id = $1 RETURNING *`,
      [boxRecordId, labelType, qrPayload, labelPayloadJson ? JSON.stringify(labelPayloadJson) : null]
    );
    return result.rows[0];
  },

  async checkAllBoxesLabeled(shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT COUNT(*) as total, COUNT(CASE WHEN status = 'labeled' THEN 1 END) as labeled
       FROM ops_shipment_boxes WHERE shipment_id = $1`,
      [shipmentId]
    );
    const { total, labeled } = result.rows[0];
    return parseInt(total) === parseInt(labeled) && parseInt(total) > 0;
  }
};

// =====================================================
// PACKING LOGS SERVICE
// =====================================================

export const opsPackingLogsService = {
  WEIGHT_LIMIT_LBS: 46.5,

  async getByShipmentBoxId(shipmentBoxId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_packing_logs WHERE shipment_box_id = $1',
      [shipmentBoxId]
    );
    return result.rows[0] || null;
  },

  async create(data) {
    const pool = getPool();
    const packingLogId = generateId('PACK');
    
    if (!data.packDate || !data.batchId) {
      throw new Error('VALIDATION_ERROR: packDate and batchId are required');
    }
    if (!data.shakeTestPass || !data.zeroRattleConfirmed) {
      throw new Error('VALIDATION_ERROR: shakeTestPass and zeroRattleConfirmed must be true');
    }
    
    const weight = data.weightLb ? parseFloat(data.weightLb) : 0;
    
    if (weight > this.WEIGHT_LIMIT_LBS) {
      const box = await pool.query(`SELECT shipment_id, box_id FROM ops_shipment_boxes WHERE box_record_id = $1`, [data.shipmentBoxId]);
      const shipmentId = box.rows[0]?.shipment_id;
      
      await pool.query(
        `UPDATE ops_shipment_boxes SET 
          weight = $2, is_heavy = TRUE, is_overweight = TRUE, updated_at = NOW()
         WHERE box_record_id = $1`,
        [data.shipmentBoxId, weight]
      );
      
      if (shipmentId) {
        await pool.query(
          `UPDATE ops_shipments SET has_overweight_boxes = TRUE, updated_at = NOW() WHERE shipment_id = $1`,
          [shipmentId]
        );
      }
      
      await opsOverweightService.logSafetyViolation(
        data.packedByUserId, 
        data.packedByUserName, 
        data.shipmentBoxId, 
        weight, 
        shipmentId
      );
      
      throw new Error(`SAFETY_VIOLATION: Box weight ${weight} lbs exceeds ${this.WEIGHT_LIMIT_LBS} lb limit. This box cannot be packed. Repack with reduced weight. A Lucky Drops penalty has been applied.`);
    }
    
    const result = await pool.query(
      `INSERT INTO ops_packing_logs (
        packing_log_id, shipment_box_id, pack_date, batch_id, weight_lb,
        shake_test_pass, zero_rattle_confirmed, notes, packed_by_user_id, packed_by_user_name,
        kit_c_scanned_at, kit_d_scanned_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [
        packingLogId, data.shipmentBoxId, data.packDate, data.batchId, 
        data.weightLb || null, data.shakeTestPass, data.zeroRattleConfirmed,
        data.notes || null, data.packedByUserId, data.packedByUserName || null,
        data.kitCScannedAt || null, data.kitDScannedAt || null
      ]
    );
    
    const isHeavy = weight > 40;
    const isOverweight = weight > this.WEIGHT_LIMIT_LBS;
    await pool.query(
      `UPDATE ops_shipment_boxes SET 
        status = 'packed',
        packing_log_id = $2,
        batch_id = $3,
        pack_date = $4,
        weight = $5,
        is_heavy = $6,
        is_overweight = $7,
        updated_at = NOW()
       WHERE box_record_id = $1`,
      [data.shipmentBoxId, packingLogId, data.batchId, data.packDate, data.weightLb || null, isHeavy, isOverweight]
    );
    
    if (isOverweight) {
      const box = await pool.query(`SELECT shipment_id FROM ops_shipment_boxes WHERE box_record_id = $1`, [data.shipmentBoxId]);
      if (box.rows[0]) {
        await pool.query(
          `UPDATE ops_shipments SET has_overweight_boxes = TRUE, updated_at = NOW() WHERE shipment_id = $1`,
          [box.rows[0].shipment_id]
        );
      }
    }
    
    return result.rows[0];
  },

  async recordKitScan(packingLogId, kitType) {
    const pool = getPool();
    const field = kitType === 'C' ? 'kit_c_scanned_at' : 'kit_d_scanned_at';
    await pool.query(
      `UPDATE ops_packing_logs SET ${field} = NOW(), updated_at = NOW() WHERE packing_log_id = $1`,
      [packingLogId]
    );
  },

  async checkKitCDVerified(shipmentBoxId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT kit_c_scanned_at, kit_d_scanned_at FROM ops_packing_logs WHERE shipment_box_id = $1`,
      [shipmentBoxId]
    );
    if (!result.rows[0]) return { verified: false, reason: 'No packing log found' };
    const { kit_c_scanned_at, kit_d_scanned_at } = result.rows[0];
    if (!kit_c_scanned_at || !kit_d_scanned_at) {
      return { 
        verified: false, 
        reason: `HUB-AND-SPOKE: Box C/D requires KIT C and KIT D QR scans. Missing: ${!kit_c_scanned_at ? 'KIT C' : ''} ${!kit_d_scanned_at ? 'KIT D' : ''}`.trim()
      };
    }
    return { verified: true };
  },

  async update(packingLogId, data) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_packing_logs SET
        pack_date = COALESCE($2, pack_date),
        batch_id = COALESCE($3, batch_id),
        weight_lb = COALESCE($4, weight_lb),
        shake_test_pass = COALESCE($5, shake_test_pass),
        zero_rattle_confirmed = COALESCE($6, zero_rattle_confirmed),
        notes = COALESCE($7, notes),
        updated_at = NOW()
       WHERE packing_log_id = $1 RETURNING *`,
      [packingLogId, data.packDate, data.batchId, data.weightLb, data.shakeTestPass, data.zeroRattleConfirmed, data.notes]
    );
    return result.rows[0];
  }
};

// =====================================================
// DELIVERY RECORDS SERVICE
// =====================================================

export const opsDeliveryRecordsService = {
  async getByDeliveryId(deliveryId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_delivery_records WHERE delivery_id = $1',
      [deliveryId]
    );
    return result.rows[0] || null;
  },

  async getByShipmentId(shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_delivery_records WHERE shipment_id = $1 ORDER BY created_at DESC',
      [shipmentId]
    );
    return result.rows;
  },

  async getPendingForPartner(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM ops_delivery_records 
       WHERE site_id = $1 AND status = 'delivered' AND partner_accepted_at IS NULL
       ORDER BY delivered_at DESC`,
      [siteId]
    );
    return result.rows;
  },

  async createPOD(data) {
    const pool = getPool();
    const deliveryId = generateId('DEL');
    
    const result = await pool.query(
      `INSERT INTO ops_delivery_records (
        delivery_id, shipment_id, site_id, driver_id, driver_name, route_id,
        carrier_type, tracking_number, placement_photos, status,
        access_denied, access_denied_photo, access_denied_notes,
        site_fail_flag, site_fail_photo, site_fail_notes, delivered_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
       RETURNING *`,
      [
        deliveryId, data.shipmentId, data.siteId, data.driverId,
        data.driverName || null, data.routeId || null,
        data.carrierType, data.trackingNumber || null,
        JSON.stringify(data.placementPhotos || []),
        data.accessDenied ? 'access_denied' : 'delivered',
        data.accessDenied || false, data.accessDeniedPhoto || null, data.accessDeniedNotes || null,
        data.siteFailFlag || false, data.siteFailPhoto || null, data.siteFailNotes || null,
        data.accessDenied ? null : new Date()
      ]
    );
    
    // Update shipment status if delivered
    if (!data.accessDenied) {
      await opsShipmentsService.updateStatus(data.shipmentId, 'delivered');
    }
    
    // Auto-create incidents
    if (data.accessDenied) {
      await opsIncidentsService.create({
        siteId: data.siteId,
        type: 'access_denied',
        severity: 'high',
        title: 'Delivery Access Denied',
        description: data.accessDeniedNotes || 'Driver could not access closet for delivery.',
        photos: data.accessDeniedPhoto ? [data.accessDeniedPhoto] : [],
        relatedShipmentId: data.shipmentId,
        relatedDeliveryId: deliveryId,
        autoCreated: true,
        createdBy: data.driverId
      });
    }
    
    if (data.siteFailFlag) {
      await opsIncidentsService.create({
        siteId: data.siteId,
        type: 'site_fail_messy',
        severity: 'medium',
        title: 'Site Fail: Disorganized Closet',
        description: data.siteFailNotes || 'Driver flagged closet as disorganized/unsafe.',
        photos: data.siteFailPhoto ? [data.siteFailPhoto] : [],
        relatedShipmentId: data.shipmentId,
        relatedDeliveryId: deliveryId,
        autoCreated: true,
        createdBy: data.driverId
      });
    }
    
    return result.rows[0];
  },

  async partnerAccept(deliveryId, userId) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_delivery_records SET
        partner_accepted_at = NOW(),
        partner_accepted_by = $2,
        status = 'accepted',
        updated_at = NOW()
       WHERE delivery_id = $1 RETURNING *`,
      [deliveryId, userId]
    );
    return result.rows[0];
  },

  async partnerRefuse(deliveryId, userId, reason, photo, notes) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_delivery_records SET
        partner_refused = TRUE,
        refusal_reason = $3,
        refusal_photo = $4,
        refusal_notes = $5,
        status = 'refused',
        updated_at = NOW()
       WHERE delivery_id = $1 RETURNING *`,
      [deliveryId, userId, reason, photo || null, notes || null]
    );
    
    const delivery = result.rows[0];
    
    // Update shipment status
    if (delivery) {
      await opsShipmentsService.updateStatus(delivery.shipment_id, 'refused', null, { refusalReason: reason });
      
      // Auto-create incident for wet/leak refusal
      if (reason === 'wet_leak') {
        await opsIncidentsService.create({
          siteId: delivery.site_id,
          type: 'wet_leak_refusal',
          severity: 'critical',
          title: 'Delivery Refused: Wet/Leak',
          description: notes || 'Partner refused delivery due to wet or leaking box.',
          photos: photo ? [photo] : [],
          relatedShipmentId: delivery.shipment_id,
          relatedDeliveryId: deliveryId,
          autoCreated: true,
          createdBy: userId
        });
      }
    }
    
    return delivery;
  },

  async accept(deliveryId, userId) {
    return this.partnerAccept(deliveryId, userId);
  },

  async refuse(deliveryId, userId, reason, photo, notes) {
    return this.partnerRefuse(deliveryId, userId, reason, photo, notes);
  },

  async getPendingBySite(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT d.*, s.shipment_type, s.carrier_type as shipment_carrier_type
       FROM ops_delivery_records d
       LEFT JOIN ops_shipments s ON d.shipment_id = s.shipment_id
       WHERE d.site_id = $1 AND d.status = 'delivered' AND d.partner_accepted_at IS NULL
       ORDER BY d.delivered_at DESC`,
      [siteId]
    );
    return result.rows;
  }
};

// =====================================================
// INCIDENTS SERVICE
// =====================================================

export const opsIncidentsService = {
  async getAll(filters = {}) {
    const pool = getPool();
    let query = 'SELECT i.*, s.venue_name FROM ops_incidents i JOIN ops_sites s ON i.site_id = s.site_id WHERE 1=1';
    const params = [];
    
    if (filters.siteId) {
      params.push(filters.siteId);
      query += ` AND i.site_id = $${params.length}`;
    }
    if (filters.status) {
      params.push(filters.status);
      query += ` AND i.status = $${params.length}`;
    }
    if (filters.type) {
      params.push(filters.type);
      query += ` AND i.type = $${params.length}`;
    }
    
    query += ' ORDER BY i.created_at DESC';
    
    const result = await pool.query(query, params);
    return result.rows;
  },

  async getByIncidentId(incidentId) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM ops_incidents WHERE incident_id = $1',
      [incidentId]
    );
    return result.rows[0] || null;
  },

  async getOpen() {
    const pool = getPool();
    const result = await pool.query(
      `SELECT i.*, s.venue_name 
       FROM ops_incidents i 
       JOIN ops_sites s ON i.site_id = s.site_id
       WHERE i.status IN ('open', 'in_progress')
       ORDER BY 
         CASE i.severity 
           WHEN 'critical' THEN 1 
           WHEN 'high' THEN 2 
           WHEN 'medium' THEN 3 
           ELSE 4 
         END,
         i.created_at DESC`
    );
    return result.rows;
  },

  async create(data) {
    const pool = getPool();
    const incidentId = generateId('INC');
    const result = await pool.query(
      `INSERT INTO ops_incidents (
        incident_id, site_id, type, severity, title, description, photos,
        related_task_id, related_shipment_id, related_delivery_id,
        auto_created, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [
        incidentId, data.siteId, data.type, data.severity || 'medium',
        data.title, data.description || null, JSON.stringify(data.photos || []),
        data.relatedTaskId || null, data.relatedShipmentId || null, data.relatedDeliveryId || null,
        data.autoCreated || false, data.createdBy || null
      ]
    );
    
    const incident = result.rows[0];
    
    setTimeout(async () => {
      try {
        const safeModeCheck = await checkAndTriggerSafeModeForIncident(
          data.siteId, data.type, data.severity
        );
        if (safeModeCheck?.triggered) {
          console.log(`[SAFE_MODE] Triggered for site ${data.siteId}: ${safeModeCheck.reason}`);
        }
      } catch (e) {
        console.log('Safe mode check error:', e.message);
      }
    }, 0);
    
    return incident;
  },

  async assign(incidentId, userId) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_incidents SET
        assigned_to = $2,
        assigned_at = NOW(),
        status = 'in_progress',
        updated_at = NOW()
       WHERE incident_id = $1 RETURNING *`,
      [incidentId, userId]
    );
    return result.rows[0];
  },

  async resolve(incidentId, userId, notes) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_incidents SET
        status = 'resolved',
        resolved_at = NOW(),
        resolved_by = $2,
        resolution_notes = $3,
        updated_at = NOW()
       WHERE incident_id = $1 RETURNING *`,
      [incidentId, userId, notes]
    );
    return result.rows[0];
  },

  async dismiss(incidentId, userId, notes) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_incidents SET
        status = 'dismissed',
        resolved_at = NOW(),
        resolved_by = $2,
        resolution_notes = $3,
        updated_at = NOW()
       WHERE incident_id = $1 RETURNING *`,
      [incidentId, userId, notes]
    );
    return result.rows[0];
  }
};

// =====================================================
// AUDIT LOG SERVICE
// =====================================================

export const opsAuditLogService = {
  async log(userId, userName, action, entityType, entityId, details = {}) {
    const pool = getPool();
    const logId = generateId('LOG');
    await pool.query(
      `INSERT INTO ops_audit_log (log_id, user_id, user_name, action, entity_type, entity_id, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [logId, userId, userName, action, entityType, entityId, JSON.stringify(details)]
    );
  },

  async getByEntity(entityType, entityId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM ops_audit_log 
       WHERE entity_type = $1 AND entity_id = $2 
       ORDER BY created_at DESC`,
      [entityType, entityId]
    );
    return result.rows;
  },

  async getRecent(limit = 50) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM ops_audit_log ORDER BY created_at DESC LIMIT $1`,
      [limit]
    );
    return result.rows;
  }
};

// =====================================================
// MANAGER OVERRIDES SERVICE
// =====================================================

export const opsManagerOverridesService = {
  async create(data) {
    const pool = getPool();
    const overrideId = generateId('OVR');
    const result = await pool.query(
      `INSERT INTO ops_manager_overrides (
        override_id, manager_id, manager_name, override_type,
        site_id, entity_type, entity_id, reason, previous_value, new_value, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [
        overrideId, data.managerId, data.managerName, data.overrideType,
        data.siteId || null, data.entityType || null, data.entityId || null,
        data.reason, JSON.stringify(data.previousValue || null),
        JSON.stringify(data.newValue || null), data.expiresAt || null
      ]
    );
    
    // Also log to audit
    await opsAuditLogService.log(
      data.managerId, data.managerName, 'manager_override',
      data.entityType || 'override', overrideId, data
    );
    
    return result.rows[0];
  },

  async getRecent(limit = 20) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM ops_manager_overrides ORDER BY created_at DESC LIMIT $1`,
      [limit]
    );
    return result.rows;
  },

  async getByEntityId(entityType, entityId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM ops_manager_overrides 
       WHERE entity_type = $1 AND entity_id = $2 
       ORDER BY created_at DESC`,
      [entityType, entityId]
    );
    return result.rows;
  }
};

// =====================================================
// NOTIFICATIONS SERVICE
// =====================================================

export const opsNotificationsService = {
  async create(data) {
    const pool = getPool();
    const notificationId = generateId('NOTIF');
    const result = await pool.query(
      `INSERT INTO ops_notifications (
        notification_id, site_id, type, severity, title, message,
        linked_entity_type, linked_entity_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        notificationId, data.siteId || null, data.type, data.severity || 'normal',
        data.title, data.message, data.linkedEntityType || null, data.linkedEntityId || null
      ]
    );
    return result.rows[0];
  },

  async getAll(filters = {}) {
    const pool = getPool();
    let query = `SELECT n.*, s.venue_name 
                 FROM ops_notifications n
                 LEFT JOIN ops_sites s ON n.site_id = s.site_id
                 WHERE 1=1`;
    const params = [];
    let paramIndex = 1;

    if (filters.siteId) {
      query += ` AND n.site_id = $${paramIndex++}`;
      params.push(filters.siteId);
    }
    if (filters.severity) {
      query += ` AND n.severity = $${paramIndex++}`;
      params.push(filters.severity);
    }
    if (filters.type) {
      query += ` AND n.type = $${paramIndex++}`;
      params.push(filters.type);
    }
    if (filters.unreadOnly) {
      query += ` AND n.read_at IS NULL`;
    }

    query += ` ORDER BY 
      CASE n.severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        ELSE 3 
      END,
      n.created_at DESC 
      LIMIT $${paramIndex}`;
    params.push(filters.limit || 100);

    const result = await pool.query(query, params);
    return result.rows;
  },

  async getUnreadCount() {
    const pool = getPool();
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM ops_notifications WHERE read_at IS NULL`
    );
    return parseInt(result.rows[0].count);
  },

  async markRead(notificationId, userId) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_notifications SET
        read_at = NOW(),
        read_by = $2
       WHERE notification_id = $1 RETURNING *`,
      [notificationId, userId]
    );
    return result.rows[0];
  },

  async markAllRead(userId) {
    const pool = getPool();
    await pool.query(
      `UPDATE ops_notifications SET
        read_at = NOW(),
        read_by = $1
       WHERE read_at IS NULL`,
      [userId]
    );
  }
};

// =====================================================
// CUPS HOLD SERVICE
// =====================================================

export const opsCupsHoldService = {
  async activateHold(siteId, reason, userId, userName) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_sites SET
        cups_hold_active = TRUE,
        cups_hold_reason = $2,
        cups_hold_created_at = NOW(),
        cups_hold_cleared_at = NULL,
        updated_at = NOW()
       WHERE site_id = $1 RETURNING *`,
      [siteId, reason]
    );

    await opsAuditLogService.log(
      userId, userName, 'HOLD_CREATED',
      'site', siteId, { reason }
    );

    await opsNotificationsService.create({
      siteId,
      type: 'hold_created',
      severity: 'high',
      title: 'Cups Hold Activated',
      message: `Cups shipments blocked for site: ${reason}`,
      linkedEntityType: 'site',
      linkedEntityId: siteId
    });

    return result.rows[0];
  },

  async clearHold(siteId, reason, userId, userName) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE ops_sites SET
        cups_hold_active = FALSE,
        cups_hold_cleared_at = NOW(),
        updated_at = NOW()
       WHERE site_id = $1 RETURNING *`,
      [siteId]
    );

    await opsAuditLogService.log(
      userId, userName, 'HOLD_CLEARED',
      'site', siteId, { reason }
    );

    await opsNotificationsService.create({
      siteId,
      type: 'hold_cleared',
      severity: 'normal',
      title: 'Cups Hold Cleared',
      message: `Cups shipments unblocked for site: ${reason}`,
      linkedEntityType: 'site',
      linkedEntityId: siteId
    });

    return result.rows[0];
  },

  async overrideHold(siteId, shipmentId, reason, managerId, managerName) {
    const override = await opsManagerOverridesService.create({
      managerId,
      managerName,
      overrideType: 'cups_hold_override',
      siteId,
      entityType: 'shipment',
      entityId: shipmentId,
      reason,
      previousValue: { cupsHoldActive: true }
    });

    await opsAuditLogService.log(
      managerId, managerName, 'HOLD_OVERRIDDEN',
      'shipment', shipmentId, { siteId, reason, overrideId: override.override_id }
    );

    await opsNotificationsService.create({
      siteId,
      type: 'hold_overridden',
      severity: 'high',
      title: 'Cups Hold Override',
      message: `Manager ${managerName} overrode cups hold: ${reason}`,
      linkedEntityType: 'shipment',
      linkedEntityId: shipmentId
    });

    return override;
  },

  async checkHoldStatus(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT cups_hold_active, cups_hold_reason, cups_hold_created_at 
       FROM ops_sites WHERE site_id = $1`,
      [siteId]
    );
    if (!result.rows[0]) return { isBlocked: false };
    return {
      isBlocked: result.rows[0].cups_hold_active,
      reason: result.rows[0].cups_hold_reason,
      holdCreatedAt: result.rows[0].cups_hold_created_at
    };
  }
};

// =====================================================
// OVERWEIGHT SAFETY SERVICE (IMMUTABLE WEIGHT LAW)
// No manual overrides allowed - deterministic enforcement
// =====================================================

export const opsOverweightService = {
  WEIGHT_LIMIT_LBS: 46.5,
  LUCKY_DROPS_PENALTY_PERCENT: 15,
  PENALTY_VISIT_COUNT: 4,

  async logSafetyViolation(packerId, packerName, boxRecordId, weight, shipmentId) {
    const pool = getPool();
    
    await opsAuditLogService.log(
      packerId, packerName, 'SAFETY_VIOLATION_OVERWEIGHT',
      'box', boxRecordId, { 
        weight, 
        limit: this.WEIGHT_LIMIT_LBS, 
        shipmentId,
        violation: 'IMMUTABLE_WEIGHT_LAW',
        penalty: `${this.LUCKY_DROPS_PENALTY_PERCENT}% Lucky Drops reduction for ${this.PENALTY_VISIT_COUNT} visits`
      }
    );

    await opsNotificationsService.create({
      type: 'safety_violation',
      severity: 'critical',
      title: 'Safety Violation: Overweight Box',
      message: `Packer ${packerName} attempted to pack box at ${weight} lbs (limit: ${this.WEIGHT_LIMIT_LBS} lbs). Lucky Drops penalty applied.`,
      linkedEntityType: 'box',
      linkedEntityId: boxRecordId
    });

    await this.applyLuckyDropsPenalty(packerId, packerName);

    return {
      violation: true,
      message: `SAFETY VIOLATION: Box exceeds ${this.WEIGHT_LIMIT_LBS} lb limit. This box cannot be shipped. A ${this.LUCKY_DROPS_PENALTY_PERCENT}% Lucky Drops penalty has been applied for your next ${this.PENALTY_VISIT_COUNT} visits.`
    };
  },

  async applyLuckyDropsPenalty(userId, userName) {
    const pool = getPool();
    
    const checkTable = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'ops_user_penalties'
      )
    `);
    
    if (!checkTable.rows[0].exists) {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS ops_user_penalties (
          id SERIAL PRIMARY KEY,
          user_id VARCHAR(255) NOT NULL,
          user_name VARCHAR(255),
          penalty_type VARCHAR(50) NOT NULL,
          penalty_percent INTEGER NOT NULL,
          visits_remaining INTEGER NOT NULL,
          created_at TIMESTAMP DEFAULT NOW(),
          expires_after_visits INTEGER NOT NULL,
          violation_ref VARCHAR(255)
        )
      `);
    }
    
    await pool.query(
      `INSERT INTO ops_user_penalties (user_id, user_name, penalty_type, penalty_percent, visits_remaining, expires_after_visits)
       VALUES ($1, $2, 'lucky_drops_reduction', $3, $4, $4)`,
      [userId, userName, this.LUCKY_DROPS_PENALTY_PERCENT, this.PENALTY_VISIT_COUNT]
    );
    
    return { penaltyApplied: true, visits: this.PENALTY_VISIT_COUNT, percent: this.LUCKY_DROPS_PENALTY_PERCENT };
  },

  async getUserPenalty(userId) {
    const pool = getPool();
    
    try {
      const result = await pool.query(
        `SELECT SUM(penalty_percent) as total_penalty, SUM(visits_remaining) as total_visits
         FROM ops_user_penalties 
         WHERE user_id = $1 AND visits_remaining > 0`,
        [userId]
      );
      
      if (!result.rows[0] || !result.rows[0].total_penalty) {
        return { penaltyPercent: 0, visitsRemaining: 0 };
      }
      
      return {
        penaltyPercent: Math.min(result.rows[0].total_penalty, 50),
        visitsRemaining: result.rows[0].total_visits
      };
    } catch (e) {
      return { penaltyPercent: 0, visitsRemaining: 0 };
    }
  },

  async decrementPenaltyVisits(userId) {
    const pool = getPool();
    
    try {
      await pool.query(
        `UPDATE ops_user_penalties 
         SET visits_remaining = visits_remaining - 1
         WHERE user_id = $1 AND visits_remaining > 0`,
        [userId]
      );
    } catch (e) {
      console.log('No penalty table or no penalties to decrement');
    }
  },

  async checkShipmentOverweight(shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT box_record_id, weight, is_overweight 
       FROM ops_shipment_boxes 
       WHERE shipment_id = $1 AND is_overweight = TRUE`,
      [shipmentId]
    );
    return {
      hasOverweight: result.rows.length > 0,
      overweightBoxes: result.rows
    };
  },

  async canMarkShipped(shipmentId) {
    const pool = getPool();
    const shipment = await pool.query(
      `SELECT has_overweight_boxes FROM ops_shipments WHERE shipment_id = $1`,
      [shipmentId]
    );
    if (!shipment.rows[0]) return { allowed: false, reason: 'Shipment not found' };
    
    const { has_overweight_boxes } = shipment.rows[0];
    
    if (has_overweight_boxes) {
      return { 
        allowed: false, 
        reason: `IMMUTABLE WEIGHT LAW: Shipment contains boxes exceeding ${this.WEIGHT_LIMIT_LBS} lb limit. These boxes must be repacked before shipping. No overrides allowed.`
      };
    }
    
    return { allowed: true };
  },

  async checkBoxWeight(weight) {
    if (weight > this.WEIGHT_LIMIT_LBS) {
      return {
        isOverweight: true,
        weight,
        limit: this.WEIGHT_LIMIT_LBS,
        violation: true
      };
    }
    return { isOverweight: false, weight, limit: this.WEIGHT_LIMIT_LBS, violation: false };
  }
};

// =====================================================
// AUTO SAFE MODE SERVICE (Self-Healing)
// 2 consecutive Hard/Bricked failures → 30-day Safe Mode
// =====================================================

export const opsAutoSafeModeService = {
  FAILURE_THRESHOLD: 2,
  SAFE_MODE_DAYS: 30,

  async checkAndTriggerSafeMode(siteId, incidentType, severity) {
    if (!['hard_fail', 'bricked', 'squeeze_gate_fail'].includes(incidentType?.toLowerCase())) {
      return { triggered: false };
    }

    const pool = getPool();
    
    const recentIncidents = await pool.query(
      `SELECT incident_id, incident_type, severity FROM ops_incidents 
       WHERE site_id = $1 AND incident_type IN ('hard_fail', 'bricked', 'squeeze_gate_fail')
       ORDER BY created_at DESC LIMIT $2`,
      [siteId, this.FAILURE_THRESHOLD]
    );

    if (recentIncidents.rows.length >= this.FAILURE_THRESHOLD) {
      const allHardFails = recentIncidents.rows.every(i => 
        ['hard_fail', 'bricked', 'squeeze_gate_fail'].includes(i.incident_type?.toLowerCase())
      );

      if (allHardFails) {
        await this.activateSafeMode(siteId);
        return { triggered: true, reason: `${this.FAILURE_THRESHOLD} consecutive Hard/Bricked failures detected` };
      }
    }

    return { triggered: false };
  },

  async activateSafeMode(siteId) {
    const pool = getPool();
    
    await pool.query(
      `UPDATE ops_site_configs SET
        safe_mode_active = TRUE,
        safe_mode_activated_at = NOW(),
        safe_mode_rhythm_days = $2,
        matcha_oat_only = TRUE,
        updated_at = NOW()
       WHERE site_id = $1`,
      [siteId, this.SAFE_MODE_DAYS]
    );

    await opsAuditLogService.log(
      'SYSTEM', 'Auto Safe Mode', 'SAFE_MODE_ACTIVATED',
      'site', siteId, { 
        reason: 'Consecutive Hard/Bricked failures',
        rhythmDays: this.SAFE_MODE_DAYS,
        matchaOatOnly: true
      }
    );

    await opsNotificationsService.create({
      siteId,
      type: 'safe_mode_activated',
      severity: 'critical',
      title: 'Safe Mode Activated',
      message: `Site automatically switched to ${this.SAFE_MODE_DAYS}-day Safe Mode (Matcha-Oat only) due to consecutive failures.`,
      linkedEntityType: 'site',
      linkedEntityId: siteId
    });

    return { activated: true };
  },

  async checkSiteStatus(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT safe_mode_active, safe_mode_activated_at, safe_mode_rhythm_days, matcha_oat_only
       FROM ops_site_configs WHERE site_id = $1`,
      [siteId]
    );
    return result.rows[0] || { safe_mode_active: false };
  }
};

// =====================================================
// SLA TRACKER SERVICE (Kroc-Standard Timers)
// Weekly: 20 min benchmark | Monthly: 45 min benchmark
// =====================================================

export const opsSLATrackerService = {
  WEEKLY_BENCHMARK_MINS: 20,
  MONTHLY_BENCHMARK_MINS: 45,

  async recordTaskCompletion(taskId, taskType, startTime, endTime, userId, userName) {
    const pool = getPool();
    
    const durationMs = new Date(endTime) - new Date(startTime);
    const durationMins = Math.round(durationMs / 60000);
    const benchmark = taskType === 'monthly' ? this.MONTHLY_BENCHMARK_MINS : this.WEEKLY_BENCHMARK_MINS;
    const metBenchmark = durationMins <= benchmark;
    const efficiencyScore = Math.min(100, Math.round((benchmark / Math.max(durationMins, 1)) * 100));

    const checkTable = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'ops_sla_trackers'
      )
    `);
    
    if (!checkTable.rows[0].exists) {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS ops_sla_trackers (
          id SERIAL PRIMARY KEY,
          task_id VARCHAR(255),
          task_type VARCHAR(50),
          user_id VARCHAR(255),
          user_name VARCHAR(255),
          start_time TIMESTAMP,
          end_time TIMESTAMP,
          duration_mins INTEGER,
          benchmark_mins INTEGER,
          met_benchmark BOOLEAN,
          efficiency_score INTEGER,
          precision_bonus_granted BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);
    }

    await pool.query(
      `INSERT INTO ops_sla_trackers (task_id, task_type, user_id, user_name, start_time, end_time, duration_mins, benchmark_mins, met_benchmark, efficiency_score)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [taskId, taskType, userId, userName, startTime, endTime, durationMins, benchmark, metBenchmark, efficiencyScore]
    );

    if (metBenchmark) {
      await this.grantPrecisionBonus(userId, userName, taskType, durationMins);
    }

    return { 
      durationMins, 
      benchmark, 
      metBenchmark, 
      efficiencyScore,
      precisionBonusGranted: metBenchmark 
    };
  },

  async grantPrecisionBonus(userId, userName, taskType, durationMins) {
    await opsAuditLogService.log(
      userId, userName, 'PRECISION_BONUS_GRANTED',
      'user', userId, { taskType, durationMins, benchmark: taskType === 'monthly' ? this.MONTHLY_BENCHMARK_MINS : this.WEEKLY_BENCHMARK_MINS }
    );

    return { bonusGranted: true, taskType };
  },

  async getSiteEfficiencyScore(siteId) {
    const pool = getPool();
    try {
      const result = await pool.query(
        `SELECT AVG(efficiency_score) as avg_score, COUNT(*) as total_tasks,
                COUNT(CASE WHEN met_benchmark THEN 1 END) as on_time_tasks
         FROM ops_sla_trackers t
         JOIN ops_weekly_tasks wt ON t.task_id = wt.task_id
         WHERE wt.site_id = $1`,
        [siteId]
      );
      return {
        averageScore: Math.round(result.rows[0]?.avg_score || 0),
        totalTasks: parseInt(result.rows[0]?.total_tasks || 0),
        onTimeTasks: parseInt(result.rows[0]?.on_time_tasks || 0)
      };
    } catch (e) {
      return { averageScore: 0, totalTasks: 0, onTimeTasks: 0 };
    }
  }
};

// =====================================================
// ESCALATION SERVICE (Building Manager Alerts)
// Sad mood or Overdue >24h → Auto escalation email
// =====================================================

export const opsEscalationService = {
  ESCALATION_THRESHOLD_HOURS: 24,

  async checkAndEscalate(siteId, issueType, issueId, createdAt) {
    const pool = getPool();
    
    const hoursElapsed = (Date.now() - new Date(createdAt).getTime()) / (1000 * 60 * 60);
    
    if (hoursElapsed < this.ESCALATION_THRESHOLD_HOURS) {
      return { escalated: false, hoursRemaining: this.ESCALATION_THRESHOLD_HOURS - hoursElapsed };
    }

    const site = await pool.query(
      `SELECT building_manager_email, venue_name FROM ops_sites WHERE site_id = $1`,
      [siteId]
    );

    if (!site.rows[0]?.building_manager_email) {
      return { escalated: false, reason: 'No building manager email configured' };
    }

    const escalation = await this.createEscalation(
      siteId, 
      site.rows[0].venue_name,
      site.rows[0].building_manager_email, 
      issueType, 
      issueId, 
      hoursElapsed
    );

    return { escalated: true, escalation };
  },

  async createEscalation(siteId, venueName, managerEmail, issueType, issueId, hoursElapsed) {
    const pool = getPool();
    
    const checkTable = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'ops_escalations'
      )
    `);
    
    if (!checkTable.rows[0].exists) {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS ops_escalations (
          id SERIAL PRIMARY KEY,
          escalation_id VARCHAR(255) UNIQUE,
          site_id VARCHAR(255),
          venue_name VARCHAR(255),
          manager_email VARCHAR(255),
          issue_type VARCHAR(100),
          issue_id VARCHAR(255),
          hours_elapsed NUMERIC,
          email_sent BOOLEAN DEFAULT FALSE,
          email_sent_at TIMESTAMP,
          resolved BOOLEAN DEFAULT FALSE,
          resolved_at TIMESTAMP,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);
    }

    const escalationId = generateId('ESC');
    await pool.query(
      `INSERT INTO ops_escalations (escalation_id, site_id, venue_name, manager_email, issue_type, issue_id, hours_elapsed)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [escalationId, siteId, venueName, managerEmail, issueType, issueId, hoursElapsed]
    );

    await opsAuditLogService.log(
      'SYSTEM', 'Escalation Service', 'ESCALATION_TRIGGERED',
      issueType, issueId, { siteId, managerEmail, hoursElapsed }
    );

    await opsNotificationsService.create({
      siteId,
      type: 'escalation_alert',
      severity: 'critical',
      title: `Escalation: ${issueType} at ${venueName}`,
      message: `Issue has been unresolved for ${Math.round(hoursElapsed)} hours. Building manager notified.`,
      linkedEntityType: issueType,
      linkedEntityId: issueId
    });

    return { escalationId, managerEmail };
  },

  async getPendingEscalations() {
    const pool = getPool();
    try {
      const result = await pool.query(
        `SELECT * FROM ops_escalations WHERE resolved = FALSE ORDER BY created_at DESC`
      );
      return result.rows;
    } catch (e) {
      return [];
    }
  }
};

// =====================================================
// STREAK MULTIPLIER SERVICE (Lucky Drops Enhancement)
// Consecutive on-time high-quality visits increase win probability
// =====================================================

export const opsStreakMultiplierService = {
  BASE_STREAK_BONUS_PERCENT: 5,
  MAX_STREAK_BONUS_PERCENT: 25,

  async recordVisitQuality(userId, userName, taskId, metSLA, qualityScore) {
    const pool = getPool();
    
    const checkTable = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'ops_user_streaks'
      )
    `);
    
    if (!checkTable.rows[0].exists) {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS ops_user_streaks (
          id SERIAL PRIMARY KEY,
          user_id VARCHAR(255) UNIQUE,
          user_name VARCHAR(255),
          current_streak INTEGER DEFAULT 0,
          best_streak INTEGER DEFAULT 0,
          total_quality_visits INTEGER DEFAULT 0,
          streak_bonus_percent INTEGER DEFAULT 0,
          last_visit_at TIMESTAMP,
          created_at TIMESTAMP DEFAULT NOW(),
          updated_at TIMESTAMP DEFAULT NOW()
        )
      `);
    }

    const isQualityVisit = metSLA && qualityScore >= 80;

    if (isQualityVisit) {
      await pool.query(`
        INSERT INTO ops_user_streaks (user_id, user_name, current_streak, best_streak, total_quality_visits, streak_bonus_percent, last_visit_at)
        VALUES ($1, $2, 1, 1, 1, $3, NOW())
        ON CONFLICT (user_id) DO UPDATE SET
          current_streak = ops_user_streaks.current_streak + 1,
          best_streak = GREATEST(ops_user_streaks.best_streak, ops_user_streaks.current_streak + 1),
          total_quality_visits = ops_user_streaks.total_quality_visits + 1,
          streak_bonus_percent = LEAST($4, (ops_user_streaks.current_streak + 1) * $3),
          last_visit_at = NOW(),
          updated_at = NOW()
      `, [userId, userName, this.BASE_STREAK_BONUS_PERCENT, this.MAX_STREAK_BONUS_PERCENT]);
    } else {
      await pool.query(`
        INSERT INTO ops_user_streaks (user_id, user_name, current_streak, streak_bonus_percent, last_visit_at)
        VALUES ($1, $2, 0, 0, NOW())
        ON CONFLICT (user_id) DO UPDATE SET
          current_streak = 0,
          streak_bonus_percent = 0,
          last_visit_at = NOW(),
          updated_at = NOW()
      `, [userId, userName]);
    }

    return { isQualityVisit };
  },

  async getUserStreakBonus(userId) {
    const pool = getPool();
    try {
      const result = await pool.query(
        `SELECT current_streak, streak_bonus_percent FROM ops_user_streaks WHERE user_id = $1`,
        [userId]
      );
      if (!result.rows[0]) return { streak: 0, bonusPercent: 0 };
      return { 
        streak: result.rows[0].current_streak, 
        bonusPercent: result.rows[0].streak_bonus_percent 
      };
    } catch (e) {
      return { streak: 0, bonusPercent: 0 };
    }
  }
};

// =====================================================
// PHOTO GUARDRAILS SERVICE
// Enforces minimum size and metadata requirements
// =====================================================

export const opsPhotoGuardrailsService = {
  MIN_FILE_SIZE_BYTES: 1024 * 1024, // 1MB minimum
  
  validatePhoto(photoData) {
    const errors = [];
    
    if (!photoData) {
      return { valid: false, errors: ['No photo data provided'] };
    }
    
    if (photoData.sizeBytes && photoData.sizeBytes < this.MIN_FILE_SIZE_BYTES) {
      errors.push(`Photo too small: ${Math.round(photoData.sizeBytes / 1024)}KB (minimum 1MB required for proof-of-work)`);
    }
    
    if (!photoData.hasGpsMetadata && photoData.requiresGps !== false) {
      errors.push('GPS location metadata missing - enable location services and retake photo');
    }
    
    if (!photoData.hasTimestamp && photoData.requiresTimestamp !== false) {
      errors.push('Timestamp metadata missing - photo must be taken fresh, not from gallery');
    }
    
    return {
      valid: errors.length === 0,
      errors,
      validated: errors.length === 0,
      sizeBytes: photoData.sizeBytes,
      hasGps: !!photoData.hasGpsMetadata,
      hasTimestamp: !!photoData.hasTimestamp
    };
  },

  async logRejection(userId, userName, photoContext, errors) {
    await opsAuditLogService.log(
      userId, userName, 'PHOTO_GUARDRAIL_REJECTION',
      'photo', photoContext.entityId || 'unknown', 
      { context: photoContext.type, errors, timestamp: new Date().toISOString() }
    );
    
    return { rejected: true, errors };
  }
};

// =====================================================
// FLEET INTEGRITY SCORE SERVICE
// Aggregates Hub safety violations and Site compliance
// =====================================================

export const opsFleetIntegrityService = {
  async calculateScore() {
    const pool = getPool();
    
    const safetyViolations = await pool.query(`
      SELECT COUNT(*) as count FROM ops_audit_logs 
      WHERE action IN ('SAFETY_VIOLATION_OVERWEIGHT', 'PHOTO_GUARDRAIL_REJECTION')
      AND created_at > NOW() - INTERVAL '30 days'
    `);
    
    let slaCompliance = { avg_score: 100, total: 0, on_time: 0 };
    try {
      const slaResult = await pool.query(`
        SELECT AVG(efficiency_score) as avg_score, 
               COUNT(*) as total,
               COUNT(CASE WHEN met_benchmark THEN 1 END) as on_time
        FROM ops_sla_trackers 
        WHERE created_at > NOW() - INTERVAL '30 days'
      `);
      if (slaResult.rows[0]) slaCompliance = slaResult.rows[0];
    } catch (e) { }
    
    let escalationCount = 0;
    try {
      const escalations = await pool.query(`
        SELECT COUNT(*) as count FROM ops_escalations 
        WHERE created_at > NOW() - INTERVAL '30 days' AND resolved = FALSE
      `);
      escalationCount = parseInt(escalations.rows[0]?.count || 0);
    } catch (e) { }
    
    let incidentCount = 0;
    try {
      const incidents = await pool.query(`
        SELECT COUNT(*) as count FROM ops_incidents 
        WHERE created_at > NOW() - INTERVAL '30 days' 
        AND severity IN ('critical', 'high')
      `);
      incidentCount = parseInt(incidents.rows[0]?.count || 0);
    } catch (e) { }
    
    const violationCount = parseInt(safetyViolations.rows[0]?.count || 0);
    const avgSlaScore = parseFloat(slaCompliance.avg_score || 100);
    const onTimePercent = slaCompliance.total > 0 
      ? (parseInt(slaCompliance.on_time || 0) / parseInt(slaCompliance.total)) * 100 
      : 100;
    
    const violationPenalty = Math.min(violationCount * 2, 20);
    const escalationPenalty = Math.min(escalationCount * 3, 15);
    const incidentPenalty = Math.min(incidentCount * 2, 15);
    const slaBonus = Math.min(Math.round((avgSlaScore - 80) / 2), 10);
    
    const baseScore = 100;
    const score = Math.max(0, Math.min(100, 
      baseScore - violationPenalty - escalationPenalty - incidentPenalty + slaBonus
    ));
    
    let grade = 'A';
    if (score < 60) grade = 'F';
    else if (score < 70) grade = 'D';
    else if (score < 80) grade = 'C';
    else if (score < 90) grade = 'B';
    
    return {
      score,
      grade,
      components: {
        hubSafetyViolations: violationCount,
        siteComplianceScore: Math.round(avgSlaScore),
        onTimeCompletionRate: Math.round(onTimePercent),
        openEscalations: escalationCount,
        criticalIncidents: incidentCount
      },
      penalties: {
        violations: violationPenalty,
        escalations: escalationPenalty,
        incidents: incidentPenalty
      },
      bonuses: {
        slaPerformance: Math.max(0, slaBonus)
      },
      period: '30 days',
      calculatedAt: new Date().toISOString()
    };
  },

  async getSiteScore(siteId) {
    const pool = getPool();
    
    let slaResult = { avg_score: 100, total: 0, on_time: 0 };
    try {
      const result = await pool.query(`
        SELECT AVG(t.efficiency_score) as avg_score,
               COUNT(*) as total,
               COUNT(CASE WHEN t.met_benchmark THEN 1 END) as on_time
        FROM ops_sla_trackers t
        JOIN ops_weekly_tasks wt ON t.task_id = wt.task_id
        WHERE wt.site_id = $1 AND t.created_at > NOW() - INTERVAL '30 days'
      `, [siteId]);
      if (result.rows[0]) slaResult = result.rows[0];
    } catch (e) { }
    
    let incidentCount = 0;
    try {
      const incidents = await pool.query(`
        SELECT COUNT(*) as count FROM ops_incidents 
        WHERE site_id = $1 AND created_at > NOW() - INTERVAL '30 days'
      `, [siteId]);
      incidentCount = parseInt(incidents.rows[0]?.count || 0);
    } catch (e) { }
    
    const avgScore = parseFloat(slaResult.avg_score || 100);
    const onTimeRate = slaResult.total > 0 
      ? (parseInt(slaResult.on_time || 0) / parseInt(slaResult.total)) * 100 
      : 100;
    
    const score = Math.max(0, Math.min(100, 
      Math.round(avgScore * 0.6 + onTimeRate * 0.3 - incidentCount * 2)
    ));
    
    return {
      siteId,
      score,
      slaEfficiency: Math.round(avgScore),
      onTimeRate: Math.round(onTimeRate),
      incidentCount,
      period: '30 days'
    };
  }
};

// =====================================================
// VERIFICATION LOCK SERVICE
// Ensures visits can't close without required docs
// =====================================================

export const opsVerificationLockService = {
  async canCloseVisit(taskId, visitType) {
    const pool = getPool();
    
    const submission = await pool.query(
      `SELECT * FROM ops_weekly_submissions WHERE task_id = $1 ORDER BY submitted_at DESC LIMIT 1`,
      [taskId]
    );
    
    if (!submission.rows[0]) {
      return { canClose: false, reason: 'No submission found for this task' };
    }
    
    const sub = submission.rows[0];
    const checklistData = typeof sub.checklist_data === 'string' 
      ? JSON.parse(sub.checklist_data) 
      : sub.checklist_data;
    
    const missingItems = [];
    
    if (!checklistData?.afterPhotoUrl && !checklistData?.afterPhoto) {
      missingItems.push('After photo documentation required');
    }
    
    if (visitType === 'monthly' || sub.task_type === 'monthly') {
      if (!checklistData?.deepCleanCompleted) {
        missingItems.push('Monthly Deep Clean Wizard must be completed');
      }
      
      const requiredDeepCleanSteps = [
        'drip_tray_cleaned', 'grinder_cleaned', 'steam_wand_cleaned',
        'interior_wiped', 'exterior_polished'
      ];
      
      const completedSteps = checklistData?.deepCleanSteps || [];
      const missingSteps = requiredDeepCleanSteps.filter(s => !completedSteps.includes(s));
      
      if (missingSteps.length > 0) {
        missingItems.push(`Deep clean steps incomplete: ${missingSteps.join(', ')}`);
      }
    }
    
    if (missingItems.length > 0) {
      return {
        canClose: false,
        reason: 'VERIFICATION_LOCK: Visit cannot be closed until all requirements are met',
        missingItems,
        status: 'blocked'
      };
    }
    
    return { canClose: true, status: 'verified' };
  },

  async markVerified(taskId, verifiedBy) {
    const pool = getPool();
    
    await pool.query(
      `UPDATE ops_weekly_submissions SET 
        verification_status = 'verified',
        verified_at = NOW(),
        verified_by = $2
       WHERE task_id = $1`,
      [taskId, verifiedBy]
    );
    
    return { verified: true };
  }
};

// =====================================================
// BUILDING COMMAND DASHBOARD SERVICE
// Read-only view for building managers
// =====================================================

export const opsBuildingCommandService = {
  async getDashboardData(siteId) {
    const pool = getPool();
    
    const siteInfo = await pool.query(
      `SELECT s.*, sc.safe_mode_active, sc.matcha_oat_only
       FROM ops_sites s
       LEFT JOIN ops_site_configs sc ON s.site_id = sc.site_id
       WHERE s.site_id = $1`,
      [siteId]
    );
    
    if (!siteInfo.rows[0]) {
      return { error: 'Site not found' };
    }
    
    const site = siteInfo.rows[0];
    
    let recentTasks = [];
    try {
      const tasks = await pool.query(`
        SELECT wt.*, ws.status as submission_status, ws.submitted_at
        FROM ops_weekly_tasks wt
        LEFT JOIN ops_weekly_submissions ws ON wt.task_id = ws.task_id
        WHERE wt.site_id = $1
        ORDER BY wt.week_start DESC LIMIT 8
      `, [siteId]);
      recentTasks = tasks.rows;
    } catch (e) { }
    
    let complianceStreak = 0;
    for (const task of recentTasks) {
      if (task.submission_status === 'approved' || task.submission_status === 'completed') {
        complianceStreak++;
      } else {
        break;
      }
    }
    
    let openIncidents = [];
    try {
      const incidents = await pool.query(`
        SELECT * FROM ops_incidents 
        WHERE site_id = $1 AND status IN ('open', 'in_progress')
        ORDER BY severity DESC, created_at DESC
      `, [siteId]);
      openIncidents = incidents.rows;
    } catch (e) { }
    
    const siteScore = await opsFleetIntegrityService.getSiteScore(siteId);
    
    const completedTasks = recentTasks.filter(t => 
      t.submission_status === 'approved' || t.submission_status === 'completed'
    ).length;
    const uptimePercent = recentTasks.length > 0 
      ? Math.round((completedTasks / recentTasks.length) * 100) 
      : 100;
    
    return {
      site: {
        id: site.site_id,
        name: site.venue_name,
        address: site.address,
        buildingManager: site.building_manager_name,
        buildingManagerEmail: site.building_manager_email
      },
      machineStatus: {
        safeModeActive: site.safe_mode_active || false,
        matchaOatOnly: site.matcha_oat_only || false,
        uptimePercent
      },
      compliance: {
        streak: complianceStreak,
        siteScore: siteScore.score,
        slaEfficiency: siteScore.slaEfficiency,
        onTimeRate: siteScore.onTimeRate
      },
      recentActivity: recentTasks.slice(0, 4).map(t => ({
        taskId: t.task_id,
        weekStart: t.week_start,
        taskType: t.task_type,
        status: t.submission_status || t.status,
        submittedAt: t.submitted_at
      })),
      openIncidents: openIncidents.length,
      incidentDetails: openIncidents.slice(0, 3).map(i => ({
        id: i.incident_id,
        type: i.type,
        severity: i.severity,
        title: i.title,
        createdAt: i.created_at
      })),
      lastUpdated: new Date().toISOString()
    };
  }
};

// =====================================================
// LATE-BOUND HELPER (Avoids circular reference)
// =====================================================

async function checkAndTriggerSafeModeForIncident(siteId, incidentType, severity) {
  return await opsAutoSafeModeService.checkAndTriggerSafeMode(siteId, incidentType, severity);
}

// =====================================================
// PHASE 3: SHIPPING HARDENING SERVICES
// =====================================================

// BOX CONTENTS SNAPSHOT SERVICE - Append-only box contents
export const boxContentsSnapshotService = {
  async create(data) {
    const pool = getPool();
    const snapshotId = generateId('SNAP');
    
    const result = await pool.query(
      `INSERT INTO box_contents_snapshot 
        (snapshot_id, box_id, box_record_id, shipment_id, tenant_id, site_id, sku, item_name, qty, unit, lot_number, best_by, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [snapshotId, data.boxId, data.boxRecordId, data.shipmentId, data.tenantId, data.siteId, 
       data.sku, data.itemName, data.qty, data.unit || 'ea', data.lotNumber, data.bestBy, data.createdBy]
    );
    return result.rows[0];
  },

  async bulkCreate(items, boxRecordId, shipmentId, tenantId, siteId, createdBy) {
    const pool = getPool();
    const results = [];
    
    for (const item of items) {
      const snapshotId = generateId('SNAP');
      const result = await pool.query(
        `INSERT INTO box_contents_snapshot 
          (snapshot_id, box_id, box_record_id, shipment_id, tenant_id, site_id, sku, item_name, qty, unit, lot_number, best_by, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING *`,
        [snapshotId, item.boxId, boxRecordId, shipmentId, tenantId, siteId, 
         item.sku, item.itemName, item.qty, item.unit || 'ea', item.lotNumber, item.bestBy, createdBy]
      );
      results.push(result.rows[0]);
    }
    return results;
  },

  async getByBoxRecordId(boxRecordId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM box_contents_snapshot WHERE box_record_id = $1 ORDER BY created_at`,
      [boxRecordId]
    );
    return result.rows;
  },

  async isLocked(boxRecordId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT contents_locked_at FROM ops_shipment_boxes WHERE box_record_id = $1`,
      [boxRecordId]
    );
    return result.rows[0]?.contents_locked_at != null;
  }
};

// QC GATE EVENTS SERVICE - Append-only QC validation records
export const qcGateEventsService = {
  GATE_TYPES: [
    'scale_zero_calibration',
    'freshness_lock',
    'weight_law_check',
    'movement_compression',
    'label_verification',
    'kit_scan_c',
    'kit_scan_d'
  ],

  async record(data) {
    const pool = getPool();
    const gateEventId = generateId('QC');
    
    const result = await pool.query(
      `INSERT INTO qc_gate_events 
        (gate_event_id, tenant_id, site_id, shipment_id, box_id, box_record_id, gate_type, pass_fail, measured_value, notes, actor_user_id, actor_user_name, photo_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [gateEventId, data.tenantId, data.siteId, data.shipmentId, data.boxId, data.boxRecordId, 
       data.gateType, data.passFail, data.measuredValue, data.notes, data.actorUserId, data.actorUserName, data.photoId]
    );
    return result.rows[0];
  },

  async getByBoxRecordId(boxRecordId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM qc_gate_events WHERE box_record_id = $1 ORDER BY created_at`,
      [boxRecordId]
    );
    return result.rows;
  },

  async allGatesPassed(boxRecordId, requiredGates = ['scale_zero_calibration', 'weight_law_check', 'label_verification']) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT gate_type, pass_fail FROM qc_gate_events 
       WHERE box_record_id = $1 AND pass_fail = 'pass'
       ORDER BY created_at DESC`,
      [boxRecordId]
    );
    
    const passedGates = new Set(result.rows.map(r => r.gate_type));
    return requiredGates.every(g => passedGates.has(g));
  },

  async getQCSummary(boxRecordId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT gate_type, pass_fail, measured_value, actor_user_name, created_at
       FROM qc_gate_events WHERE box_record_id = $1 ORDER BY created_at`,
      [boxRecordId]
    );
    
    return {
      totalGates: result.rows.length,
      passedGates: result.rows.filter(r => r.pass_fail === 'pass').length,
      failedGates: result.rows.filter(r => r.pass_fail === 'fail').length,
      events: result.rows
    };
  }
};

// BOX SCAN CUSTODY SERVICE - Driver per-box scans
export const boxScanCustodyService = {
  async recordScan(data) {
    const pool = getPool();
    const scanId = generateId('SCAN');
    
    const result = await pool.query(
      `INSERT INTO box_scan_custody 
        (scan_id, tenant_id, site_id, shipment_id, box_record_id, delivery_id, scanned_by_driver_id, scanned_by_driver_name, scan_type, gps_latitude, gps_longitude, client_timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [scanId, data.tenantId, data.siteId, data.shipmentId, data.boxRecordId, data.deliveryId,
       data.driverId, data.driverName, data.scanType || 'delivery', data.gpsLatitude, data.gpsLongitude, data.clientTimestamp]
    );
    return result.rows[0];
  },

  async getByDeliveryId(deliveryId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM box_scan_custody WHERE delivery_id = $1 ORDER BY scanned_at`,
      [deliveryId]
    );
    return result.rows;
  },

  async getScannedBoxCount(deliveryId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT COUNT(DISTINCT box_record_id) as count FROM box_scan_custody WHERE delivery_id = $1`,
      [deliveryId]
    );
    return parseInt(result.rows[0]?.count || 0);
  },

  async verifyAllBoxesScanned(shipmentId, deliveryId) {
    const pool = getPool();
    
    const expectedBoxes = await pool.query(
      `SELECT box_record_id FROM ops_shipment_boxes WHERE shipment_id = $1`,
      [shipmentId]
    );
    
    const scannedBoxes = await pool.query(
      `SELECT DISTINCT box_record_id FROM box_scan_custody WHERE delivery_id = $1`,
      [deliveryId]
    );
    
    const expectedSet = new Set(expectedBoxes.rows.map(r => r.box_record_id));
    const scannedSet = new Set(scannedBoxes.rows.map(r => r.box_record_id));
    
    const missing = [...expectedSet].filter(id => !scannedSet.has(id));
    const extra = [...scannedSet].filter(id => !expectedSet.has(id));
    
    return {
      allScanned: missing.length === 0,
      expectedCount: expectedSet.size,
      scannedCount: scannedSet.size,
      missingBoxes: missing,
      unexpectedBoxes: extra
    };
  }
};

// ZONE PAR TARGETS SERVICE - Site inventory PAR levels
export const zoneParTargetsService = {
  async create(data) {
    const pool = getPool();
    const parId = generateId('PAR');
    
    const result = await pool.query(
      `INSERT INTO zone_par_targets 
        (par_id, tenant_id, site_id, zone, sku, item_name, unit, min_qty, target_qty, reorder_point, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [parId, data.tenantId, data.siteId, data.zone, data.sku, data.itemName, 
       data.unit || 'ea', data.minQty, data.targetQty, data.reorderPoint, data.createdBy]
    );
    return result.rows[0];
  },

  async getBySiteId(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM zone_par_targets WHERE site_id = $1 AND is_active = TRUE ORDER BY zone, sku`,
      [siteId]
    );
    return result.rows;
  },

  async getByZone(siteId, zone) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM zone_par_targets WHERE site_id = $1 AND zone = $2 AND is_active = TRUE ORDER BY sku`,
      [siteId, zone]
    );
    return result.rows;
  },

  async update(parId, data) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE zone_par_targets SET 
        min_qty = COALESCE($2, min_qty),
        target_qty = COALESCE($3, target_qty),
        reorder_point = COALESCE($4, reorder_point),
        is_active = COALESCE($5, is_active),
        updated_at = NOW()
       WHERE par_id = $1 RETURNING *`,
      [parId, data.minQty, data.targetQty, data.reorderPoint, data.isActive]
    );
    return result.rows[0];
  },

  async calculateDeltas(siteId, currentCounts) {
    const pool = getPool();
    const parTargets = await this.getBySiteId(siteId);
    
    const deltas = parTargets.map(par => {
      const current = currentCounts[par.sku] || 0;
      const delta = par.target_qty - current;
      const needsReorder = current <= (par.reorder_point || par.min_qty);
      
      return {
        zone: par.zone,
        sku: par.sku,
        itemName: par.item_name,
        currentQty: current,
        targetQty: par.target_qty,
        minQty: par.min_qty,
        delta: delta > 0 ? delta : 0,
        needsReorder,
        unit: par.unit
      };
    });
    
    return deltas.filter(d => d.delta > 0 || d.needsReorder);
  }
};

// REFILL COUNTS SERVICE - Partner count submissions
export const refillCountsService = {
  async record(data) {
    const pool = getPool();
    const countId = generateId('CNT');
    const delta = data.countAfter - (data.countBefore || 0);
    
    const result = await pool.query(
      `INSERT INTO refill_counts 
        (count_id, tenant_id, site_id, submission_id, zone, sku, item_name, count_before, count_after, delta, par_target_qty, counted_by, photo_proof)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [countId, data.tenantId, data.siteId, data.submissionId, data.zone, data.sku, data.itemName,
       data.countBefore, data.countAfter, delta, data.parTargetQty, data.countedBy, data.photoProof]
    );
    return result.rows[0];
  },

  async getBySubmissionId(submissionId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM refill_counts WHERE submission_id = $1 ORDER BY zone, sku`,
      [submissionId]
    );
    return result.rows;
  },

  async getLatestBySite(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT DISTINCT ON (sku) * FROM refill_counts 
       WHERE site_id = $1 ORDER BY sku, counted_at DESC`,
      [siteId]
    );
    return result.rows;
  },

  async getConsumptionHistory(siteId, days = 30) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT zone, sku, item_name, SUM(delta) as total_consumed, COUNT(*) as refill_count
       FROM refill_counts 
       WHERE site_id = $1 AND counted_at >= NOW() - INTERVAL '${days} days'
       GROUP BY zone, sku, item_name ORDER BY zone, sku`,
      [siteId]
    );
    return result.rows;
  }
};

// SHIPMENT PROPOSALS SERVICE - Auto-generated from consumption
export const shipmentProposalsService = {
  async create(data) {
    const pool = getPool();
    const proposalId = generateId('PROP');
    
    const result = await pool.query(
      `INSERT INTO shipment_proposals 
        (proposal_id, tenant_id, site_id, status, proposed_boxes, proposed_items, consumption_basis, projected_depletion_date, urgency)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [proposalId, data.tenantId, data.siteId, 'pending', 
       JSON.stringify(data.proposedBoxes || []), JSON.stringify(data.proposedItems || []),
       JSON.stringify(data.consumptionBasis), data.projectedDepletionDate, data.urgency || 'normal']
    );
    return result.rows[0];
  },

  async getPending(tenantId) {
    const pool = getPool();
    const query = tenantId 
      ? `SELECT sp.*, s.venue_name FROM shipment_proposals sp 
         LEFT JOIN ops_sites s ON sp.site_id = s.site_id
         WHERE sp.status = 'pending' AND sp.tenant_id = $1 ORDER BY sp.urgency DESC, sp.created_at`
      : `SELECT sp.*, s.venue_name FROM shipment_proposals sp 
         LEFT JOIN ops_sites s ON sp.site_id = s.site_id
         WHERE sp.status = 'pending' ORDER BY sp.urgency DESC, sp.created_at`;
    
    const result = await pool.query(query, tenantId ? [tenantId] : []);
    return result.rows;
  },

  async approve(proposalId, approvedBy) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE shipment_proposals SET 
        status = 'approved', approved_by = $2, approved_at = NOW()
       WHERE proposal_id = $1 RETURNING *`,
      [proposalId, approvedBy]
    );
    return result.rows[0];
  },

  async convertToShipment(proposalId, shipmentId) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE shipment_proposals SET 
        status = 'converted', converted_to_shipment_id = $2
       WHERE proposal_id = $1 RETURNING *`,
      [proposalId, shipmentId]
    );
    return result.rows[0];
  },

  async generateFromConsumption(siteId, tenantId) {
    const pool = getPool();
    
    const latestCounts = await refillCountsService.getLatestBySite(siteId);
    const parTargets = await zoneParTargetsService.getBySiteId(siteId);
    const consumption = await refillCountsService.getConsumptionHistory(siteId, 14);
    
    const currentInventory = {};
    latestCounts.forEach(c => { currentInventory[c.sku] = c.count_after; });
    
    const avgDailyConsumption = {};
    consumption.forEach(c => { 
      avgDailyConsumption[c.sku] = Math.ceil(parseInt(c.total_consumed) / 14); 
    });
    
    const itemsNeeded = [];
    let earliestDepletion = null;
    
    parTargets.forEach(par => {
      const current = currentInventory[par.sku] || 0;
      const daily = avgDailyConsumption[par.sku] || 1;
      const daysUntilMin = Math.max(0, Math.floor((current - par.min_qty) / daily));
      
      if (current < par.target_qty) {
        itemsNeeded.push({
          zone: par.zone,
          sku: par.sku,
          itemName: par.item_name,
          currentQty: current,
          targetQty: par.target_qty,
          qtyNeeded: par.target_qty - current,
          daysUntilDepletion: daysUntilMin
        });
        
        if (!earliestDepletion || daysUntilMin < earliestDepletion) {
          earliestDepletion = daysUntilMin;
        }
      }
    });
    
    if (itemsNeeded.length === 0) {
      return null;
    }
    
    const boxRecommendations = [];
    const zoneItems = {};
    itemsNeeded.forEach(item => {
      if (!zoneItems[item.zone]) zoneItems[item.zone] = [];
      zoneItems[item.zone].push(item);
    });
    
    Object.keys(zoneItems).forEach(zone => {
      const boxType = zone === 'A' ? 'A' : zone === 'E' ? 'E' : 'B1';
      boxRecommendations.push({ boxType, zone, items: zoneItems[zone] });
    });
    
    const urgency = earliestDepletion <= 3 ? 'urgent' : earliestDepletion <= 7 ? 'high' : 'normal';
    
    const proposal = await this.create({
      tenantId,
      siteId,
      proposedBoxes: boxRecommendations,
      proposedItems: itemsNeeded,
      consumptionBasis: { avgDailyConsumption, currentInventory },
      projectedDepletionDate: new Date(Date.now() + earliestDepletion * 24 * 60 * 60 * 1000),
      urgency
    });
    
    return proposal;
  }
};

// PLAYBOOK TASKS SERVICE - Auto-created from incidents
export const playbookTasksService = {
  PLAYBOOKS: {
    wet_leak: [
      { title: 'Reship replacement boxes', description: 'Create emergency shipment for affected items' },
      { title: 'Hub audit Box A packing', description: 'Review packing process for liquids boxes' },
      { title: 'Carrier claim documentation', description: 'Gather evidence for carrier damage claim' }
    ],
    missing_box: [
      { title: 'Reconcile expected vs scanned', description: 'Compare shipment manifest to driver scans' },
      { title: 'Carrier tracking verification', description: 'Check tracking number status' },
      { title: 'Driver interview', description: 'Contact driver to verify delivery' }
    ],
    wrong_items: [
      { title: 'Manifest/tenant/site validation', description: 'Verify labels match correct destination' },
      { title: 'Hub packing process review', description: 'Check for cross-site contamination' }
    ],
    damaged_packaging: [
      { title: 'Carrier claim evidence packet', description: 'Compile photos and documentation' },
      { title: 'Reship if contents affected', description: 'Assess and replace damaged goods' }
    ],
    access_denied: [
      { title: 'Contact site for access resolution', description: 'Coordinate with building management' },
      { title: 'Reschedule delivery', description: 'Plan alternate delivery time' }
    ],
    bricked_powder: [
      { title: 'Check storage conditions', description: 'Verify humidity/temperature at closet' },
      { title: 'Replace affected powder', description: 'Emergency matcha replacement' }
    ]
  },

  async createFromIncident(incidentId, incidentType, tenantId, siteId) {
    const pool = getPool();
    const playbook = this.PLAYBOOKS[incidentType] || [];
    
    const tasks = [];
    for (const taskDef of playbook) {
      const taskId = generateId('PBTASK');
      const dueAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
      
      const result = await pool.query(
        `INSERT INTO playbook_tasks 
          (task_id, tenant_id, site_id, incident_id, playbook_type, task_title, task_description, due_at, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
         RETURNING *`,
        [taskId, tenantId, siteId, incidentId, incidentType, taskDef.title, taskDef.description, dueAt]
      );
      tasks.push(result.rows[0]);
    }
    return tasks;
  },

  async getByIncidentId(incidentId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM playbook_tasks WHERE incident_id = $1 ORDER BY created_at`,
      [incidentId]
    );
    return result.rows;
  },

  async complete(taskId, completedBy, completionNotes) {
    const pool = getPool();
    const result = await pool.query(
      `UPDATE playbook_tasks SET 
        status = 'completed', completed_by = $2, completed_at = NOW(), completion_notes = $3
       WHERE task_id = $1 RETURNING *`,
      [taskId, completedBy, completionNotes]
    );
    return result.rows[0];
  },

  async getPendingBySite(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT pt.*, i.title as incident_title, i.severity 
       FROM playbook_tasks pt
       LEFT JOIN ops_incidents i ON pt.incident_id = i.incident_id
       WHERE pt.site_id = $1 AND pt.status = 'pending'
       ORDER BY pt.due_at`,
      [siteId]
    );
    return result.rows;
  }
};

// ACCEPTANCE WINDOW SERVICE - Auto-escalation for unaccepted deliveries
export const acceptanceWindowService = {
  async checkAndEscalate() {
    const pool = getPool();
    
    const expired = await pool.query(
      `SELECT d.*, s.shipment_id, s.tenant_id, os.venue_name
       FROM ops_delivery_records d
       LEFT JOIN ops_shipments s ON d.shipment_id = s.shipment_id
       LEFT JOIN ops_sites os ON d.site_id = os.site_id
       WHERE d.status = 'delivered' 
         AND d.partner_accepted_at IS NULL 
         AND d.acceptance_escalated = FALSE
         AND d.acceptance_window_expires_at < NOW()`
    );
    
    const escalated = [];
    for (const delivery of expired.rows) {
      const incidentId = generateId('INC');
      
      await pool.query(
        `INSERT INTO ops_incidents 
          (incident_id, site_id, type, severity, title, description, related_delivery_id, status, auto_created, created_at)
         VALUES ($1, $2, 'acceptance_expired', 'high', $3, $4, $5, 'open', TRUE, NOW())`,
        [incidentId, delivery.site_id, 
         `Delivery not accepted within window - ${delivery.venue_name}`,
         `Delivery ${delivery.delivery_id} was not accepted within the required window. Shipment: ${delivery.shipment_id}`,
         delivery.delivery_id]
      );
      
      await pool.query(
        `UPDATE ops_delivery_records SET 
          acceptance_escalated = TRUE, escalation_incident_id = $2
         WHERE delivery_id = $1`,
        [delivery.delivery_id, incidentId]
      );
      
      await opsNotificationsService.create({
        type: 'acceptance_window_expired',
        severity: 'high',
        siteId: delivery.site_id,
        title: 'Delivery Acceptance Required',
        message: `Delivery to ${delivery.venue_name} has not been accepted. Action required.`,
        linkedEntityType: 'delivery',
        linkedEntityId: delivery.delivery_id
      });
      
      escalated.push({ deliveryId: delivery.delivery_id, incidentId });
    }
    
    return escalated;
  },

  async setAcceptanceWindow(deliveryId, windowHours = 24) {
    const pool = getPool();
    const expiresAt = new Date(Date.now() + windowHours * 60 * 60 * 1000);
    
    await pool.query(
      `UPDATE ops_delivery_records SET acceptance_window_expires_at = $2 WHERE delivery_id = $1`,
      [deliveryId, expiresAt]
    );
    return expiresAt;
  }
};

// EVIDENCE PACKET SERVICE - Export bundles for disputes
export const evidencePacketService = {
  async generate(entityType, entityId, generatedBy) {
    const pool = getPool();
    let packet = null;
    
    if (entityType === 'shipment') {
      packet = await this.generateShipmentPacket(entityId, generatedBy);
    } else if (entityType === 'delivery') {
      packet = await this.generateDeliveryPacket(entityId, generatedBy);
    }
    
    return packet;
  },

  async generateShipmentPacket(shipmentId, generatedBy) {
    const pool = getPool();
    
    const shipment = await pool.query(
      `SELECT s.*, os.venue_name, os.address FROM ops_shipments s
       LEFT JOIN ops_sites os ON s.site_id = os.site_id
       WHERE s.shipment_id = $1`,
      [shipmentId]
    );
    
    if (!shipment.rows[0]) return null;
    const ship = shipment.rows[0];
    
    const boxes = await pool.query(
      `SELECT * FROM ops_shipment_boxes WHERE shipment_id = $1`,
      [shipmentId]
    );
    
    const qcEvents = [];
    const contents = [];
    for (const box of boxes.rows) {
      const qc = await qcGateEventsService.getByBoxRecordId(box.box_record_id);
      const cont = await boxContentsSnapshotService.getByBoxRecordId(box.box_record_id);
      qcEvents.push(...qc);
      contents.push(...cont);
    }
    
    const deliveries = await pool.query(
      `SELECT * FROM ops_delivery_records WHERE shipment_id = $1`,
      [shipmentId]
    );
    
    const custodyScans = [];
    for (const del of deliveries.rows) {
      const scans = await boxScanCustodyService.getByDeliveryId(del.delivery_id);
      custodyScans.push(...scans);
    }
    
    const payload = {
      shipment: ship,
      boxes: boxes.rows,
      boxContents: contents,
      qcGateEvents: qcEvents,
      deliveries: deliveries.rows,
      custodyScans,
      generatedAt: new Date().toISOString()
    };
    
    const crypto = await import('crypto');
    const packetHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    
    const packetId = generateId('EVPKT');
    const result = await pool.query(
      `INSERT INTO evidence_packets 
        (packet_id, tenant_id, site_id, packet_type, entity_type, entity_id, packet_hash, packet_payload, 
         manifest_summary, qc_gate_count, photo_count, event_count, generated_by)
       VALUES ($1, $2, $3, 'shipment_full', 'shipment', $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [packetId, ship.tenant_id, ship.site_id, shipmentId, packetHash, JSON.stringify(payload),
       `Shipment ${shipmentId}: ${boxes.rows.length} boxes, ${qcEvents.length} QC events`,
       qcEvents.length, deliveries.rows.reduce((acc, d) => acc + (d.placement_photos?.length || 0), 0),
       custodyScans.length, generatedBy]
    );
    
    return result.rows[0];
  },

  async generateDeliveryPacket(deliveryId, generatedBy) {
    const pool = getPool();
    
    const delivery = await pool.query(
      `SELECT d.*, s.*, os.venue_name FROM ops_delivery_records d
       LEFT JOIN ops_shipments s ON d.shipment_id = s.shipment_id
       LEFT JOIN ops_sites os ON d.site_id = os.site_id
       WHERE d.delivery_id = $1`,
      [deliveryId]
    );
    
    if (!delivery.rows[0]) return null;
    const del = delivery.rows[0];
    
    const custodyScans = await boxScanCustodyService.getByDeliveryId(deliveryId);
    
    const payload = {
      delivery: del,
      custodyScans,
      podPhotos: del.placement_photos || [],
      generatedAt: new Date().toISOString()
    };
    
    const crypto = await import('crypto');
    const packetHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    
    const packetId = generateId('EVPKT');
    const result = await pool.query(
      `INSERT INTO evidence_packets 
        (packet_id, tenant_id, site_id, packet_type, entity_type, entity_id, packet_hash, packet_payload, 
         manifest_summary, photo_count, event_count, generated_by)
       VALUES ($1, $2, $3, 'delivery_pod', 'delivery', $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [packetId, del.tenant_id, del.site_id, deliveryId, packetHash, JSON.stringify(payload),
       `Delivery ${deliveryId}: ${custodyScans.length} box scans`,
       (del.placement_photos?.length || 0), custodyScans.length, generatedBy]
    );
    
    return result.rows[0];
  },

  async getByEntityId(entityType, entityId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM evidence_packets WHERE entity_type = $1 AND entity_id = $2 ORDER BY generated_at DESC`,
      [entityType, entityId]
    );
    return result.rows;
  }
};

// GOLDEN PHOTOS SERVICE - Reference photos per site/zone
export const goldenPhotosService = {
  async upload(data) {
    const pool = getPool();
    const goldenId = generateId('GOLD');
    
    const result = await pool.query(
      `INSERT INTO golden_photos 
        (golden_id, tenant_id, site_id, zone, photo_url, description, uploaded_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [goldenId, data.tenantId, data.siteId, data.zone, data.photoUrl, data.description, data.uploadedBy]
    );
    return result.rows[0];
  },

  async getBySiteId(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM golden_photos WHERE site_id = $1 AND is_active = TRUE ORDER BY zone`,
      [siteId]
    );
    return result.rows;
  },

  async getByZone(siteId, zone) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM golden_photos WHERE site_id = $1 AND zone = $2 AND is_active = TRUE`,
      [siteId, zone]
    );
    return result.rows[0];
  },

  async deactivate(goldenId) {
    const pool = getPool();
    await pool.query(
      `UPDATE golden_photos SET is_active = FALSE WHERE golden_id = $1`,
      [goldenId]
    );
  }
};

// MANIFEST SERVICE - Generate printable manifests
export const manifestService = {
  async generateBoxManifest(boxRecordId) {
    const pool = getPool();
    
    const box = await pool.query(
      `SELECT b.*, s.shipment_type, s.carrier_type, s.tracking_number, s.tenant_id as shipment_tenant_id,
              os.venue_name, os.address
       FROM ops_shipment_boxes b
       LEFT JOIN ops_shipments s ON b.shipment_id = s.shipment_id
       LEFT JOIN ops_sites os ON b.site_id = os.site_id
       WHERE b.box_record_id = $1`,
      [boxRecordId]
    );
    
    if (!box.rows[0]) return null;
    const b = box.rows[0];
    
    const contents = await boxContentsSnapshotService.getByBoxRecordId(boxRecordId);
    const qcSummary = await qcGateEventsService.getQCSummary(boxRecordId);
    const packingLog = await pool.query(
      `SELECT * FROM ops_packing_logs WHERE shipment_box_id = $1`,
      [boxRecordId]
    );
    
    return {
      boxId: b.box_id,
      boxRecordId: b.box_record_id,
      descriptor: b.descriptor,
      sequence: `${b.box_number} of ${b.total_in_set}`,
      shipmentId: b.shipment_id,
      shipmentType: b.shipment_type,
      carrier: b.carrier_type,
      trackingNumber: b.tracking_number,
      destination: {
        tenantId: b.shipment_tenant_id,
        siteId: b.site_id,
        venueName: b.venue_name,
        address: b.address
      },
      weight: {
        target: b.target_weight_lbs,
        actual: b.weight,
        isHeavy: b.is_heavy,
        isOverweight: b.is_overweight
      },
      contents: contents.map(c => ({
        sku: c.sku,
        itemName: c.item_name,
        qty: c.qty,
        unit: c.unit,
        lotNumber: c.lot_number,
        bestBy: c.best_by
      })),
      qcGates: qcSummary,
      packingLog: packingLog.rows[0] || null,
      labelGeneratedAt: b.label_generated_at,
      contentsLockedAt: b.contents_locked_at,
      generatedAt: new Date().toISOString()
    };
  },

  async generateShipmentManifest(shipmentId) {
    const pool = getPool();
    
    const shipment = await pool.query(
      `SELECT s.*, os.venue_name, os.address FROM ops_shipments s
       LEFT JOIN ops_sites os ON s.site_id = os.site_id
       WHERE s.shipment_id = $1`,
      [shipmentId]
    );
    
    if (!shipment.rows[0]) return null;
    const ship = shipment.rows[0];
    
    const boxes = await pool.query(
      `SELECT * FROM ops_shipment_boxes WHERE shipment_id = $1 ORDER BY box_number`,
      [shipmentId]
    );
    
    const boxManifests = [];
    for (const box of boxes.rows) {
      const manifest = await this.generateBoxManifest(box.box_record_id);
      boxManifests.push(manifest);
    }
    
    return {
      shipmentId: ship.shipment_id,
      tenantId: ship.tenant_id,
      siteId: ship.site_id,
      destination: {
        venueName: ship.venue_name,
        address: ship.address
      },
      shipmentType: ship.shipment_type,
      carrier: ship.carrier_type,
      trackingNumber: ship.tracking_number,
      status: ship.status,
      totalBoxes: ship.total_boxes,
      expectedBoxCount: ship.expected_box_count,
      boxes: boxManifests,
      plannedShipDate: ship.planned_ship_date,
      expectedDeliveryDate: ship.expected_delivery_date,
      createdBy: ship.created_by,
      createdAt: ship.created_at,
      generatedAt: new Date().toISOString()
    };
  }
};

// =====================================================
// PHASE 4: PILOT READINESS + WEEKLY CADENCE + KPI
// =====================================================

// GO-LIVE CERTIFICATE SERVICE - Onboarding wizard
export const goLiveCertificateService = {
  DRY_RUN_CHECKS: [
    { type: 'qr_scan', name: 'QR Code Scan Works' },
    { type: 'photo_upload', name: 'Photo Upload + GPS Verification Works' },
    { type: 'delivery_scan', name: 'Delivery Scan + Acceptance Works' },
    { type: 'refill_counts', name: 'Refill Counts Submission Works' },
    { type: 'evidence_packet', name: 'Evidence Packet Export Works' }
  ],

  async create(tenantId, siteId, createdBy) {
    const pool = getPool();
    const certificateId = generateId('CERT');
    
    const result = await pool.query(
      `INSERT INTO go_live_certificates 
        (certificate_id, tenant_id, site_id, status, created_by)
       VALUES ($1, $2, $3, 'pending', $4)
       RETURNING *`,
      [certificateId, tenantId, siteId, createdBy]
    );
    return result.rows[0];
  },

  async getBySiteId(siteId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM go_live_certificates WHERE site_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [siteId]
    );
    return result.rows[0];
  },

  async getById(certificateId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM go_live_certificates WHERE certificate_id = $1`,
      [certificateId]
    );
    return result.rows[0];
  },

  async updateOnboardingStep(certificateId, stepName, stepData) {
    const pool = getPool();
    
    const cert = await this.getById(certificateId);
    if (!cert) return null;
    
    const steps = typeof cert.onboarding_steps === 'string' 
      ? JSON.parse(cert.onboarding_steps) 
      : (cert.onboarding_steps || {});
    
    steps[stepName] = { ...stepData, completedAt: new Date().toISOString() };
    
    const result = await pool.query(
      `UPDATE go_live_certificates SET 
        onboarding_steps = $2, updated_at = NOW()
       WHERE certificate_id = $1 RETURNING *`,
      [certificateId, JSON.stringify(steps)]
    );
    return result.rows[0];
  },

  async recordDryRunCheck(certificateId, checkType, passed, resultData, testedBy) {
    const pool = getPool();
    const checkId = generateId('CHK');
    
    const cert = await this.getById(certificateId);
    if (!cert) return null;
    
    await pool.query(
      `INSERT INTO go_live_dry_run_checks 
        (check_id, certificate_id, tenant_id, site_id, check_type, check_name, passed, result_data, tested_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [checkId, certificateId, cert.tenant_id, cert.site_id, checkType, 
       this.DRY_RUN_CHECKS.find(c => c.type === checkType)?.name || checkType,
       passed, JSON.stringify(resultData || {}), testedBy]
    );
    
    const allChecks = await pool.query(
      `SELECT check_type, passed FROM go_live_dry_run_checks WHERE certificate_id = $1`,
      [certificateId]
    );
    
    const passedChecks = {};
    allChecks.rows.forEach(c => {
      if (c.passed) passedChecks[c.check_type] = true;
    });
    
    const allPassed = this.DRY_RUN_CHECKS.every(c => passedChecks[c.type]);
    
    await pool.query(
      `UPDATE go_live_certificates SET 
        dry_run_results = $2, all_checks_passed = $3, updated_at = NOW()
       WHERE certificate_id = $1`,
      [certificateId, JSON.stringify(passedChecks), allPassed]
    );
    
    return { checkId, passed, allPassed };
  },

  async getDryRunStatus(certificateId) {
    const pool = getPool();
    
    const checks = await pool.query(
      `SELECT * FROM go_live_dry_run_checks WHERE certificate_id = $1 ORDER BY tested_at DESC`,
      [certificateId]
    );
    
    const passedByType = {};
    checks.rows.forEach(c => {
      if (!passedByType[c.check_type] && c.passed) {
        passedByType[c.check_type] = c;
      }
    });
    
    return this.DRY_RUN_CHECKS.map(check => ({
      type: check.type,
      name: check.name,
      passed: !!passedByType[check.type],
      lastCheck: passedByType[check.type] || checks.rows.find(c => c.check_type === check.type)
    }));
  },

  async markLive(certificateId, userId) {
    const pool = getPool();
    
    const cert = await this.getById(certificateId);
    if (!cert) return { error: 'Certificate not found' };
    if (!cert.all_checks_passed) {
      return { error: 'All dry-run checks must pass before marking site live' };
    }
    
    await pool.query(
      `UPDATE go_live_certificates SET 
        status = 'live', marked_live_at = NOW(), marked_live_by = $2, updated_at = NOW()
       WHERE certificate_id = $1`,
      [certificateId, userId]
    );
    
    await pool.query(
      `UPDATE ops_sites SET 
        is_live = TRUE, go_live_certificate_id = $2, status = 'active', updated_at = NOW()
       WHERE site_id = $1`,
      [cert.site_id, certificateId]
    );
    
    await opsAuditLogService.log(userId, 'System', 'SITE_MARKED_LIVE', 'site', cert.site_id, {
      certificateId, tenantId: cert.tenant_id
    });
    
    return { success: true, siteId: cert.site_id };
  },

  async updateZonesAndPAR(certificateId, zonesConfigured, parTargetsCount) {
    const pool = getPool();
    await pool.query(
      `UPDATE go_live_certificates SET 
        zones_configured = $2, par_targets_count = $3, updated_at = NOW()
       WHERE certificate_id = $1`,
      [certificateId, JSON.stringify(zonesConfigured), parTargetsCount]
    );
  },

  async updateGoldenPhotos(certificateId, count) {
    const pool = getPool();
    await pool.query(
      `UPDATE go_live_certificates SET golden_photos_count = $2, updated_at = NOW()
       WHERE certificate_id = $1`,
      [certificateId, count]
    );
  },

  async addInvitedUser(certificateId, userInfo) {
    const pool = getPool();
    const cert = await this.getById(certificateId);
    if (!cert) return null;
    
    const users = typeof cert.users_invited === 'string' 
      ? JSON.parse(cert.users_invited) 
      : (cert.users_invited || []);
    
    users.push({ ...userInfo, invitedAt: new Date().toISOString() });
    
    await pool.query(
      `UPDATE go_live_certificates SET users_invited = $2, updated_at = NOW()
       WHERE certificate_id = $1`,
      [certificateId, JSON.stringify(users)]
    );
    return users;
  }
};

// KPI SCOREBOARD SERVICE - Computed metrics from events
export const kpiScoreboardService = {
  THRESHOLDS: {
    proofFailureRate: 0.15,
    acceptanceOverdue: 0,
    missingBoxRate: 0
  },

  async computeWeeklyKPIs(siteId, weekStart) {
    const pool = getPool();
    
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekEnd.getDate() + 7);
    
    const site = await opsSitesService.getBySiteId(siteId);
    if (!site) return null;
    
    const refillStats = await pool.query(`
      SELECT 
        COUNT(*) as scheduled,
        COUNT(*) FILTER (WHERE status IN ('completed', 'approved')) as completed
      FROM ops_weekly_tasks 
      WHERE site_id = $1 AND week_start >= $2 AND week_start < $3
    `, [siteId, weekStart, weekEnd]);
    
    const refillScheduled = parseInt(refillStats.rows[0]?.scheduled || 0);
    const refillCompleted = parseInt(refillStats.rows[0]?.completed || 0);
    const refillCompletionRate = refillScheduled > 0 ? (refillCompleted / refillScheduled) * 100 : 100;
    
    const proofStats = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE verification_status = 'verified' AND resubmission_count = 0) as first_pass
      FROM ops_weekly_submissions 
      WHERE site_id = $1 AND submitted_at >= $2 AND submitted_at < $3
    `, [siteId, weekStart, weekEnd]);
    
    const proofSubmissions = parseInt(proofStats.rows[0]?.total || 0);
    const proofFirstPass = parseInt(proofStats.rows[0]?.first_pass || 0);
    const proofFirstPassRate = proofSubmissions > 0 ? (proofFirstPass / proofSubmissions) * 100 : 100;
    
    const deliveryStats = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'accepted') as accepted,
        AVG(EXTRACT(EPOCH FROM (partner_accepted_at - delivered_at))/3600) 
          FILTER (WHERE partner_accepted_at IS NOT NULL) as avg_latency_hours
      FROM ops_delivery_records 
      WHERE site_id = $1 AND delivered_at >= $2 AND delivered_at < $3
    `, [siteId, weekStart, weekEnd]);
    
    const deliveriesTotal = parseInt(deliveryStats.rows[0]?.total || 0);
    const deliveriesAccepted = parseInt(deliveryStats.rows[0]?.accepted || 0);
    const avgAcceptanceLatency = parseFloat(deliveryStats.rows[0]?.avg_latency_hours || 0);
    
    const missingBoxStats = await pool.query(`
      SELECT COUNT(*) as count FROM ops_incidents 
      WHERE site_id = $1 AND type = 'missing_box' 
        AND created_at >= $2 AND created_at < $3
    `, [siteId, weekStart, weekEnd]);
    const missingBoxCount = parseInt(missingBoxStats.rows[0]?.count || 0);
    
    const incidentStats = await pool.query(`
      SELECT type, COUNT(*) as count FROM ops_incidents 
      WHERE site_id = $1 AND created_at >= $2 AND created_at < $3
      GROUP BY type
    `, [siteId, weekStart, weekEnd]);
    
    const incidentsTotal = incidentStats.rows.reduce((sum, r) => sum + parseInt(r.count), 0);
    const incidentsByType = {};
    incidentStats.rows.forEach(r => { incidentsByType[r.type] = parseInt(r.count); });
    
    const trainingFlags = [];
    if (proofSubmissions > 0 && (1 - proofFirstPassRate/100) > this.THRESHOLDS.proofFailureRate) {
      trainingFlags.push({ type: 'proof_failures', message: 'High proof failure rate - training recommended' });
    }
    
    const overdueDeliveries = await pool.query(`
      SELECT COUNT(*) as count FROM ops_delivery_records 
      WHERE site_id = $1 AND status = 'delivered' 
        AND partner_accepted_at IS NULL 
        AND acceptance_window_expires_at < NOW()
    `, [siteId]);
    
    if (parseInt(overdueDeliveries.rows[0]?.count || 0) > 0) {
      trainingFlags.push({ type: 'acceptance_overdue', message: 'Overdue acceptance - ops escalation needed' });
    }
    
    if (missingBoxCount > 0) {
      trainingFlags.push({ type: 'missing_box', message: 'Missing boxes detected - hub audit needed' });
    }
    
    const snapshotId = generateId('KPI');
    
    await pool.query(`
      INSERT INTO weekly_kpi_snapshots 
        (snapshot_id, tenant_id, site_id, week_start, week_end,
         refill_scheduled, refill_completed, refill_completion_rate,
         proof_submissions, proof_first_pass, proof_first_pass_rate,
         deliveries_total, deliveries_accepted, avg_acceptance_latency_hours,
         missing_box_count, incidents_total, incidents_by_type, training_flags)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      ON CONFLICT (site_id, week_start) DO UPDATE SET
        refill_scheduled = EXCLUDED.refill_scheduled,
        refill_completed = EXCLUDED.refill_completed,
        refill_completion_rate = EXCLUDED.refill_completion_rate,
        proof_submissions = EXCLUDED.proof_submissions,
        proof_first_pass = EXCLUDED.proof_first_pass,
        proof_first_pass_rate = EXCLUDED.proof_first_pass_rate,
        deliveries_total = EXCLUDED.deliveries_total,
        deliveries_accepted = EXCLUDED.deliveries_accepted,
        avg_acceptance_latency_hours = EXCLUDED.avg_acceptance_latency_hours,
        missing_box_count = EXCLUDED.missing_box_count,
        incidents_total = EXCLUDED.incidents_total,
        incidents_by_type = EXCLUDED.incidents_by_type,
        training_flags = EXCLUDED.training_flags,
        computed_at = NOW()
      RETURNING *
    `, [snapshotId, site.tenant_id, siteId, weekStart, weekEnd,
        refillScheduled, refillCompleted, refillCompletionRate,
        proofSubmissions, proofFirstPass, proofFirstPassRate,
        deliveriesTotal, deliveriesAccepted, avgAcceptanceLatency,
        missingBoxCount, incidentsTotal, JSON.stringify(incidentsByType), JSON.stringify(trainingFlags)]);
    
    for (const flag of trainingFlags) {
      const flagId = generateId('FLAG');
      await pool.query(`
        INSERT INTO training_flags (flag_id, tenant_id, site_id, flag_type, flag_reason, severity)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [flagId, site.tenant_id, siteId, flag.type, flag.message, 'warning']);
    }
    
    return {
      siteId,
      weekStart,
      weekEnd,
      refill: { scheduled: refillScheduled, completed: refillCompleted, rate: refillCompletionRate },
      proof: { submissions: proofSubmissions, firstPass: proofFirstPass, rate: proofFirstPassRate },
      delivery: { total: deliveriesTotal, accepted: deliveriesAccepted, avgLatencyHours: avgAcceptanceLatency },
      missingBoxCount,
      incidents: { total: incidentsTotal, byType: incidentsByType },
      trainingFlags
    };
  },

  async getWeeklySnapshot(siteId, weekStart) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM weekly_kpi_snapshots WHERE site_id = $1 AND week_start = $2`,
      [siteId, weekStart]
    );
    return result.rows[0];
  },

  async getTrainingFlags(siteId, acknowledged = false) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM training_flags WHERE site_id = $1 AND acknowledged = $2 ORDER BY created_at DESC`,
      [siteId, acknowledged]
    );
    return result.rows;
  },

  async acknowledgeFlag(flagId, userId) {
    const pool = getPool();
    await pool.query(
      `UPDATE training_flags SET acknowledged = TRUE, acknowledged_by = $2, acknowledged_at = NOW()
       WHERE flag_id = $1`,
      [flagId, userId]
    );
  }
};

// WEEKLY CADENCE SERVICE - Auto-generated work queue
export const weeklyCadenceService = {
  async generateWeeklyPlan(tenantId, weekStart, generatedBy) {
    const pool = getPool();
    const planId = generateId('PLAN');
    
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekEnd.getDate() + 7);
    
    const sites = await pool.query(
      `SELECT * FROM ops_sites WHERE tenant_id = $1 AND is_live = TRUE AND status = 'active'`,
      [tenantId]
    );
    
    let shipmentProposalsCount = 0;
    let refillTasksCount = 0;
    let deliveryTasksCount = 0;
    let exceptionsCount = 0;
    
    await pool.query(
      `INSERT INTO weekly_cadence_plans 
        (plan_id, tenant_id, week_start, week_end, status, sites_included, generated_by)
       VALUES ($1, $2, $3, $4, 'draft', $5, $6)`,
      [planId, tenantId, weekStart, weekEnd, JSON.stringify(sites.rows.map(s => s.site_id)), generatedBy]
    );
    
    for (const site of sites.rows) {
      const proposal = await shipmentProposalsService.generateFromConsumption(site.site_id, tenantId);
      if (proposal) {
        shipmentProposalsCount++;
        await this.createWorkItem(planId, tenantId, site.site_id, 'shipment_proposal', 
          `Review shipment proposal for ${site.venue_name}`, 
          { urgency: proposal.urgency, proposalId: proposal.proposal_id }, 'shipment_proposal', proposal.proposal_id);
      }
      
      const taskId = generateId('TASK');
      await opsWeeklyTasksService.create({
        siteId: site.site_id,
        taskType: 'weekly',
        weekStart,
        dueDate: new Date(weekEnd.getTime() - 24*60*60*1000)
      });
      refillTasksCount++;
      
      await this.createWorkItem(planId, tenantId, site.site_id, 'refill_task',
        `Weekly refill for ${site.venue_name}`,
        { dueDate: weekEnd }, 'weekly_task', taskId);
      
      const pendingDeliveries = await pool.query(
        `SELECT d.* FROM ops_delivery_records d
         LEFT JOIN ops_shipments s ON d.shipment_id = s.shipment_id
         WHERE d.site_id = $1 AND d.status = 'in_transit'`,
        [site.site_id]
      );
      
      for (const delivery of pendingDeliveries.rows) {
        deliveryTasksCount++;
        await this.createWorkItem(planId, tenantId, site.site_id, 'delivery_task',
          `Delivery to ${site.venue_name}`,
          { deliveryId: delivery.delivery_id }, 'delivery', delivery.delivery_id);
      }
      
      const openIncidents = await pool.query(
        `SELECT * FROM ops_incidents WHERE site_id = $1 AND status IN ('open', 'in_progress')`,
        [site.site_id]
      );
      
      for (const incident of openIncidents.rows) {
        exceptionsCount++;
        await this.createWorkItem(planId, tenantId, site.site_id, 'exception',
          `Incident: ${incident.title}`,
          { incidentId: incident.incident_id, severity: incident.severity }, 'incident', incident.incident_id, 
          incident.severity === 'critical' ? 'high' : 'normal');
      }
    }
    
    await pool.query(
      `UPDATE weekly_cadence_plans SET 
        shipment_proposals_generated = $2, refill_tasks_generated = $3,
        delivery_tasks_generated = $4, exceptions_count = $5
       WHERE plan_id = $1`,
      [planId, shipmentProposalsCount, refillTasksCount, deliveryTasksCount, exceptionsCount]
    );
    
    return {
      planId,
      tenantId,
      weekStart,
      weekEnd,
      sitesIncluded: sites.rows.length,
      shipmentProposals: shipmentProposalsCount,
      refillTasks: refillTasksCount,
      deliveryTasks: deliveryTasksCount,
      exceptions: exceptionsCount
    };
  },

  async createWorkItem(planId, tenantId, siteId, itemType, title, metadata, linkedEntityType, linkedEntityId, priority = 'normal') {
    const pool = getPool();
    const workItemId = generateId('WORK');
    
    await pool.query(
      `INSERT INTO weekly_work_items 
        (work_item_id, plan_id, tenant_id, site_id, item_type, title, priority, linked_entity_type, linked_entity_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [workItemId, planId, tenantId, siteId, itemType, title, priority, linkedEntityType, linkedEntityId]
    );
    return workItemId;
  },

  async getThisWeekPlan(tenantId) {
    const pool = getPool();
    const today = new Date();
    const dayOfWeek = today.getDay();
    const weekStart = new Date(today);
    weekStart.setDate(today.getDate() - dayOfWeek);
    weekStart.setHours(0, 0, 0, 0);
    
    const result = await pool.query(
      `SELECT * FROM weekly_cadence_plans WHERE tenant_id = $1 AND week_start = $2`,
      [tenantId, weekStart]
    );
    return result.rows[0];
  },

  async getWorkItems(planId, filters = {}) {
    const pool = getPool();
    let query = `SELECT w.*, s.venue_name FROM weekly_work_items w
                 LEFT JOIN ops_sites s ON w.site_id = s.site_id
                 WHERE w.plan_id = $1`;
    const params = [planId];
    
    if (filters.itemType) {
      params.push(filters.itemType);
      query += ` AND w.item_type = $${params.length}`;
    }
    if (filters.status) {
      params.push(filters.status);
      query += ` AND w.status = $${params.length}`;
    }
    if (filters.siteId) {
      params.push(filters.siteId);
      query += ` AND w.site_id = $${params.length}`;
    }
    
    query += ` ORDER BY CASE w.priority WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, w.created_at`;
    
    const result = await pool.query(query, params);
    return result.rows;
  },

  async completeWorkItem(workItemId, completedBy) {
    const pool = getPool();
    await pool.query(
      `UPDATE weekly_work_items SET status = 'completed', completed_by = $2, completed_at = NOW()
       WHERE work_item_id = $1`,
      [workItemId, completedBy]
    );
  },

  async getExceptionsQueue(tenantId) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT w.*, s.venue_name, i.severity as incident_severity, i.type as incident_type
       FROM weekly_work_items w
       LEFT JOIN ops_sites s ON w.site_id = s.site_id
       LEFT JOIN ops_incidents i ON w.linked_entity_id = i.incident_id AND w.linked_entity_type = 'incident'
       WHERE w.tenant_id = $1 AND w.item_type = 'exception' AND w.status = 'pending'
       ORDER BY CASE w.priority WHEN 'high' THEN 1 ELSE 2 END, w.created_at`,
      [tenantId]
    );
    return result.rows;
  }
};

// LANDLORD DIGEST SERVICE - Weekly read-only summaries
export const landlordDigestService = {
  async generateDigest(siteId, weekStart) {
    const pool = getPool();
    
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekEnd.getDate() + 7);
    
    const site = await opsSitesService.getBySiteId(siteId);
    if (!site) return null;
    
    const refillStats = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status IN ('completed', 'approved')) as completed,
        COUNT(*) FILTER (WHERE status = 'overdue') as overdue
      FROM ops_weekly_tasks 
      WHERE site_id = $1 AND week_start >= $2 AND week_start < $3
    `, [siteId, weekStart, weekEnd]);
    
    const refillsCompleted = parseInt(refillStats.rows[0]?.completed || 0);
    const refillsOverdue = parseInt(refillStats.rows[0]?.overdue || 0);
    
    const deliveryStats = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'accepted') as accepted,
        COUNT(*) FILTER (WHERE status IN ('delivered', 'in_transit')) as pending
      FROM ops_delivery_records 
      WHERE site_id = $1 AND created_at >= $2 AND created_at < $3
    `, [siteId, weekStart, weekEnd]);
    
    const deliveriesAccepted = parseInt(deliveryStats.rows[0]?.accepted || 0);
    const deliveriesPending = parseInt(deliveryStats.rows[0]?.pending || 0);
    
    const incidentStats = await pool.query(`
      SELECT severity, COUNT(*) as count 
      FROM ops_incidents 
      WHERE site_id = $1 AND status IN ('open', 'in_progress')
      GROUP BY severity
    `, [siteId]);
    
    const openIncidents = incidentStats.rows.reduce((sum, r) => sum + parseInt(r.count), 0);
    const incidentSeverities = {};
    incidentStats.rows.forEach(r => { incidentSeverities[r.severity] = parseInt(r.count); });
    
    const streakData = await opsStreakMultiplierService.getCurrentStreak(siteId);
    const complianceStreak = streakData?.currentStreak || 0;
    
    let overallStatus = 'good';
    if (openIncidents > 0 && incidentSeverities.critical) {
      overallStatus = 'critical';
    } else if (openIncidents > 0 || refillsOverdue > 0) {
      overallStatus = 'attention';
    }
    
    const digestSummary = this.generateSummaryText({
      refillsCompleted, refillsOverdue, deliveriesAccepted, deliveriesPending,
      openIncidents, complianceStreak, overallStatus
    });
    
    const digestId = generateId('DIG');
    
    await pool.query(`
      INSERT INTO landlord_digests 
        (digest_id, tenant_id, site_id, week_start, week_end,
         refills_completed, refills_overdue, deliveries_accepted, deliveries_pending,
         open_incidents, incident_severities, compliance_streak, overall_status, digest_summary)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      ON CONFLICT (site_id, week_start) DO UPDATE SET
        refills_completed = EXCLUDED.refills_completed,
        refills_overdue = EXCLUDED.refills_overdue,
        deliveries_accepted = EXCLUDED.deliveries_accepted,
        deliveries_pending = EXCLUDED.deliveries_pending,
        open_incidents = EXCLUDED.open_incidents,
        incident_severities = EXCLUDED.incident_severities,
        compliance_streak = EXCLUDED.compliance_streak,
        overall_status = EXCLUDED.overall_status,
        digest_summary = EXCLUDED.digest_summary,
        generated_at = NOW()
      RETURNING *
    `, [digestId, site.tenant_id, siteId, weekStart, weekEnd,
        refillsCompleted, refillsOverdue, deliveriesAccepted, deliveriesPending,
        openIncidents, JSON.stringify(incidentSeverities), complianceStreak, overallStatus, digestSummary]);
    
    return {
      siteId,
      siteName: site.venue_name,
      weekStart,
      weekEnd,
      refills: { completed: refillsCompleted, overdue: refillsOverdue },
      deliveries: { accepted: deliveriesAccepted, pending: deliveriesPending },
      incidents: { open: openIncidents, severities: incidentSeverities },
      complianceStreak,
      overallStatus,
      summary: digestSummary,
      definitions: this.getDefinitions()
    };
  },

  generateSummaryText(data) {
    let summary = '';
    
    if (data.overallStatus === 'good') {
      summary = 'Your coffee machine is running smoothly this week. ';
    } else if (data.overallStatus === 'critical') {
      summary = 'There are urgent issues requiring attention. ';
    } else {
      summary = 'Some items need attention. ';
    }
    
    if (data.refillsCompleted > 0) {
      summary += `${data.refillsCompleted} scheduled maintenance visit${data.refillsCompleted > 1 ? 's' : ''} completed. `;
    }
    
    if (data.refillsOverdue > 0) {
      summary += `${data.refillsOverdue} visit${data.refillsOverdue > 1 ? 's are' : ' is'} overdue. `;
    }
    
    if (data.deliveriesAccepted > 0) {
      summary += `${data.deliveriesAccepted} supply delivery${data.deliveriesAccepted > 1 ? 'ies' : 'y'} received. `;
    }
    
    if (data.complianceStreak > 1) {
      summary += `${data.complianceStreak} week compliance streak!`;
    }
    
    return summary.trim();
  },

  getDefinitions() {
    return {
      verified: 'A visit that was completed with all required photos and checks passing on the first try.',
      overdue: 'A scheduled visit or delivery acceptance that was not completed within the expected timeframe.',
      complianceStreak: 'The number of consecutive weeks with all scheduled visits completed on time.',
      incident: 'Any reported issue with the machine or supplies that needs attention.'
    };
  },

  async getDigest(siteId, weekStart) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM landlord_digests WHERE site_id = $1 AND week_start = $2`,
      [siteId, weekStart]
    );
    
    if (!result.rows[0]) return null;
    
    return {
      ...result.rows[0],
      definitions: this.getDefinitions()
    };
  },

  async getRecentDigests(siteId, limit = 4) {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM landlord_digests WHERE site_id = $1 ORDER BY week_start DESC LIMIT $2`,
      [siteId, limit]
    );
    return result.rows.map(d => ({ ...d, definitions: this.getDefinitions() }));
  }
};
