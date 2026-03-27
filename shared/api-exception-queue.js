import { Router } from 'express';
import { getPool } from './db.js';
import { logSecurityEvent } from './rls-middleware.js';

const router = Router();

const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

const opsAuth = (req, res, next) => {
  const role = req.headers['x-user-role'];
  if (!['ops_admin', 'ops_manager'].includes(role)) {
    return res.status(403).json({ error: 'Ops access required' });
  }
  next();
};

router.get('/queue', opsAuth, async (req, res) => {
  const pool = getPool();
  const { 
    site, type, status = 'open', overdue, owner, 
    sortBy = 'severity', sortDir = 'desc',
    limit = 50, offset = 0 
  } = req.query;
  
  try {
    let query = `
      SELECT 
        i.incident_id, i.type, i.severity, i.title, i.status,
        i.site_id, i.created_at, i.sla_due_at, i.assigned_to,
        s.venue_name,
        CASE 
          WHEN i.sla_due_at IS NOT NULL AND i.sla_due_at < NOW() THEN TRUE
          ELSE FALSE
        END as is_overdue
      FROM ops_incidents i
      LEFT JOIN ops_sites s ON i.site_id = s.site_id
      WHERE 1=1
    `;
    const params = [];
    
    if (site) {
      params.push(site);
      query += ` AND i.site_id = $${params.length}`;
    }
    
    if (type && type !== 'all') {
      params.push(type);
      query += ` AND i.type = $${params.length}`;
    }
    
    if (status && status !== 'all') {
      if (status === 'open') {
        query += ` AND i.status IN ('open', 'in_progress')`;
      } else {
        params.push(status);
        query += ` AND i.status = $${params.length}`;
      }
    }
    
    if (overdue === 'true') {
      query += ` AND i.sla_due_at IS NOT NULL AND i.sla_due_at < NOW()`;
    }
    
    if (owner) {
      params.push(owner);
      query += ` AND i.assigned_to = $${params.length}`;
    }
    
    const sortColumn = sortBy === 'sla_due_at' ? 'i.sla_due_at' : 
                       sortBy === 'created_at' ? 'i.created_at' : 
                       `CASE i.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END`;
    query += ` ORDER BY ${sortColumn} ${sortDir === 'asc' ? 'ASC NULLS LAST' : 'DESC NULLS LAST'}`;
    
    params.push(parseInt(limit));
    query += `, i.created_at DESC LIMIT $${params.length}`;
    
    params.push(parseInt(offset));
    query += ` OFFSET $${params.length}`;
    
    const result = await pool.query(query, params);
    
    const countQuery = `
      SELECT COUNT(*) as total FROM ops_incidents i
      WHERE status IN ('open', 'in_progress')
    `;
    const countResult = await pool.query(countQuery);
    
    res.json({
      queue: result.rows,
      total: parseInt(countResult.rows[0]?.total || 0),
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/queue/:incidentId', opsAuth, async (req, res) => {
  const pool = getPool();
  const { incidentId } = req.params;
  
  try {
    const incident = await pool.query(
      `SELECT i.*, s.venue_name, s.address
       FROM ops_incidents i
       LEFT JOIN ops_sites s ON i.site_id = s.site_id
       WHERE i.incident_id = $1`,
      [incidentId]
    );
    
    if (incident.rows.length === 0) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    
    let timeline = [];
    try {
      const events = await pool.query(
        `SELECT event_id, event_type, payload_json, created_at
         FROM events
         WHERE payload_json::text LIKE $1
         ORDER BY created_at ASC`,
        [`%${incidentId}%`]
      );
      timeline = events.rows.map(e => ({
        eventId: e.event_id,
        type: e.event_type,
        payload: e.payload_json,
        timestamp: e.created_at
      }));
    } catch (e) { }
    
    let relatedShipments = [];
    let relatedBoxes = [];
    try {
      const shipments = await pool.query(
        `SELECT ship.shipment_id, ship.status, ship.created_at
         FROM ops_shipments ship
         WHERE ship.site_id = $1
         ORDER BY ship.created_at DESC LIMIT 5`,
        [incident.rows[0].site_id]
      );
      relatedShipments = shipments.rows;
      
      if (relatedShipments.length > 0) {
        const boxes = await pool.query(
          `SELECT box_record_id, box_id, box_sequence, status
           FROM ops_shipment_boxes
           WHERE shipment_id = $1`,
          [relatedShipments[0].shipment_id]
        );
        relatedBoxes = boxes.rows;
      }
    } catch (e) { }
    
    let attachedEvidence = [];
    try {
      const evidence = await pool.query(
        `SELECT attachment_id, file_type, url, created_at
         FROM attachments
         WHERE site_id = $1
         ORDER BY created_at DESC LIMIT 10`,
        [incident.rows[0].site_id]
      );
      attachedEvidence = evidence.rows;
    } catch (e) { }
    
    let assignmentHistory = [];
    try {
      const assignments = await pool.query(
        `SELECT * FROM ops_incident_assignments
         WHERE incident_id = $1
         ORDER BY assigned_at DESC`,
        [incidentId]
      );
      assignmentHistory = assignments.rows;
    } catch (e) { }
    
    res.json({
      incident: incident.rows[0],
      timeline,
      relatedShipments,
      relatedBoxes,
      attachedEvidence,
      assignmentHistory
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/queue/:incidentId/assign', opsAuth, async (req, res) => {
  const pool = getPool();
  const { incidentId } = req.params;
  const { assignTo, assignedBy } = req.body;
  
  try {
    const assignmentId = generateId('ASGN');
    
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS ops_incident_assignments (
          id SERIAL PRIMARY KEY,
          assignment_id TEXT UNIQUE NOT NULL,
          incident_id TEXT NOT NULL,
          assigned_to TEXT NOT NULL,
          assigned_by TEXT NOT NULL,
          assigned_at TIMESTAMP DEFAULT NOW(),
          notes TEXT
        )
      `);
    } catch (e) { }
    
    await pool.query(
      `INSERT INTO ops_incident_assignments 
       (assignment_id, incident_id, assigned_to, assigned_by)
       VALUES ($1, $2, $3, $4)`,
      [assignmentId, incidentId, assignTo, assignedBy]
    );
    
    await pool.query(
      `UPDATE ops_incidents SET 
         assigned_to = $2, 
         status = CASE WHEN status = 'open' THEN 'in_progress' ELSE status END,
         updated_at = NOW()
       WHERE incident_id = $1`,
      [incidentId, assignTo]
    );
    
    logSecurityEvent('INCIDENT_ASSIGNED', {
      userId: assignedBy,
      endpoint: `/queue/${incidentId}/assign`,
      action: 'POST',
      metadata: { incidentId, assignTo }
    });
    
    res.json({ success: true, assignmentId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/queue/:incidentId/complete', opsAuth, async (req, res) => {
  const pool = getPool();
  const { incidentId } = req.params;
  const { completedBy, resolution } = req.body;
  
  try {
    await pool.query(
      `UPDATE ops_incidents SET 
         status = 'resolved',
         resolved_at = NOW(),
         resolved_by = $2,
         resolution_notes = $3,
         updated_at = NOW()
       WHERE incident_id = $1`,
      [incidentId, completedBy, resolution]
    );
    
    logSecurityEvent('INCIDENT_RESOLVED', {
      userId: completedBy,
      endpoint: `/queue/${incidentId}/complete`,
      action: 'POST',
      metadata: { incidentId, resolution }
    });
    
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/stats', opsAuth, async (req, res) => {
  const pool = getPool();
  
  try {
    const openCount = await pool.query(
      `SELECT 
         COUNT(*) FILTER (WHERE status IN ('open', 'in_progress')) as open,
         COUNT(*) FILTER (WHERE severity = 'critical' AND status IN ('open', 'in_progress')) as critical,
         COUNT(*) FILTER (WHERE sla_due_at < NOW() AND status IN ('open', 'in_progress')) as overdue
       FROM ops_incidents`
    );
    
    const byType = await pool.query(
      `SELECT type, COUNT(*) as count 
       FROM ops_incidents 
       WHERE status IN ('open', 'in_progress')
       GROUP BY type`
    );
    
    const recentResolved = await pool.query(
      `SELECT COUNT(*) as count 
       FROM ops_incidents 
       WHERE status = 'resolved' 
       AND resolved_at > NOW() - INTERVAL '24 hours'`
    );
    
    res.json({
      stats: {
        open: parseInt(openCount.rows[0]?.open || 0),
        critical: parseInt(openCount.rows[0]?.critical || 0),
        overdue: parseInt(openCount.rows[0]?.overdue || 0),
        resolvedLast24h: parseInt(recentResolved.rows[0]?.count || 0),
        byType: byType.rows.reduce((acc, r) => {
          acc[r.type] = parseInt(r.count);
          return acc;
        }, {})
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
