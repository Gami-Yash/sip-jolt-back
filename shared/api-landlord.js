import { Router } from 'express';
import { getPool } from './db.js';
import { tenantMiddleware, logSecurityEvent, withTenantContext } from './rls-middleware.js';

const router = Router();

const landlordAuth = (req, res, next) => {
  const role = req.headers['x-user-role'];
  const tenantId = req.headers['x-tenant-id'];
  
  if (!['landlord_viewer', 'ops_admin'].includes(role)) {
    logSecurityEvent('LANDLORD_ACCESS_DENIED', {
      userId: req.headers['x-user-id'],
      tenantId,
      endpoint: req.path,
      action: req.method,
      success: false,
      metadata: { reason: 'invalid_role', providedRole: role }
    });
    return res.status(403).json({ error: 'Landlord viewer access required' });
  }
  
  if (!tenantId) {
    return res.status(403).json({ error: 'Tenant context required' });
  }
  
  req.tenantId = tenantId;
  next();
};

router.get('/portfolio', landlordAuth, async (req, res) => {
  const pool = getPool();
  const { tenantId } = req;
  
  try {
    const sites = await pool.query(
      `SELECT COUNT(*) as live_count FROM ops_sites 
       WHERE tenant_id = $1 AND status = 'live'`,
      [tenantId]
    );
    
    let pendingAcceptance = 0;
    try {
      const pending = await pool.query(
        `SELECT COUNT(*) as count FROM ops_delivery_records dr
         JOIN ops_shipments s ON dr.shipment_id = s.shipment_id
         WHERE s.tenant_id = $1 
         AND dr.status = 'delivered'
         AND dr.accepted_at IS NULL
         AND dr.created_at > NOW() - INTERVAL '7 days'`,
        [tenantId]
      );
      pendingAcceptance = parseInt(pending.rows[0]?.count || 0);
    } catch (e) { }
    
    let overdueRefills = 0;
    try {
      const overdue = await pool.query(
        `SELECT COUNT(*) as count FROM ops_weekly_tasks wt
         JOIN ops_sites s ON wt.site_id = s.site_id
         WHERE s.tenant_id = $1 
         AND wt.status = 'pending'
         AND wt.due_date < NOW()`,
        [tenantId]
      );
      overdueRefills = parseInt(overdue.rows[0]?.count || 0);
    } catch (e) { }
    
    let incidentsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    try {
      const incidents = await pool.query(
        `SELECT severity, COUNT(*) as count FROM ops_incidents
         WHERE tenant_id = $1 
         AND status IN ('open', 'in_progress')
         AND created_at > NOW() - INTERVAL '30 days'
         GROUP BY severity`,
        [tenantId]
      );
      incidents.rows.forEach(r => {
        incidentsBySeverity[r.severity] = parseInt(r.count);
      });
    } catch (e) { }
    
    let weeklySummary = null;
    try {
      const summary = await pool.query(
        `SELECT 
           SUM(refills_completed) as refills,
           SUM(deliveries_completed) as deliveries,
           SUM(incidents_count) as incidents,
           AVG(service_score) as avg_score
         FROM landlord_digests
         WHERE tenant_id = $1 
         AND week_start >= DATE_TRUNC('week', CURRENT_DATE)`,
        [tenantId]
      );
      if (summary.rows[0]) {
        weeklySummary = {
          refills: parseInt(summary.rows[0].refills || 0),
          deliveries: parseInt(summary.rows[0].deliveries || 0),
          incidents: parseInt(summary.rows[0].incidents || 0),
          avgScore: Math.round(parseFloat(summary.rows[0].avg_score || 0))
        };
      }
    } catch (e) { }
    
    logSecurityEvent('LANDLORD_PORTFOLIO_VIEW', {
      userId: req.headers['x-user-id'],
      tenantId,
      endpoint: '/portfolio',
      action: 'GET',
      success: true
    });
    
    res.json({
      portfolio: {
        liveSites: parseInt(sites.rows[0]?.live_count || 0),
        pendingAcceptance,
        overdueRefills,
        incidentsBySeverity,
        weeklySummary
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/sites', landlordAuth, async (req, res) => {
  const pool = getPool();
  const { tenantId } = req;
  
  try {
    const result = await pool.query(
      `SELECT 
         s.site_id, s.venue_name, s.address, s.status,
         s.last_visit_date, s.created_at,
         (SELECT COUNT(*) FROM ops_incidents i 
          WHERE i.site_id = s.site_id AND i.status IN ('open', 'in_progress')) as open_incidents
       FROM ops_sites s
       WHERE s.tenant_id = $1
       ORDER BY s.venue_name`,
      [tenantId]
    );
    
    res.json({ sites: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/sites/:siteId', landlordAuth, async (req, res) => {
  const pool = getPool();
  const { tenantId } = req;
  const { siteId } = req.params;
  
  try {
    const siteResult = await pool.query(
      `SELECT * FROM ops_sites WHERE site_id = $1 AND tenant_id = $2`,
      [siteId, tenantId]
    );
    
    if (siteResult.rows.length === 0) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const site = siteResult.rows[0];
    
    let lastDelivery = null;
    try {
      const delivery = await pool.query(
        `SELECT dr.*, s.shipment_id 
         FROM ops_delivery_records dr
         JOIN ops_shipments s ON dr.shipment_id = s.shipment_id
         WHERE s.site_id = $1
         ORDER BY dr.created_at DESC LIMIT 1`,
        [siteId]
      );
      if (delivery.rows[0]) {
        lastDelivery = {
          date: delivery.rows[0].created_at,
          status: delivery.rows[0].status,
          acceptedAt: delivery.rows[0].accepted_at
        };
      }
    } catch (e) { }
    
    let lastRefill = null;
    try {
      const refill = await pool.query(
        `SELECT ws.* FROM ops_weekly_submissions ws
         JOIN ops_weekly_tasks wt ON ws.task_id = wt.task_id
         WHERE wt.site_id = $1
         ORDER BY ws.submitted_at DESC LIMIT 1`,
        [siteId]
      );
      if (refill.rows[0]) {
        lastRefill = {
          date: refill.rows[0].submitted_at,
          status: refill.rows[0].verification_status || 'pending'
        };
      }
    } catch (e) { }
    
    let openIncidents = [];
    try {
      const incidents = await pool.query(
        `SELECT incident_id, type, severity, title, status, created_at
         FROM ops_incidents
         WHERE site_id = $1 AND status IN ('open', 'in_progress')
         ORDER BY severity DESC, created_at DESC
         LIMIT 10`,
        [siteId]
      );
      openIncidents = incidents.rows;
    } catch (e) { }
    
    res.json({
      site: {
        ...site,
        lastDelivery,
        lastRefill,
        openIncidents
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/incidents', landlordAuth, async (req, res) => {
  const pool = getPool();
  const { tenantId } = req;
  const { status = 'all', severity = 'all', limit = 50 } = req.query;
  
  try {
    let query = `
      SELECT i.*, s.venue_name 
      FROM ops_incidents i
      LEFT JOIN ops_sites s ON i.site_id = s.site_id
      WHERE i.tenant_id = $1
    `;
    const params = [tenantId];
    
    if (status !== 'all') {
      params.push(status);
      query += ` AND i.status = $${params.length}`;
    }
    
    if (severity !== 'all') {
      params.push(severity);
      query += ` AND i.severity = $${params.length}`;
    }
    
    params.push(parseInt(limit));
    query += ` ORDER BY i.created_at DESC LIMIT $${params.length}`;
    
    const result = await pool.query(query, params);
    
    res.json({ incidents: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/digest/weekly', landlordAuth, async (req, res) => {
  const pool = getPool();
  const { tenantId } = req;
  
  try {
    const result = await pool.query(
      `SELECT * FROM landlord_digests
       WHERE tenant_id = $1
       ORDER BY week_start DESC
       LIMIT 12`,
      [tenantId]
    );
    
    res.json({ digests: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
