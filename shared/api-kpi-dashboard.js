import { Router } from 'express';
import { getPool } from './db.js';

const router = Router();

const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

const opsAuth = (req, res, next) => {
  const role = req.headers['x-user-role'];
  if (!['ops_admin', 'ops_manager'].includes(role)) {
    return res.status(403).json({ error: 'Ops access required' });
  }
  next();
};

const TRAINING_THRESHOLDS = {
  proofRejectionRate: 20,
  missingScanCount: 3,
  lateAcceptanceCount: 3,
  repeatedIncidentCount: 3,
  evaluationDays: 14
};

router.get('/sites', opsAuth, async (req, res) => {
  const pool = getPool();
  const { startDate, endDate, tenantId } = req.query;
  
  const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const end = endDate || new Date().toISOString().split('T')[0];
  
  try {
    let query = `
      SELECT 
        s.site_id, s.venue_name, s.status,
        COALESCE(kpi.refill_completion_rate, 0) as refill_completion_rate,
        COALESCE(kpi.proof_first_pass_rate, 0) as proof_first_pass_rate,
        COALESCE(kpi.avg_acceptance_latency_hours, 0) as avg_acceptance_latency,
        COALESCE(kpi.missing_box_count, 0) as missing_box_count,
        COALESCE(kpi.incidents_total, 0) as incident_count,
        COALESCE(kpi.training_flags, '[]'::jsonb) as training_flags
      FROM ops_sites s
      LEFT JOIN weekly_kpi_snapshots kpi ON s.site_id = kpi.site_id
        AND kpi.week_start >= $1 AND kpi.week_end <= $2
      WHERE s.status = 'live'
    `;
    
    const params = [start, end];
    
    if (tenantId) {
      params.push(tenantId);
      query += ` AND s.tenant_id = $${params.length}`;
    }
    
    query += ` ORDER BY s.venue_name`;
    
    const result = await pool.query(query, params);
    
    res.json({ sites: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/sites/:siteId/detail', opsAuth, async (req, res) => {
  const pool = getPool();
  const { siteId } = req.params;
  const { weeks = 4 } = req.query;
  
  try {
    const snapshots = await pool.query(`
      SELECT * FROM weekly_kpi_snapshots
      WHERE site_id = $1
      ORDER BY week_start DESC
      LIMIT $2
    `, [siteId, parseInt(weeks)]);
    
    const incidents = await pool.query(`
      SELECT type, severity, COUNT(*) as count
      FROM ops_incidents
      WHERE site_id = $1 AND created_at > NOW() - INTERVAL '30 days'
      GROUP BY type, severity
    `, [siteId]);
    
    const completeness = await pool.query(`
      SELECT * FROM evidence_completeness
      WHERE site_id = $1
      ORDER BY week_start DESC
      LIMIT 4
    `, [siteId]);
    
    res.json({
      snapshots: snapshots.rows,
      incidentBreakdown: incidents.rows,
      evidenceCompleteness: completeness.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/training-flags', opsAuth, async (req, res) => {
  const pool = getPool();
  
  try {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS training_flags (
          id SERIAL PRIMARY KEY,
          flag_id TEXT UNIQUE NOT NULL,
          tenant_id TEXT,
          site_id TEXT,
          user_id TEXT,
          flag_type TEXT NOT NULL,
          trigger_value DECIMAL(8,2),
          threshold_value DECIMAL(8,2),
          evaluation_period_days INTEGER DEFAULT 14,
          status TEXT DEFAULT 'open',
          recommended_action TEXT,
          created_at TIMESTAMP DEFAULT NOW(),
          resolved_at TIMESTAMP,
          resolved_by TEXT
        )
      `);
    } catch (e) { }
    
    const flags = await pool.query(`
      SELECT tf.*, s.venue_name, u.name as user_name
      FROM training_flags tf
      LEFT JOIN ops_sites s ON tf.site_id = s.site_id
      LEFT JOIN jolt_users u ON tf.user_id::integer = u.id
      WHERE tf.status = 'open'
      ORDER BY tf.created_at DESC
    `);
    
    res.json({ flags: flags.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/training-flags/evaluate', opsAuth, async (req, res) => {
  const pool = getPool();
  
  try {
    const evaluationDays = TRAINING_THRESHOLDS.evaluationDays;
    const flagsCreated = [];
    
    const proofRejections = await pool.query(`
      SELECT submitter_id, COUNT(*) as total,
             COUNT(*) FILTER (WHERE verification_status = 'rejected') as rejected
      FROM ops_weekly_submissions
      WHERE submitted_at > NOW() - INTERVAL '${evaluationDays} days'
      GROUP BY submitter_id
      HAVING COUNT(*) >= 5
    `);
    
    for (const row of proofRejections.rows) {
      const rejectionRate = (row.rejected / row.total) * 100;
      if (rejectionRate > TRAINING_THRESHOLDS.proofRejectionRate) {
        const flagId = generateId('FLAG');
        await pool.query(`
          INSERT INTO training_flags (flag_id, user_id, flag_type, trigger_value, threshold_value, 
                                       evaluation_period_days, recommended_action)
          VALUES ($1, $2, 'high_proof_rejection', $3, $4, $5, $6)
          ON CONFLICT DO NOTHING
        `, [
          flagId, row.submitter_id, rejectionRate, TRAINING_THRESHOLDS.proofRejectionRate,
          evaluationDays, 'Review photo submission guidelines with technician'
        ]);
        flagsCreated.push({ type: 'high_proof_rejection', userId: row.submitter_id, value: rejectionRate });
      }
    }
    
    const missingScanUsers = await pool.query(`
      SELECT i.created_by as user_id, COUNT(*) as count
      FROM ops_incidents i
      WHERE i.type = 'missing_scan'
        AND i.created_at > NOW() - INTERVAL '${evaluationDays} days'
      GROUP BY i.created_by
      HAVING COUNT(*) >= $1
    `, [TRAINING_THRESHOLDS.missingScanCount]);
    
    for (const row of missingScanUsers.rows) {
      const flagId = generateId('FLAG');
      await pool.query(`
        INSERT INTO training_flags (flag_id, user_id, flag_type, trigger_value, threshold_value,
                                     evaluation_period_days, recommended_action)
        VALUES ($1, $2, 'repeated_missing_scans', $3, $4, $5, $6)
        ON CONFLICT DO NOTHING
      `, [
        flagId, row.user_id, row.count, TRAINING_THRESHOLDS.missingScanCount,
        evaluationDays, 'Reinforce custody scan workflow requirements'
      ]);
      flagsCreated.push({ type: 'repeated_missing_scans', userId: row.user_id, value: row.count });
    }
    
    const lateAcceptanceSites = await pool.query(`
      SELECT s.site_id, s.tenant_id, COUNT(*) as count
      FROM ops_incidents i
      JOIN ops_sites s ON i.site_id = s.site_id
      WHERE i.type = 'acceptance_overdue'
        AND i.created_at > NOW() - INTERVAL '${evaluationDays} days'
      GROUP BY s.site_id, s.tenant_id
      HAVING COUNT(*) >= $1
    `, [TRAINING_THRESHOLDS.lateAcceptanceCount]);
    
    for (const row of lateAcceptanceSites.rows) {
      const flagId = generateId('FLAG');
      await pool.query(`
        INSERT INTO training_flags (flag_id, tenant_id, site_id, flag_type, trigger_value, threshold_value,
                                     evaluation_period_days, recommended_action)
        VALUES ($1, $2, $3, 'repeated_late_acceptance', $4, $5, $6, $7)
        ON CONFLICT DO NOTHING
      `, [
        flagId, row.tenant_id, row.site_id, row.count, TRAINING_THRESHOLDS.lateAcceptanceCount,
        evaluationDays, 'Review delivery acceptance process with partner'
      ]);
      flagsCreated.push({ type: 'repeated_late_acceptance', siteId: row.site_id, value: row.count });
    }
    
    res.json({ 
      evaluated: true, 
      evaluationDays,
      flagsCreated: flagsCreated.length,
      flags: flagsCreated 
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/training-flags/:flagId/resolve', opsAuth, async (req, res) => {
  const pool = getPool();
  const { flagId } = req.params;
  const { resolvedBy, notes } = req.body;
  
  try {
    await pool.query(`
      UPDATE training_flags SET 
        status = 'resolved',
        resolved_at = NOW(),
        resolved_by = $2
      WHERE flag_id = $1
    `, [flagId, resolvedBy]);
    
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/summary', opsAuth, async (req, res) => {
  const pool = getPool();
  
  try {
    const sites = await pool.query(`
      SELECT COUNT(*) FILTER (WHERE status = 'live') as live,
             COUNT(*) FILTER (WHERE status = 'onboarding') as onboarding,
             COUNT(*) as total
      FROM ops_sites
    `);
    
    let weeklyRefills = { scheduled: 0, completed: 0 };
    try {
      const refills = await pool.query(`
        SELECT COUNT(*) as scheduled,
               COUNT(*) FILTER (WHERE status = 'completed') as completed
        FROM ops_weekly_tasks
        WHERE week_start >= DATE_TRUNC('week', CURRENT_DATE)
          AND task_type = 'weekly'
      `);
      weeklyRefills = refills.rows[0];
    } catch (e) { }
    
    let deliveries = { total: 0, accepted: 0, refused: 0, pending: 0 };
    try {
      const del = await pool.query(`
        SELECT COUNT(*) as total,
               COUNT(*) FILTER (WHERE accepted_at IS NOT NULL) as accepted,
               COUNT(*) FILTER (WHERE status = 'refused') as refused,
               COUNT(*) FILTER (WHERE accepted_at IS NULL AND status = 'delivered') as pending
        FROM ops_delivery_records
        WHERE created_at > NOW() - INTERVAL '7 days'
      `);
      deliveries = del.rows[0];
    } catch (e) { }
    
    let incidents = { open: 0, critical: 0, resolvedToday: 0 };
    try {
      const inc = await pool.query(`
        SELECT COUNT(*) FILTER (WHERE status IN ('open', 'in_progress')) as open,
               COUNT(*) FILTER (WHERE status IN ('open', 'in_progress') AND severity = 'critical') as critical,
               COUNT(*) FILTER (WHERE status = 'resolved' AND resolved_at > CURRENT_DATE) as resolved_today
        FROM ops_incidents
      `);
      incidents = inc.rows[0];
    } catch (e) { }
    
    let trainingFlags = 0;
    try {
      const flags = await pool.query(`SELECT COUNT(*) as count FROM training_flags WHERE status = 'open'`);
      trainingFlags = parseInt(flags.rows[0]?.count || 0);
    } catch (e) { }
    
    res.json({
      summary: {
        sites: sites.rows[0],
        weeklyRefills,
        deliveries,
        incidents,
        trainingFlags
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
