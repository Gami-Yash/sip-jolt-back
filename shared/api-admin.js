import express from 'express';
import { getPool } from './db.js';
import { 
  sessionManager, 
  healthChecks, 
  featureFlagService,
  logSecurityEvent,
  paginatedResponse
} from './production-hardening.js';
import { evidencePacketService } from './services/ops.js';

const router = express.Router();

function requireOpsAdmin(req, res, next) {
  const userRole = req.headers['x-user-role'];
  if (userRole !== 'ops_manager' && userRole !== 'admin') {
    return res.status(403).json({ error: 'Ops-admin access required' });
  }
  next();
}

router.get('/health', async (req, res) => {
  try {
    const health = await healthChecks.all();
    const statusCode = health.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    res.status(500).json({ status: 'error', error: error.message });
  }
});

router.get('/status', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    
    const systemStatus = await pool.query(
      `SELECT * FROM system_status ORDER BY last_check_at DESC LIMIT 1`
    );
    
    const errorRate = await pool.query(`
      SELECT COUNT(*) as count FROM failure_log 
      WHERE created_at > NOW() - INTERVAL '1 hour'
    `);
    
    const denyCount = await pool.query(`
      SELECT COUNT(*) as count FROM security_deny_log 
      WHERE created_at > NOW() - INTERVAL '1 hour'
    `);
    
    const activeUsers = await pool.query(`
      SELECT COUNT(DISTINCT user_id) as count FROM auth_sessions 
      WHERE last_activity_at > NOW() - INTERVAL '15 minutes'
    `);
    
    res.json({
      deployVersion: process.env.REPL_SLUG || 'development',
      deployedAt: systemStatus.rows[0]?.deployed_at || new Date().toISOString(),
      healthStatus: (await healthChecks.all()).status,
      errorRate1h: parseInt(errorRate.rows[0]?.count || 0),
      securityDenies1h: parseInt(denyCount.rows[0]?.count || 0),
      activeUsers: parseInt(activeUsers.rows[0]?.count || 0),
      featureFlags: featureFlagService.getAllFlags(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching system status:', error);
    res.status(500).json({ error: 'Failed to fetch system status' });
  }
});

router.get('/failures', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const { tenantId, siteId, userId, limit = 50 } = req.query;
    
    let query = `SELECT * FROM failure_log WHERE 1=1`;
    const params = [];
    
    if (tenantId) {
      params.push(tenantId);
      query += ` AND tenant_id = $${params.length}`;
    }
    if (siteId) {
      params.push(siteId);
      query += ` AND site_id = $${params.length}`;
    }
    if (userId) {
      params.push(userId);
      query += ` AND user_id = $${params.length}`;
    }
    
    params.push(Math.min(200, parseInt(limit)));
    query += ` ORDER BY created_at DESC LIMIT $${params.length}`;
    
    const result = await pool.query(query, params);
    
    res.json({ 
      failures: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error('Error fetching failures:', error);
    res.status(500).json({ error: 'Failed to fetch failures' });
  }
});

router.get('/security-denies', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const { denyType, tenantId, limit = 50 } = req.query;
    
    let query = `SELECT * FROM security_deny_log WHERE 1=1`;
    const params = [];
    
    if (denyType) {
      params.push(denyType);
      query += ` AND deny_type = $${params.length}`;
    }
    if (tenantId) {
      params.push(tenantId);
      query += ` AND tenant_id = $${params.length}`;
    }
    
    params.push(Math.min(200, parseInt(limit)));
    query += ` ORDER BY created_at DESC LIMIT $${params.length}`;
    
    const result = await pool.query(query, params);
    
    res.json({ 
      denies: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error('Error fetching security denies:', error);
    res.status(500).json({ error: 'Failed to fetch security denies' });
  }
});

router.get('/evidence-completeness', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const { siteId, weekStart } = req.query;
    
    let query = `SELECT ec.*, os.venue_name 
                 FROM evidence_completeness ec
                 LEFT JOIN ops_sites os ON ec.site_id = os.site_id
                 WHERE 1=1`;
    const params = [];
    
    if (siteId) {
      params.push(siteId);
      query += ` AND ec.site_id = $${params.length}`;
    }
    if (weekStart) {
      params.push(weekStart);
      query += ` AND ec.week_start = $${params.length}`;
    }
    
    query += ` ORDER BY ec.week_start DESC, ec.completeness_rate ASC LIMIT 100`;
    
    const result = await pool.query(query, params);
    
    res.json({ completeness: result.rows });
  } catch (error) {
    console.error('Error fetching evidence completeness:', error);
    res.status(500).json({ error: 'Failed to fetch evidence completeness' });
  }
});

router.post('/compute-evidence-completeness', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const { siteId, weekStart } = req.body;
    
    if (!siteId || !weekStart) {
      return res.status(400).json({ error: 'siteId and weekStart required' });
    }
    
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekEnd.getDate() + 7);
    
    const site = await pool.query(`SELECT * FROM ops_sites WHERE site_id = $1`, [siteId]);
    if (!site.rows[0]) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const submissions = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE verification_status = 'verified') as verified
      FROM ops_weekly_submissions
      WHERE site_id = $1 AND submitted_at >= $2 AND submitted_at < $3
    `, [siteId, weekStart, weekEnd]);
    
    const deliveries = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE pod_photo IS NOT NULL) as with_proof
      FROM ops_delivery_records
      WHERE site_id = $1 AND delivered_at >= $2 AND delivered_at < $3
    `, [siteId, weekStart, weekEnd]);
    
    const totalRequired = parseInt(submissions.rows[0]?.total || 0) + parseInt(deliveries.rows[0]?.total || 0);
    const totalSubmitted = parseInt(submissions.rows[0]?.total || 0) + parseInt(deliveries.rows[0]?.with_proof || 0);
    const totalVerified = parseInt(submissions.rows[0]?.verified || 0) + parseInt(deliveries.rows[0]?.with_proof || 0);
    const completenessRate = totalRequired > 0 ? (totalVerified / totalRequired) * 100 : 100;
    
    const completenessId = `COMP-${Date.now().toString(36).toUpperCase()}`;
    
    await pool.query(`
      INSERT INTO evidence_completeness 
        (completeness_id, tenant_id, site_id, week_start, total_required, total_submitted, total_verified, completeness_rate)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (site_id, week_start) DO UPDATE SET
        total_required = EXCLUDED.total_required,
        total_submitted = EXCLUDED.total_submitted,
        total_verified = EXCLUDED.total_verified,
        completeness_rate = EXCLUDED.completeness_rate,
        computed_at = NOW()
    `, [completenessId, site.rows[0].tenant_id, siteId, weekStart, totalRequired, totalSubmitted, totalVerified, completenessRate]);
    
    res.json({
      siteId,
      weekStart,
      totalRequired,
      totalSubmitted,
      totalVerified,
      completenessRate: completenessRate.toFixed(2) + '%'
    });
  } catch (error) {
    console.error('Error computing evidence completeness:', error);
    res.status(500).json({ error: 'Failed to compute evidence completeness' });
  }
});

router.post('/generate-evidence-packet', requireOpsAdmin, async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const { entityType, entityId } = req.body;
    
    if (!entityType || !entityId) {
      return res.status(400).json({ error: 'entityType and entityId required' });
    }
    
    const packet = await evidencePacketService.generate(entityType, entityId, userId);
    
    if (!packet) {
      return res.status(404).json({ error: 'Entity not found' });
    }
    
    await logSecurityEvent('EVIDENCE_PACKET_GENERATED', userId, { entityType, entityId });
    
    res.json({ packet, message: 'Evidence packet generated' });
  } catch (error) {
    console.error('Error generating evidence packet:', error);
    res.status(500).json({ error: 'Failed to generate evidence packet' });
  }
});

router.post('/sessions/revoke-user', requireOpsAdmin, async (req, res) => {
  try {
    const adminId = req.headers['x-user-id'];
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId required' });
    }
    
    const result = await sessionManager.revokeUserSessions(userId, adminId);
    res.json({ message: `Revoked ${result.revokedCount} sessions for user ${userId}` });
  } catch (error) {
    console.error('Error revoking user sessions:', error);
    res.status(500).json({ error: 'Failed to revoke sessions' });
  }
});

router.post('/sessions/kill-all', requireOpsAdmin, async (req, res) => {
  try {
    const adminId = req.headers['x-user-id'];
    const { exceptCurrent } = req.body;
    
    const currentSession = req.headers['x-session-token'];
    const result = await sessionManager.killAllSessions(
      exceptCurrent ? currentSession : null, 
      adminId
    );
    
    res.json({ message: `Killed ${result.killedCount} sessions` });
  } catch (error) {
    console.error('Error killing sessions:', error);
    res.status(500).json({ error: 'Failed to kill sessions' });
  }
});

router.get('/sessions/:userId', requireOpsAdmin, async (req, res) => {
  try {
    const sessions = await sessionManager.getActiveSessions(req.params.userId);
    res.json({ sessions });
  } catch (error) {
    console.error('Error fetching sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

router.get('/feature-flags', requireOpsAdmin, async (req, res) => {
  res.json({ flags: featureFlagService.getAllFlags() });
});

router.post('/feature-flags/:flagName', requireOpsAdmin, async (req, res) => {
  try {
    const { enabled } = req.body;
    const adminId = req.headers['x-user-id'];
    
    featureFlagService.setFlag(req.params.flagName, enabled);
    
    await logSecurityEvent('FEATURE_FLAG_CHANGED', adminId, {
      flag: req.params.flagName,
      enabled
    });
    
    res.json({ 
      flag: req.params.flagName, 
      enabled,
      message: 'Feature flag updated' 
    });
  } catch (error) {
    console.error('Error updating feature flag:', error);
    res.status(500).json({ error: 'Failed to update feature flag' });
  }
});

router.get('/retention-policies', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const result = await pool.query(`SELECT * FROM data_retention_policy ORDER BY entity_type`);
    res.json({ policies: result.rows });
  } catch (error) {
    console.error('Error fetching retention policies:', error);
    res.status(500).json({ error: 'Failed to fetch retention policies' });
  }
});

// =========== USER MANAGEMENT ROUTES (v1.00) ===========

const generateId = (prefix) => `${prefix}-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

const logUserMgmtEvent = async (pool, eventType, actorId, targetUserId, payload) => {
  try {
    await pool.query(`
      INSERT INTO events (event_id, event_type, actor_user_id, payload_json, server_timestamp)
      VALUES ($1, $2, $3, $4, NOW())
    `, [
      generateId('EVT'),
      eventType,
      actorId,
      JSON.stringify({ ...payload, target_user_id: targetUserId })
    ]);
  } catch (e) {
    console.error('Failed to log user mgmt event:', e.message);
  }
};

router.get('/users', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const tenantId = req.headers['x-tenant-id'] || 'JOLT_INTERNAL';
    
    const result = await pool.query(`
      SELECT 
        u.id, u.employee_code, u.name, u.email, u.status, u.role,
        u.reliability_score, u.assigned_route, u.restricted_mode,
        u.created_at, u.last_login_at,
        COALESCE(
          (SELECT json_agg(usa.site_id) FROM user_site_assignments usa WHERE usa.user_id = u.id),
          '[]'
        ) as site_assignments
      FROM jolt_users u
      WHERE u.tenant_id = $1 OR u.tenant_id IS NULL OR $1 = 'JOLT_INTERNAL'
      ORDER BY u.created_at DESC
    `, [tenantId]);
    
    res.json({ users: result.rows });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/users/:id', requireOpsAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const pool = getPool();
    
    const result = await pool.query(`
      SELECT 
        u.*, 
        COALESCE(
          (SELECT json_agg(json_build_object('site_id', usa.site_id, 'role', usa.role)) 
           FROM user_site_assignments usa WHERE usa.user_id = u.id),
          '[]'
        ) as site_assignments
      FROM jolt_users u
      WHERE u.id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.put('/users/:id/role', requireOpsAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    const pool = getPool();
    const actorId = req.headers['x-user-id'];
    
    const validRoles = ['PARTNER_TECHNICIAN', 'TECHNICIAN', 'DRIVER', 'OPS_MANAGER', 'LANDLORD_VIEWER'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
    }
    
    const oldUser = await pool.query('SELECT role FROM jolt_users WHERE id = $1', [id]);
    const oldRole = oldUser.rows[0]?.role;
    
    await pool.query(`
      UPDATE jolt_users SET role = $1, updated_at = NOW() WHERE id = $2
    `, [role, id]);
    
    await logUserMgmtEvent(pool, 'USER_ROLE_CHANGED', actorId, id, {
      old_role: oldRole,
      new_role: role
    });
    
    res.json({ success: true, message: `User role updated to ${role}` });
  } catch (error) {
    console.error('Update role error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/assign-site', requireOpsAdmin, async (req, res) => {
  try {
    const { userId, siteId, role } = req.body;
    const pool = getPool();
    const actorId = req.headers['x-user-id'];
    const tenantId = req.headers['x-tenant-id'] || 'JOLT_INTERNAL';
    
    if (!userId || !siteId) {
      return res.status(400).json({ error: 'userId and siteId required' });
    }
    
    await pool.query(`
      INSERT INTO user_site_assignments (user_id, site_id, role, tenant_id, assigned_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (user_id, site_id) DO UPDATE SET role = $3, assigned_at = NOW()
    `, [userId, siteId, role || 'PARTNER_TECHNICIAN', tenantId]);
    
    await logUserMgmtEvent(pool, 'USER_SITE_ASSIGNED', actorId, userId, {
      site_id: siteId,
      role: role || 'PARTNER_TECHNICIAN'
    });
    
    res.json({ success: true, message: `User assigned to site ${siteId}` });
  } catch (error) {
    console.error('Assign site error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/unassign-site', requireOpsAdmin, async (req, res) => {
  try {
    const { userId, siteId } = req.body;
    const pool = getPool();
    const actorId = req.headers['x-user-id'];
    
    if (!userId || !siteId) {
      return res.status(400).json({ error: 'userId and siteId required' });
    }
    
    await pool.query(`
      DELETE FROM user_site_assignments WHERE user_id = $1 AND site_id = $2
    `, [userId, siteId]);
    
    await logUserMgmtEvent(pool, 'USER_SITE_UNASSIGNED', actorId, userId, {
      site_id: siteId
    });
    
    res.json({ success: true, message: `User unassigned from site ${siteId}` });
  } catch (error) {
    console.error('Unassign site error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.put('/users/:id/reliability', requireOpsAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reliabilityScore, reason } = req.body;
    const pool = getPool();
    const actorId = req.headers['x-user-id'];
    
    if (typeof reliabilityScore !== 'number' || reliabilityScore < 0 || reliabilityScore > 100) {
      return res.status(400).json({ error: 'Reliability score must be between 0 and 100' });
    }
    
    const oldUser = await pool.query('SELECT reliability_score FROM jolt_users WHERE id = $1', [id]);
    const oldScore = oldUser.rows[0]?.reliability_score;
    
    await pool.query(`
      UPDATE jolt_users SET reliability_score = $1, updated_at = NOW() WHERE id = $2
    `, [reliabilityScore, id]);
    
    await logUserMgmtEvent(pool, 'USER_RELIABILITY_UPDATED', actorId, id, {
      old_score: oldScore,
      new_score: reliabilityScore,
      reason
    });
    
    res.json({ success: true, message: 'Reliability score updated' });
  } catch (error) {
    console.error('Update reliability error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/users/:id/clear-restricted', requireOpsAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    const pool = getPool();
    const actorId = req.headers['x-user-id'];
    
    await pool.query(`
      UPDATE jolt_users 
      SET restricted_mode = FALSE, 
          restricted_mode_cleared_by = $1,
          restricted_mode_cleared_at = NOW(),
          updated_at = NOW()
      WHERE id = $2
    `, [actorId, id]);
    
    await logUserMgmtEvent(pool, 'USER_RESTRICTED_CLEARED', actorId, id, { reason });
    
    res.json({ success: true, message: 'Restricted mode cleared' });
  } catch (error) {
    console.error('Clear restricted error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/user-audit-log', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const { limit = 50, offset = 0 } = req.query;
    
    const result = await pool.query(`
      SELECT e.*, u.name as actor_name
      FROM events e
      LEFT JOIN jolt_users u ON e.actor_user_id::text = u.id::text
      WHERE e.event_type LIKE 'USER_%'
      ORDER BY e.server_timestamp DESC
      LIMIT $1 OFFSET $2
    `, [parseInt(limit), parseInt(offset)]);
    
    res.json({ events: result.rows });
  } catch (error) {
    console.error('Audit log error:', error);
    res.status(500).json({ error: error.message });
  }
});

// =========== END USER MANAGEMENT ===========

router.post('/seed-test-tenants', requireOpsAdmin, async (req, res) => {
  try {
    const pool = getPool();
    const adminId = req.headers['x-user-id'];
    
    const tenant1Id = 'TEST_TENANT_ALPHA';
    const tenant2Id = 'TEST_TENANT_BETA';
    
    await pool.query(`
      INSERT INTO tenants (tenant_id, name) VALUES
        ($1, 'Test Coffee Co Alpha'),
        ($2, 'Test Coffee Co Beta')
      ON CONFLICT (tenant_id) DO NOTHING
    `, [tenant1Id, tenant2Id]);
    
    await pool.query(`
      INSERT INTO ops_sites (site_id, tenant_id, venue_name, address, status) VALUES
        ('SITE_MAIN_ALPHA', $1, 'Main Street Coffee', '123 Main St', 'active'),
        ('SITE_MAIN_BETA', $2, 'Main Street Coffee', '124 Main St', 'active'),
        ('SITE_DOWNTOWN_ALPHA', $1, 'Downtown Cafe', '456 Downtown Ave', 'active'),
        ('SITE_DOWNTOWN_BETA', $2, 'Downtown Cafe', '457 Downtown Ave', 'active')
      ON CONFLICT (site_id) DO NOTHING
    `, [tenant1Id, tenant2Id]);
    
    await logSecurityEvent('TEST_TENANTS_SEEDED', adminId, { tenant1Id, tenant2Id });
    
    res.json({ 
      message: 'Test tenants seeded with similar site names',
      tenants: [
        { tenantId: tenant1Id, sites: ['SITE_MAIN_ALPHA', 'SITE_DOWNTOWN_ALPHA'] },
        { tenantId: tenant2Id, sites: ['SITE_MAIN_BETA', 'SITE_DOWNTOWN_BETA'] }
      ]
    });
  } catch (error) {
    console.error('Error seeding test tenants:', error);
    res.status(500).json({ error: 'Failed to seed test tenants' });
  }
});

export default router;
