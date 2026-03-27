import { getPool } from './db.js';

const TENANT_SCOPED_TABLES = [
  'ops_sites',
  'ops_shipments', 
  'ops_shipment_boxes',
  'ops_delivery_records',
  'ops_packing_logs',
  'ops_incidents',
  'ops_weekly_tasks',
  'ops_weekly_submissions',
  'ops_escalations',
  'ops_sla_trackers',
  'events',
  'workflow_sessions',
  'attachments',
  'photos',
  'user_site_assignments',
  'go_live_certificates',
  'go_live_dry_run_checks',
  'weekly_kpi_snapshots',
  'weekly_cadence_plans',
  'weekly_work_items',
  'landlord_digests',
  'zone_par_targets',
  'refill_counts',
  'shipment_proposals',
  'qc_gate_events',
  'box_contents_snapshot',
  'box_scan_custody',
  'evidence_completeness',
  'correction_events',
  'training_flags',
  'ops_incident_assignments'
];

export async function setTenantContext(tenantId) {
  const pool = getPool();
  if (!tenantId) {
    return null;
  }
  
  const client = await pool.connect();
  try {
    await client.query(`SET LOCAL app.tenant_id = $1`, [tenantId]);
    return client;
  } catch (e) {
    client.release();
    throw e;
  }
}

export async function withTenantContext(tenantId, operation) {
  const pool = getPool();
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    if (tenantId) {
      await client.query(`SET LOCAL app.tenant_id = $1`, [tenantId]);
    }
    
    const result = await operation(client);
    
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

export async function logSecurityEvent(eventType, details) {
  const pool = getPool();
  try {
    await pool.query(`
      INSERT INTO security_events (
        event_id, event_type, user_id, tenant_id, endpoint, action,
        target_table, success, metadata, created_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()
      )
    `, [
      `SEC-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      eventType,
      details.userId || null,
      details.tenantId || null,
      details.endpoint || null,
      details.action || null,
      details.table || null,
      details.success !== false,
      JSON.stringify(details.metadata || {})
    ]);
  } catch (e) {
    console.error('[RLS] Failed to log security event:', e.message);
  }
}

export async function logTenantDeny(details) {
  await logSecurityEvent('RLS_DENY', {
    ...details,
    success: false,
    metadata: {
      ...details.metadata,
      reason: details.reason || 'tenant_context_missing_or_invalid'
    }
  });
}

export function extractTenantFromRequest(req) {
  return req.headers['x-tenant-id'] || 
         req.body?.tenantId || 
         req.query?.tenantId ||
         null;
}

export function tenantMiddleware(options = {}) {
  const { requireTenant = false, allowedRoles = null } = options;
  
  return async (req, res, next) => {
    const tenantId = extractTenantFromRequest(req);
    const userRole = req.headers['x-user-role'];
    const userId = req.headers['x-user-id'];
    
    req.tenantContext = {
      tenantId,
      role: userRole,
      userId
    };
    
    if (requireTenant && !tenantId) {
      await logTenantDeny({
        userId,
        endpoint: req.path,
        action: req.method,
        reason: 'tenant_context_required_but_missing'
      });
      
      return res.status(403).json({
        error: 'Tenant context required',
        code: 'TENANT_REQUIRED'
      });
    }
    
    if (allowedRoles && !allowedRoles.includes(userRole)) {
      await logTenantDeny({
        userId,
        tenantId,
        endpoint: req.path,
        action: req.method,
        reason: 'role_not_permitted'
      });
      
      return res.status(403).json({
        error: 'Access denied for role',
        code: 'ROLE_DENIED'
      });
    }
    
    next();
  };
}

export async function setupRLSPolicies() {
  const pool = getPool();
  const client = await pool.connect();
  
  console.log('[RLS] Setting up Row Level Security policies...');
  
  try {
    await client.query(`
      CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS TEXT AS $func$
      BEGIN
        RETURN NULLIF(current_setting('app.tenant_id', TRUE), '');
      END;
      $func$ LANGUAGE plpgsql STABLE;
    `);
    
    for (const table of TENANT_SCOPED_TABLES) {
      try {
        const tableExists = await client.query(`
          SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = $1
          )
        `, [table]);
        
        if (!tableExists.rows[0].exists) {
          continue;
        }
        
        const colExists = await client.query(`
          SELECT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_name = $1 AND column_name = 'tenant_id'
          )
        `, [table]);
        
        if (!colExists.rows[0].exists) {
          continue;
        }
        
        await client.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);
        
        await client.query(`DROP POLICY IF EXISTS tenant_isolation ON ${table}`);
        await client.query(`
          CREATE POLICY tenant_isolation ON ${table}
          FOR SELECT
          USING (
            tenant_id = current_tenant_id() 
            OR tenant_id IS NULL 
            OR current_tenant_id() IS NULL
          )
        `);
        await client.query(`DROP POLICY IF EXISTS tenant_isolation_insert ON ${table}`);
        await client.query(`
          CREATE POLICY tenant_isolation_insert ON ${table}
          FOR INSERT
          WITH CHECK (
            tenant_id = current_tenant_id() 
            OR tenant_id IS NULL 
            OR current_tenant_id() IS NULL
          )
        `);
        await client.query(`DROP POLICY IF EXISTS tenant_isolation_update ON ${table}`);
        await client.query(`
          CREATE POLICY tenant_isolation_update ON ${table}
          FOR UPDATE
          USING (
            tenant_id = current_tenant_id() 
            OR tenant_id IS NULL 
            OR current_tenant_id() IS NULL
          )
          WITH CHECK (
            tenant_id = current_tenant_id() 
            OR tenant_id IS NULL 
            OR current_tenant_id() IS NULL
          )
        `);
        
        console.log(`  [RLS] Policy applied to: ${table}`);
      } catch (e) {
        console.log(`  [RLS] Skipped ${table}:`, e.message);
      }
    }
    
    console.log('[RLS] Row Level Security setup complete!');
    return { success: true, tables: TENANT_SCOPED_TABLES };
  } catch (e) {
    console.error('[RLS] Setup failed:', e.message);
    return { success: false, error: e.message };
  } finally {
    client.release();
  }
}

export async function testCrossTenantAccess(tenantA, tenantB, table) {
  const pool = getPool();
  
  try {
    const results = await withTenantContext(tenantA, async (client) => {
      const result = await client.query(
        `SELECT COUNT(*) as count FROM ${table} WHERE tenant_id = $1`,
        [tenantB]
      );
      return result.rows[0].count;
    });
    
    return {
      crossTenantRowsVisible: parseInt(results) > 0,
      count: parseInt(results)
    };
  } catch (e) {
    return { error: e.message };
  }
}

export { TENANT_SCOPED_TABLES };
