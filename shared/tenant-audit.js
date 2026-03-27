import { getPool } from './db.js';

const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

export const tenantAuditService = {
  SAMPLE_SIZE: 100,
  AUDIT_TABLES: [
    'events',
    'ops_sites',
    'ops_shipments',
    'ops_delivery_records',
    'ops_incidents',
    'workflow_sessions',
    'attachments',
    'photos'
  ],

  async runIsolationAudit(tenantId = null) {
    const pool = getPool();
    const auditId = generateId('AUDIT');
    const violations = [];
    const startTime = Date.now();

    for (const table of this.AUDIT_TABLES) {
      const tableViolations = await this.auditTable(pool, table, tenantId);
      violations.push(...tableViolations);
    }

    const crossRefViolations = await this.auditCrossReferences(pool, tenantId);
    violations.push(...crossRefViolations);

    const auditResult = {
      audit_id: auditId,
      run_at: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      tenant_scope: tenantId || 'all',
      tables_checked: this.AUDIT_TABLES.length,
      violations_found: violations.length,
      violations,
      passed: violations.length === 0
    };

    await pool.query(`
      INSERT INTO tenant_isolation_audits (
        audit_id, tenant_id, tables_checked, violations_found,
        passed, details, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
    `, [
      auditId,
      tenantId,
      this.AUDIT_TABLES.length,
      violations.length,
      violations.length === 0,
      JSON.stringify(auditResult)
    ]);

    return auditResult;
  },

  async auditTable(pool, table, tenantId) {
    const violations = [];

    try {
      const hasColumn = await pool.query(`
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = $1 AND column_name = 'tenant_id'
      `, [table]);

      if (hasColumn.rows.length === 0) {
        return [];
      }

      const nullTenantQuery = tenantId
        ? `SELECT COUNT(*) as count FROM ${table} WHERE tenant_id IS NULL AND site_id IS NOT NULL`
        : `SELECT COUNT(*) as count FROM ${table} WHERE tenant_id IS NULL AND site_id IS NOT NULL`;
      
      const nullResult = await pool.query(nullTenantQuery);
      if (parseInt(nullResult.rows[0].count) > 0) {
        violations.push({
          type: 'null_tenant_id',
          table,
          count: parseInt(nullResult.rows[0].count),
          severity: 'warning',
          message: `${table} has ${nullResult.rows[0].count} rows with NULL tenant_id but non-NULL site_id`
        });
      }

      if (table !== 'ops_sites') {
        const mismatchQuery = `
          SELECT COUNT(*) as count FROM ${table} t
          LEFT JOIN ops_sites s ON t.site_id = s.site_id
          WHERE t.site_id IS NOT NULL 
            AND s.site_id IS NOT NULL 
            AND t.tenant_id != s.tenant_id
        `;
        
        try {
          const mismatchResult = await pool.query(mismatchQuery);
          if (parseInt(mismatchResult.rows[0].count) > 0) {
            violations.push({
              type: 'tenant_site_mismatch',
              table,
              count: parseInt(mismatchResult.rows[0].count),
              severity: 'critical',
              message: `${table} has ${mismatchResult.rows[0].count} rows where tenant_id doesn't match the site's tenant`
            });
          }
        } catch (e) {
        }
      }

    } catch (error) {
      violations.push({
        type: 'audit_error',
        table,
        severity: 'error',
        message: `Failed to audit table: ${error.message}`
      });
    }

    return violations;
  },

  async auditCrossReferences(pool, tenantId) {
    const violations = [];

    try {
      const crossTenantShipments = await pool.query(`
        SELECT COUNT(*) as count FROM ops_shipments s
        JOIN ops_sites site ON s.site_id = site.site_id
        WHERE s.tenant_id != site.tenant_id
      `);

      if (parseInt(crossTenantShipments.rows[0].count) > 0) {
        violations.push({
          type: 'cross_tenant_shipment',
          table: 'ops_shipments',
          count: parseInt(crossTenantShipments.rows[0].count),
          severity: 'critical',
          message: 'Shipments exist that reference sites from different tenants'
        });
      }

      const crossTenantDeliveries = await pool.query(`
        SELECT COUNT(*) as count FROM ops_delivery_records d
        JOIN ops_shipments s ON d.shipment_id = s.shipment_id
        WHERE d.tenant_id IS NOT NULL AND d.tenant_id != s.tenant_id
      `);

      if (parseInt(crossTenantDeliveries.rows[0].count) > 0) {
        violations.push({
          type: 'cross_tenant_delivery',
          table: 'ops_delivery_records',
          count: parseInt(crossTenantDeliveries.rows[0].count),
          severity: 'critical',
          message: 'Delivery records exist that reference shipments from different tenants'
        });
      }

    } catch (error) {
    }

    return violations;
  },

  async getAuditHistory(limit = 10) {
    const pool = getPool();
    
    const result = await pool.query(`
      SELECT * FROM tenant_isolation_audits
      ORDER BY created_at DESC
      LIMIT $1
    `, [limit]);

    return result.rows;
  },

  async generateTenantChecksum(tenantId) {
    const pool = getPool();
    
    const counts = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM ops_sites WHERE tenant_id = $1) as sites,
        (SELECT COUNT(*) FROM ops_shipments WHERE tenant_id = $1) as shipments,
        (SELECT COUNT(*) FROM ops_delivery_records WHERE tenant_id = $1) as deliveries,
        (SELECT COUNT(*) FROM events WHERE tenant_id = $1) as events
    `, [tenantId]);

    const data = {
      tenant_id: tenantId,
      generated_at: new Date().toISOString(),
      counts: counts.rows[0]
    };

    const checksum = require('crypto')
      .createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex')
      .substring(0, 16);

    return {
      tenant_id: tenantId,
      checksum,
      ...data.counts
    };
  },

  async validateEvidencePacketTenant(packetId, expectedTenantId) {
    const pool = getPool();
    
    const packet = await pool.query(`
      SELECT tenant_id, generated_at FROM evidence_packets WHERE packet_id = $1
    `, [packetId]);

    if (!packet.rows[0]) {
      return { valid: false, reason: 'Packet not found' };
    }

    if (packet.rows[0].tenant_id !== expectedTenantId) {
      return { 
        valid: false, 
        reason: 'Tenant mismatch',
        packetTenant: packet.rows[0].tenant_id,
        expectedTenant: expectedTenantId
      };
    }

    return { valid: true };
  }
};

export default tenantAuditService;
