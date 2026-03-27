import { getPool } from './db.js';

export const FEATURE_FLAGS = {
  OFFLINE_QUEUE_SLA: 'offline_queue_sla',
  A50_SQUEEZE_GATE: 'a50_squeeze_gate',
  CONSEQUENCE_ENGINE: 'consequence_engine',
  SAFE_MODE: 'safe_mode',
  RESTRICTED_MODE: 'restricted_mode',
  RECERT_GATES: 'recert_gates',
  TENANT_AUDIT: 'tenant_audit',
  ENHANCED_POD: 'enhanced_pod'
};

export const featureFlagService = {
  DEFAULT_FLAGS: {
    [FEATURE_FLAGS.OFFLINE_QUEUE_SLA]: false,
    [FEATURE_FLAGS.A50_SQUEEZE_GATE]: false,
    [FEATURE_FLAGS.CONSEQUENCE_ENGINE]: false,
    [FEATURE_FLAGS.SAFE_MODE]: false,
    [FEATURE_FLAGS.RESTRICTED_MODE]: false,
    [FEATURE_FLAGS.RECERT_GATES]: false,
    [FEATURE_FLAGS.TENANT_AUDIT]: true,
    [FEATURE_FLAGS.ENHANCED_POD]: false
  },

  async getFlag(flagName, tenantId = null, siteId = null) {
    const pool = getPool();
    
    if (siteId) {
      const siteFlag = await pool.query(`
        SELECT enabled FROM feature_flags 
        WHERE flag_name = $1 AND site_id = $2
      `, [flagName, siteId]);
      
      if (siteFlag.rows[0]) {
        return siteFlag.rows[0].enabled;
      }
    }

    if (tenantId) {
      const tenantFlag = await pool.query(`
        SELECT enabled FROM feature_flags 
        WHERE flag_name = $1 AND tenant_id = $2 AND site_id IS NULL
      `, [flagName, tenantId]);
      
      if (tenantFlag.rows[0]) {
        return tenantFlag.rows[0].enabled;
      }
    }

    const globalFlag = await pool.query(`
      SELECT enabled FROM feature_flags 
      WHERE flag_name = $1 AND tenant_id IS NULL AND site_id IS NULL
    `, [flagName]);
    
    if (globalFlag.rows[0]) {
      return globalFlag.rows[0].enabled;
    }

    return this.DEFAULT_FLAGS[flagName] ?? false;
  },

  async setFlag(flagName, enabled, tenantId = null, siteId = null, setBy = 'system') {
    const pool = getPool();
    
    // Check if flag exists
    const existingQuery = tenantId 
      ? (siteId 
        ? `SELECT id FROM feature_flags WHERE flag_name = $1 AND tenant_id = $2 AND site_id = $3`
        : `SELECT id FROM feature_flags WHERE flag_name = $1 AND tenant_id = $2 AND site_id IS NULL`)
      : (siteId
        ? `SELECT id FROM feature_flags WHERE flag_name = $1 AND tenant_id IS NULL AND site_id = $2`
        : `SELECT id FROM feature_flags WHERE flag_name = $1 AND tenant_id IS NULL AND site_id IS NULL`);
    
    const params = tenantId 
      ? (siteId ? [flagName, tenantId, siteId] : [flagName, tenantId])
      : (siteId ? [flagName, siteId] : [flagName]);
    
    const existing = await pool.query(existingQuery, params);
    
    if (existing.rows.length > 0) {
      await pool.query(`
        UPDATE feature_flags SET enabled = $1, updated_by = $2, updated_at = NOW() WHERE id = $3
      `, [enabled, setBy, existing.rows[0].id]);
    } else {
      await pool.query(`
        INSERT INTO feature_flags (flag_name, enabled, tenant_id, site_id, updated_by, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
      `, [flagName, enabled, tenantId, siteId, setBy]);
    }

    try {
      const actorId = parseInt(setBy);
      if (!isNaN(actorId)) {
        await pool.query(`
          INSERT INTO events (event_id, event_type, actor_user_id, tenant_id, site_id, payload_json, server_timestamp)
          VALUES ($1, $2, $3, $4, $5, $6, NOW())
        `, [
          `EVT-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
          'FEATURE_FLAG_CHANGED',
          actorId,
          tenantId,
          siteId,
          JSON.stringify({ flag_name: flagName, enabled, set_by: setBy })
        ]);
      }
    } catch (e) {
      console.log('Feature flag event logging skipped:', e.message);
    }

    return { flagName, enabled, tenantId, siteId };
  },

  async getAllFlags(tenantId = null, siteId = null) {
    const pool = getPool();
    const flags = { ...this.DEFAULT_FLAGS };

    const globalFlags = await pool.query(`
      SELECT flag_name, enabled FROM feature_flags 
      WHERE tenant_id IS NULL AND site_id IS NULL
    `);
    
    for (const row of globalFlags.rows) {
      flags[row.flag_name] = row.enabled;
    }

    if (tenantId) {
      const tenantFlags = await pool.query(`
        SELECT flag_name, enabled FROM feature_flags 
        WHERE tenant_id = $1 AND site_id IS NULL
      `, [tenantId]);
      
      for (const row of tenantFlags.rows) {
        flags[row.flag_name] = row.enabled;
      }
    }

    if (siteId) {
      const siteFlags = await pool.query(`
        SELECT flag_name, enabled FROM feature_flags 
        WHERE site_id = $1
      `, [siteId]);
      
      for (const row of siteFlags.rows) {
        flags[row.flag_name] = row.enabled;
      }
    }

    return flags;
  },

  async isEnabled(flagName, context = {}) {
    const { tenantId, siteId } = context;
    return this.getFlag(flagName, tenantId, siteId);
  },

  async getRolloutStatus() {
    const pool = getPool();
    
    const result = await pool.query(`
      SELECT 
        flag_name,
        COUNT(DISTINCT tenant_id) FILTER (WHERE tenant_id IS NOT NULL AND enabled = TRUE) as tenants_enabled,
        COUNT(DISTINCT site_id) FILTER (WHERE site_id IS NOT NULL AND enabled = TRUE) as sites_enabled,
        MAX(CASE WHEN tenant_id IS NULL AND site_id IS NULL AND enabled = TRUE THEN 1 ELSE 0 END) as global_enabled
      FROM feature_flags
      GROUP BY flag_name
    `);

    const status = {};
    for (const row of result.rows) {
      status[row.flag_name] = {
        globalEnabled: row.global_enabled === 1,
        tenantsEnabled: parseInt(row.tenants_enabled),
        sitesEnabled: parseInt(row.sites_enabled)
      };
    }

    for (const flagName of Object.keys(this.DEFAULT_FLAGS)) {
      if (!status[flagName]) {
        status[flagName] = {
          globalEnabled: this.DEFAULT_FLAGS[flagName],
          tenantsEnabled: 0,
          sitesEnabled: 0
        };
      }
    }

    return status;
  }
};

export default featureFlagService;
