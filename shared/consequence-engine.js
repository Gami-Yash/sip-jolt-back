import { getPool } from './db.js';

const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

export const CONSEQUENCE_EVENT_TYPES = {
  A50_TEST_PASSED: 'A50_TEST_PASSED',
  A50_TEST_FAILED: 'A50_TEST_FAILED',
  SAFE_MODE_ENTER: 'SAFE_MODE_ENTER',
  SAFE_MODE_EXIT: 'SAFE_MODE_EXIT',
  RESTRICTED_MODE_ON: 'RESTRICTED_MODE_ON',
  RESTRICTED_MODE_OFF: 'RESTRICTED_MODE_OFF',
  RECERT_REQUIRED: 'RECERT_REQUIRED',
  RECERT_COMPLETE: 'RECERT_COMPLETE',
  SYNC_SLA_BREACH: 'SYNC_SLA_BREACH',
  PHOTO_SYNCED: 'PHOTO_SYNCED'
};

export const consequenceEngineService = {
  SAFE_MODE_CONSECUTIVE_FAILS: 2,
  SAFE_MODE_DURATION_DAYS: 30,
  RESTRICTED_MODE_ACCEPTANCE_HOURS: 24,
  SYNC_SLA_HOURS: 6,
  RECERT_PROOF_REJECTION_THRESHOLD: 3,

  async logConsequenceEvent(eventType, data) {
    const pool = getPool();
    const eventId = generateId('EVT');
    
    try {
      const actorId = data.actor_id ? parseInt(data.actor_id) : null;
      const validActorId = actorId && !isNaN(actorId) ? actorId : 1;
      
      await pool.query(`
        INSERT INTO events (
          event_id, event_type, tenant_id, site_id, machine_id, actor_user_id, actor_role,
          device_id, server_timestamp, gps_lat, gps_lng, evidence_links, payload_json
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9, $10, $11, $12)
      `, [
        eventId,
        eventType,
        data.tenant_id || null,
        data.site_id || null,
        data.machine_id || null,
        validActorId,
        data.actor_role || 'system',
        data.device_id || null,
        data.gps_lat || null,
        data.gps_lng || null,
        JSON.stringify(data.evidence_links || []),
        JSON.stringify(data.metadata || {})
      ]);
    } catch (e) {
      console.log('Consequence event logging note:', e.message);
    }
    
    return eventId;
  },

  async getMachineA50History(machineId, limit = 10) {
    const pool = getPool();
    const result = await pool.query(`
      SELECT * FROM a50_test_results
      WHERE machine_id = $1
      ORDER BY tested_at DESC
      LIMIT $2
    `, [machineId, limit]);
    return result.rows;
  },

  async recordA50Test(machineId, testerId, passed, proofUrl, metadata = {}) {
    const pool = getPool();
    const testId = generateId('A50');
    
    await pool.query(`
      INSERT INTO a50_test_results (
        test_id, machine_id, tester_id, passed, proof_url, timer_duration_sec,
        test_instructions_followed, metadata, tested_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    `, [
      testId,
      machineId,
      testerId,
      passed,
      proofUrl,
      metadata.timer_duration || 60,
      metadata.instructions_followed !== false,
      JSON.stringify(metadata)
    ]);

    await this.logConsequenceEvent(
      passed ? CONSEQUENCE_EVENT_TYPES.A50_TEST_PASSED : CONSEQUENCE_EVENT_TYPES.A50_TEST_FAILED,
      {
        machine_id: machineId,
        actor_id: testerId,
        evidence_links: [proofUrl],
        metadata: { test_id: testId, ...metadata }
      }
    );

    if (!passed) {
      await this.checkSafeModeEntry(machineId);
    } else {
      await this.checkSafeModeExit(machineId);
    }

    return testId;
  },

  async checkSafeModeEntry(machineId) {
    const pool = getPool();
    
    const recent = await pool.query(`
      SELECT passed FROM a50_test_results
      WHERE machine_id = $1
      ORDER BY tested_at DESC
      LIMIT $2
    `, [machineId, this.SAFE_MODE_CONSECUTIVE_FAILS]);

    const results = recent.rows;
    if (results.length >= this.SAFE_MODE_CONSECUTIVE_FAILS) {
      const allFailed = results.every(r => !r.passed);
      if (allFailed) {
        await this.enterSafeMode(machineId);
        return true;
      }
    }
    return false;
  },

  async checkSafeModeExit(machineId) {
    const pool = getPool();
    
    const machine = await pool.query(
      `SELECT safe_mode, safe_mode_entered_at FROM machines WHERE machine_id = $1`,
      [machineId]
    );
    
    if (!machine.rows[0]?.safe_mode) return false;

    const recent = await pool.query(`
      SELECT passed FROM a50_test_results
      WHERE machine_id = $1 AND tested_at > $2
      ORDER BY tested_at DESC
      LIMIT 3
    `, [machineId, machine.rows[0].safe_mode_entered_at]);

    if (recent.rows.length >= 3 && recent.rows.every(r => r.passed)) {
      await this.exitSafeMode(machineId);
      return true;
    }
    return false;
  },

  async enterSafeMode(machineId) {
    const pool = getPool();
    
    await pool.query(`
      UPDATE machines SET 
        safe_mode = TRUE,
        safe_mode_entered_at = NOW(),
        safe_mode_exit_date = NOW() + INTERVAL '${this.SAFE_MODE_DURATION_DAYS} days'
      WHERE machine_id = $1
    `, [machineId]);

    await this.logConsequenceEvent(CONSEQUENCE_EVENT_TYPES.SAFE_MODE_ENTER, {
      machine_id: machineId,
      metadata: { duration_days: this.SAFE_MODE_DURATION_DAYS }
    });

    const incidentId = generateId('INC');
    await pool.query(`
      INSERT INTO ops_incidents (
        incident_id, type, severity, title, description, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
    `, [
      incidentId,
      'safe_mode_entry',
      'high',
      `Machine ${machineId} entered Safe Mode`,
      `Machine has ${this.SAFE_MODE_CONSECUTIVE_FAILS} consecutive A50 test failures. Safe mode enabled for ${this.SAFE_MODE_DURATION_DAYS} days.`,
      'open'
    ]);

    return incidentId;
  },

  async exitSafeMode(machineId) {
    const pool = getPool();
    
    await pool.query(`
      UPDATE machines SET 
        safe_mode = FALSE,
        safe_mode_exited_at = NOW()
      WHERE machine_id = $1
    `, [machineId]);

    await this.logConsequenceEvent(CONSEQUENCE_EVENT_TYPES.SAFE_MODE_EXIT, {
      machine_id: machineId,
      metadata: { exit_reason: 'consecutive_passes' }
    });
  },

  async enterRestrictedMode(userId, reason) {
    const pool = getPool();
    
    await pool.query(`
      UPDATE jolt_users SET 
        restricted_mode = TRUE,
        restricted_mode_reason = $2,
        restricted_mode_entered_at = NOW()
      WHERE user_id = $1
    `, [userId, reason]);

    await this.logConsequenceEvent(CONSEQUENCE_EVENT_TYPES.RESTRICTED_MODE_ON, {
      actor_id: userId,
      metadata: { reason }
    });

    return true;
  },

  async exitRestrictedMode(userId, clearedBy) {
    const pool = getPool();
    
    await pool.query(`
      UPDATE jolt_users SET 
        restricted_mode = FALSE,
        restricted_mode_reason = NULL,
        restricted_mode_cleared_by = $2,
        restricted_mode_cleared_at = NOW()
      WHERE user_id = $1
    `, [userId, clearedBy]);

    await this.logConsequenceEvent(CONSEQUENCE_EVENT_TYPES.RESTRICTED_MODE_OFF, {
      actor_id: userId,
      metadata: { cleared_by: clearedBy }
    });

    return true;
  },

  async checkRecertRequired(userId) {
    const pool = getPool();
    
    const rejections = await pool.query(`
      SELECT COUNT(*) as count FROM events
      WHERE actor_user_id = $1 
        AND event_type = 'PROOF_REJECTED'
        AND server_timestamp > NOW() - INTERVAL '30 days'
    `, [userId]);

    if (parseInt(rejections.rows[0].count) >= this.RECERT_PROOF_REJECTION_THRESHOLD) {
      await this.requireRecert(userId, 'repeated_proof_rejections');
      return true;
    }
    return false;
  },

  async requireRecert(userId, reason) {
    const pool = getPool();
    
    await pool.query(`
      UPDATE jolt_users SET 
        recert_required = TRUE,
        recert_reason = $2,
        recert_required_at = NOW()
      WHERE user_id = $1
    `, [userId, reason]);

    await this.logConsequenceEvent(CONSEQUENCE_EVENT_TYPES.RECERT_REQUIRED, {
      actor_id: userId,
      metadata: { reason }
    });

    return true;
  },

  async completeRecert(userId, certifierId, certType) {
    const pool = getPool();
    
    await pool.query(`
      UPDATE jolt_users SET 
        recert_required = FALSE,
        recert_reason = NULL,
        last_recert_at = NOW(),
        last_recert_type = $2,
        last_recert_by = $3
      WHERE user_id = $1
    `, [userId, certType, certifierId]);

    await this.logConsequenceEvent(CONSEQUENCE_EVENT_TYPES.RECERT_COMPLETE, {
      actor_id: userId,
      metadata: { certified_by: certifierId, cert_type: certType }
    });

    return true;
  },

  async checkSyncSLA(queuedItems) {
    const now = Date.now();
    const slaBreaches = [];
    
    for (const item of queuedItems) {
      const createdAt = new Date(item.createdAt).getTime();
      const hoursSinceCreation = (now - createdAt) / (1000 * 60 * 60);
      
      if (hoursSinceCreation > this.SYNC_SLA_HOURS) {
        slaBreaches.push({
          itemId: item.id,
          type: item.type,
          hoursPending: Math.round(hoursSinceCreation * 10) / 10,
          createdAt: item.createdAt
        });
      }
    }
    
    return slaBreaches;
  },

  async handleSyncSLABreach(userId, breaches) {
    const pool = getPool();
    
    for (const breach of breaches) {
      await this.logConsequenceEvent(CONSEQUENCE_EVENT_TYPES.SYNC_SLA_BREACH, {
        actor_id: userId,
        metadata: breach
      });
    }

    if (breaches.length > 0) {
      const incidentId = generateId('INC');
      await pool.query(`
        INSERT INTO ops_incidents (
          incident_id, type, severity, title, description, status, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
      `, [
        incidentId,
        'sync_sla_breach',
        'high',
        `Sync SLA breach: ${breaches.length} items pending > ${this.SYNC_SLA_HOURS}h`,
        `User ${userId} has ${breaches.length} queued items that exceeded the ${this.SYNC_SLA_HOURS}-hour sync SLA.`,
        'open'
      ]);

      await this.enterRestrictedMode(userId, 'sync_sla_breach');
    }

    return breaches.length;
  },

  async isUserBlocked(userId) {
    const pool = getPool();
    
    const user = await pool.query(`
      SELECT restricted_mode, recert_required FROM jolt_users WHERE user_id = $1
    `, [userId]);

    if (!user.rows[0]) return { blocked: false };

    const { restricted_mode, recert_required } = user.rows[0];
    
    if (restricted_mode) {
      return { blocked: true, reason: 'restricted_mode', message: 'You are in restricted mode. Contact ops to clear.' };
    }
    
    if (recert_required) {
      return { blocked: true, reason: 'recert_required', message: 'Recertification required before continuing.' };
    }

    return { blocked: false };
  },

  async isMachineInSafeMode(machineId) {
    const pool = getPool();
    
    const machine = await pool.query(
      `SELECT safe_mode, safe_mode_exit_date FROM machines WHERE machine_id = $1`,
      [machineId]
    );

    if (!machine.rows[0]) return false;
    return machine.rows[0].safe_mode === true;
  }
};

export default consequenceEngineService;
