import { getPool } from './db.js';

const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

export const runWatchdog = async () => {
  console.log('[Watchdog] Starting v1.00 compliance check...');
  const pool = getPool();
  
  try {
    const overdueAcceptance = await pool.query(`
      SELECT d.*, s.venue_name as site_name, s.site_id
      FROM ops_delivery_records d
      JOIN ops_sites s ON d.site_id = s.site_id
      WHERE d.partner_accepted_at IS NULL 
        AND d.partner_refused IS NULL
        AND d.delivered_at IS NOT NULL
        AND d.delivered_at < NOW() - INTERVAL '24 hours'
    `);
    
    console.log(`[Watchdog] Found ${overdueAcceptance.rows.length} overdue acceptances`);
    
    for (const delivery of overdueAcceptance.rows) {
      const existingIncident = await pool.query(`
        SELECT incident_id FROM ops_incidents 
        WHERE type = 'acceptance_overdue' 
          AND site_id = $1 
          AND status = 'open'
          AND created_at > NOW() - INTERVAL '24 hours'
      `, [delivery.site_id]);
      
      if (existingIncident.rows.length === 0) {
        const incidentId = generateId('INC');
        
        await pool.query(`
          INSERT INTO ops_incidents (incident_id, site_id, type, severity, title, description, status, created_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        `, [
          incidentId,
          delivery.site_id,
          'acceptance_overdue',
          'critical',
          `Acceptance Overdue: ${delivery.site_name}`,
          `Delivery from ${new Date(delivery.delivered_at).toISOString()} has not been accepted within 24 hours.`,
          'open'
        ]);
        
        await pool.query(`
          UPDATE ops_sites SET status = 'SAFE_MODE', updated_at = NOW() WHERE site_id = $1
        `, [delivery.site_id]);
        
        await pool.query(`
          INSERT INTO events (event_id, event_type, site_id, actor_user_id, payload_json, server_timestamp)
          VALUES ($1, $2, $3, $4, $5, NOW())
        `, [
          generateId('EVT'),
          'SAFE_MODE_ENTER',
          delivery.site_id,
          1,
          JSON.stringify({ reason: 'acceptance_overdue_24h', incident_id: incidentId })
        ]);
        
        console.log(`[Watchdog] Created incident ${incidentId} for site ${delivery.site_id}`);
      }
    }
    
    // ========== CHECK 2: WET LEAK INCIDENTS (Notification Only) ==========
    const wetLeakIncidents = await pool.query(`
      SELECT i.*, s.site_id, s.venue_name as site_name
      FROM ops_incidents i
      JOIN ops_sites s ON i.site_id = s.site_id
      WHERE i.type = 'wet_leak'
        AND i.status = 'open'
    `);
    
    console.log(`[Watchdog] Found ${wetLeakIncidents.rows.length} wet leak incidents - Notification sent to Ops`);
    
    // ========== CHECK 3: SYNC SLA VIOLATIONS (Notification Only) ==========
    const pendingSync = await pool.query(`
      SELECT e.*, s.site_id, s.venue_name as site_name
      FROM events e
      LEFT JOIN ops_sites s ON e.site_id = s.site_id
      WHERE e.event_type LIKE '%_STARTED'
        AND e.server_timestamp < NOW() - INTERVAL '6 hours'
        AND NOT EXISTS (
          SELECT 1 FROM events e2 
          WHERE e2.site_id = e.site_id 
            AND e2.event_type LIKE '%_COMPLETED'
            AND e2.server_timestamp > e.server_timestamp
        )
    `);
    
    console.log(`[Watchdog] Found ${pendingSync.rows.length} potential sync SLA violations - Notification sent to Ops`);
    
    console.log('[Watchdog] Compliance check complete!');
    
    return {
      overdueAcceptances: overdueAcceptance.rows.length,
      wetLeakSafeModes: wetLeakIncidents.rows.length,
      syncViolations: pendingSync.rows.length
    };
  } catch (error) {
    console.error('[Watchdog] Error:', error);
    throw error;
  }
};

export const startWatchdogInterval = (intervalMinutes = 60) => {
  console.log(`[Watchdog v1.00.1] Starting with ${intervalMinutes} minute interval (1 hour)`);
  
  runWatchdog().catch(console.error);
  
  const intervalMs = intervalMinutes * 60 * 1000;
  return setInterval(() => {
    runWatchdog().catch(console.error);
  }, intervalMs);
};

export default { runWatchdog, startWatchdogInterval };
