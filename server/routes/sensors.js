import express from 'express';
import { getPool } from '../../shared/db.js';

const router = express.Router();

const INGREDIENT_MAP = {
  1: 'syrups_left',
  2: 'syrups_right',
  3: 'oat',
  4: 'dairy',
  5: 'coffee',
  6: 'matcha',
  7: 'chai',
  8: 'cocoa',
  9: 'sugar',
  10: 'cleaning',
  11: 'lids'
};

const SHELF_MAP = {
  1: 1, 2: 1,
  3: 2, 4: 2, 5: 2,
  6: 3, 7: 3, 8: 3,
  9: 4, 10: 4, 11: 4
};

async function triggerLowInventoryAlert(pool, siteId, binId, ingredient, percentFull) {
  const avgConsumptionPerDay = 1.67;
  const daysRemaining = Math.floor(percentFull / avgConsumptionPerDay);
  
  const existing = await pool.query(`
    SELECT id FROM sensor_alerts
    WHERE site_id = $1 AND bin_id = $2 AND alert_type = 'low_inventory' AND resolved_at IS NULL
  `, [siteId, binId]);
  
  if (existing.rows.length > 0) return;
  
  await pool.query(`
    INSERT INTO sensor_alerts
    (site_id, bin_id, ingredient, alert_type, severity, percent_full, estimated_days_remaining, triggered_at)
    VALUES ($1, $2, $3, 'low_inventory', $4, $5, $6, NOW())
  `, [
    siteId,
    binId,
    ingredient,
    percentFull < 10 ? 'critical' : 'warning',
    percentFull,
    daysRemaining
  ]);
}

router.post('/weight', async (req, res) => {
  try {
    const { device_id, site_id, bin_id, weight_lbs, percent_full, timestamp, battery_voltage } = req.body;
    
    if (!device_id || !site_id || bin_id === undefined || weight_lbs === undefined || percent_full === undefined) {
      return res.status(400).json({ error: 'Missing required fields: device_id, site_id, bin_id, weight_lbs, percent_full' });
    }
    
    const ingredient = INGREDIENT_MAP[bin_id] || 'unknown';
    const pool = getPool();
    
    const result = await pool.query(`
      INSERT INTO sensor_readings 
      (device_id, site_id, bin_id, ingredient, weight_lbs, percent_full, timestamp, battery_voltage, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id
    `, [
      device_id,
      site_id,
      bin_id,
      ingredient,
      weight_lbs,
      percent_full,
      timestamp || new Date(),
      battery_voltage || null,
      battery_voltage && battery_voltage < 3.5 ? 'low_battery' : 'ok'
    ]);
    
    if (percent_full < 20) {
      await triggerLowInventoryAlert(pool, site_id, bin_id, ingredient, percent_full);
    }
    
    res.status(201).json({
      success: true,
      reading_id: result.rows[0].id
    });
    
  } catch (error) {
    console.error('Sensor data error:', error);
    res.status(500).json({ error: 'Failed to process sensor data' });
  }
});

router.get('/site/:siteId', async (req, res) => {
  try {
    const { siteId } = req.params;
    const hours = parseInt(req.query.hours) || 24;
    
    const pool = getPool();
    const readings = await pool.query(`
      SELECT 
        bin_id,
        ingredient,
        weight_lbs,
        percent_full,
        timestamp,
        battery_voltage,
        status
      FROM sensor_readings
      WHERE site_id = $1
        AND timestamp > NOW() - INTERVAL '1 hour' * $2
      ORDER BY bin_id, timestamp DESC
    `, [siteId, hours]);
    
    const latestByBin = {};
    readings.rows.forEach(reading => {
      if (!latestByBin[reading.bin_id]) {
        latestByBin[reading.bin_id] = {
          ...reading,
          shelf: SHELF_MAP[reading.bin_id] || 0
        };
      }
    });
    
    res.json({
      site_id: siteId,
      bins: Object.values(latestByBin),
      bin_count: 11,
      last_updated: new Date()
    });
    
  } catch (error) {
    console.error('Get sensors error:', error);
    res.status(500).json({ error: 'Failed to retrieve sensor data' });
  }
});

router.get('/alerts', async (req, res) => {
  try {
    const { site_id, unresolved_only = 'true' } = req.query;
    const pool = getPool();
    
    let query = `
      SELECT * FROM sensor_alerts
      WHERE 1=1
    `;
    const params = [];
    
    if (site_id) {
      params.push(site_id);
      query += ` AND site_id = $${params.length}`;
    }
    
    if (unresolved_only === 'true') {
      query += ` AND resolved_at IS NULL`;
    }
    
    query += ` ORDER BY triggered_at DESC LIMIT 100`;
    
    const result = await pool.query(query, params);
    
    res.json({
      alerts: result.rows,
      count: result.rows.length
    });
    
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ error: 'Failed to retrieve alerts' });
  }
});

router.post('/alerts/:alertId/resolve', async (req, res) => {
  try {
    const { alertId } = req.params;
    const { resolution_note } = req.body;
    const pool = getPool();
    
    await pool.query(`
      UPDATE sensor_alerts
      SET resolved_at = NOW(), resolution_note = $2
      WHERE id = $1
    `, [alertId, resolution_note || 'Resolved by operator']);
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Resolve alert error:', error);
    res.status(500).json({ error: 'Failed to resolve alert' });
  }
});

export default router;
