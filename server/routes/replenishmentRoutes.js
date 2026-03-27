import express from 'express';
import { pool } from '../../shared/db.js';
import yileApi from '../services/yile/yileApiService.js';

const router = express.Router();

const INGREDIENT_MAPPING = {
  '咖啡豆': 'Coffee Beans',
  'Coffee Beans': 'Coffee Beans',
  'coffeeBean': 'Coffee Beans',
  'Oat Milk': 'Oat Milk',
  '燕麦奶': 'Oat Milk',
  'Matcha': 'Matcha',
  '抹茶': 'Matcha',
  'Chai': 'Chai',
  'Cocoa': 'Cocoa',
  '可可': 'Cocoa',
  'Vanilla Syrup': 'Vanilla Syrup',
  '香草糖浆': 'Vanilla Syrup',
  'Brown Sugar Syrup': 'Brown Sugar Syrup',
  'Coconut Syrup': 'Coconut Syrup',
  'Lavender Syrup': 'Lavender Syrup',
  'Hazelnut Syrup': 'Hazelnut Syrup',
  'Caramel Syrup': 'Caramel Syrup',
  'Caramel': 'Caramel Syrup',
  'Hazelnut': 'Hazelnut Syrup',
  'Vanilla': 'Vanilla Syrup',
  '杯子': 'Cups',
  'Cups': 'Cups',
  'cup': 'Cups',
  '水': 'Hot Water',
  'Hot Water': 'Hot Water',
  'hotWater': 'Hot Water'
};

function normalizeIngredientName(yileName) {
  return INGREDIENT_MAPPING[yileName] || yileName;
}

function findYileItem(yileData, ingredientName) {
  if (!yileData || !Array.isArray(yileData)) return null;
  
  for (const track of yileData) {
    if (!track.goodsNoInfoList) continue;
    
    for (const item of track.goodsNoInfoList) {
      const normalizedName = normalizeIngredientName(item.goodsName);
      
      if (normalizedName === ingredientName) {
        return {
          ...item,
          normalizedName,
          deviceTag: track.deviceTags,
          nowStock: parseInt(item.nowStock) || 0,
          maxStock: parseInt(item.maxStock) || 1,
          typeId: item.storeType || item.inventoryType
        };
      }
    }
  }
  
  return null;
}

function getStockStatus(yileItem, setting) {
  if (!yileItem) return 'unknown';
  const percent = Math.round((yileItem.nowStock / yileItem.maxStock) * 100);
  if (percent <= setting.critical_threshold) return 'critical';
  if (percent <= setting.warning_threshold) return 'warning';
  return 'ok';
}

function calculateContainersNeeded(currentGrams, containerSizeGrams, targetLevelPercent) {
  if (!containerSizeGrams || containerSizeGrams <= 0) return 0;
  const targetGrams = (targetLevelPercent / 100) * containerSizeGrams;
  const neededGrams = Math.max(0, targetGrams - currentGrams);
  return Math.ceil(neededGrams / containerSizeGrams);
}

router.get('/settings/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    const settingsResult = await pool.query(
      'SELECT * FROM replenishment_settings WHERE device_id = $1',
      [deviceId]
    );
    const settings = settingsResult.rows;
    
    const inventoryResult = await yileApi.findInventory(deviceId);
    const tracks = inventoryResult.list || inventoryResult || [];
    
    const combined = settings.map(setting => {
      const yileItem = findYileItem(tracks, setting.ingredient_name);
      return {
        ...setting,
        currentStock: yileItem ? {
          grams: yileItem.nowStock,
          maxGrams: yileItem.maxStock,
          percent: Math.round((yileItem.nowStock / yileItem.maxStock) * 100)
        } : null,
        status: getStockStatus(yileItem, setting)
      };
    });
    
    res.json({ success: true, data: combined });
    
  } catch (error) {
    console.error('Settings fetch error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.put('/settings/:deviceId/:ingredientName', async (req, res) => {
  try {
    const { deviceId, ingredientName } = req.params;
    const {
      warning_threshold,
      critical_threshold,
      target_level,
      container_type,
      container_size_grams
    } = req.body;
    
    if (warning_threshold < 0 || warning_threshold > 100 ||
        critical_threshold < 0 || critical_threshold > 100 ||
        target_level < 0 || target_level > 100) {
      return res.status(400).json({ success: false, error: 'Percentages must be 0-100' });
    }
    
    if (critical_threshold >= warning_threshold) {
      return res.status(400).json({ 
        success: false, 
        error: 'Critical threshold must be lower than warning threshold' 
      });
    }
    
    await pool.query(`
      INSERT INTO replenishment_settings 
        (device_id, ingredient_name, warning_threshold, critical_threshold, 
         target_level, container_type, container_size_grams, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
      ON CONFLICT(device_id, ingredient_name) 
      DO UPDATE SET
        warning_threshold = EXCLUDED.warning_threshold,
        critical_threshold = EXCLUDED.critical_threshold,
        target_level = EXCLUDED.target_level,
        container_type = EXCLUDED.container_type,
        container_size_grams = EXCLUDED.container_size_grams,
        updated_at = CURRENT_TIMESTAMP
    `, [deviceId, ingredientName, warning_threshold, critical_threshold, 
        target_level, container_type, container_size_grams]);
    
    res.json({ success: true, message: 'Settings updated' });
    
  } catch (error) {
    console.error('Settings update error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/alerts', async (req, res) => {
  try {
    const { status = 'active' } = req.query;
    
    const alertsResult = await pool.query(`
      SELECT 
        a.*,
        s.device_id,
        s.ingredient_name,
        s.container_type,
        s.container_size_grams
      FROM refill_alerts a
      JOIN replenishment_settings s 
        ON a.device_id = s.device_id 
        AND a.ingredient_name = s.ingredient_name
      WHERE a.status = $1
      ORDER BY 
        CASE a.alert_level 
          WHEN 'critical' THEN 1 
          WHEN 'warning' THEN 2 
        END,
        a.created_at DESC
    `, [status]);
    
    res.json({ success: true, data: alertsResult.rows });
    
  } catch (error) {
    console.error('Alerts fetch error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/status/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    const settingsResult = await pool.query(
      'SELECT * FROM replenishment_settings WHERE device_id = $1',
      [deviceId]
    );
    
    let ingredients = [];
    let lastUpdated = null;
    
    try {
      const inventoryResult = await yileApi.findInventory(deviceId);
      const tracks = inventoryResult.list || inventoryResult || [];
      
      ingredients = settingsResult.rows.map(setting => {
        const yileItem = findYileItem(tracks, setting.ingredient_name);
        const currentLevel = yileItem 
          ? Math.round((yileItem.nowStock / yileItem.maxStock) * 100)
          : 0;
          
        return {
          name: setting.ingredient_name,
          currentLevel,
          warningThreshold: setting.warning_threshold,
          criticalThreshold: setting.critical_threshold,
          rawStock: yileItem?.nowStock || 0,
          maxStock: yileItem?.maxStock || 0
        };
      });
      
      lastUpdated = new Date().toISOString();
      
    } catch (apiError) {
      console.warn('[Replenishment] Yile API error, using defaults:', apiError.message);
      
      ingredients = settingsResult.rows.map(setting => ({
        name: setting.ingredient_name,
        currentLevel: 50,
        warningThreshold: setting.warning_threshold,
        criticalThreshold: setting.critical_threshold,
        rawStock: 0,
        maxStock: 0,
        note: 'API unavailable - showing default'
      }));
    }
    
    res.json({
      success: true,
      data: {
        deviceId,
        ingredients,
        lastUpdated
      }
    });
    
  } catch (error) {
    console.error('Status fetch error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/check/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    const inventoryResult = await yileApi.findInventory(deviceId);
    const tracks = inventoryResult.list || inventoryResult || [];
    
    const settingsResult = await pool.query(
      'SELECT * FROM replenishment_settings WHERE device_id = $1 AND monitoring_enabled = TRUE',
      [deviceId]
    );
    const settings = settingsResult.rows;
    
    const alerts = [];
    
    for (const setting of settings) {
      const yileItem = findYileItem(tracks, setting.ingredient_name);
      if (!yileItem) continue;
      
      const currentGrams = yileItem.nowStock;
      const maxGrams = yileItem.maxStock;
      const percentFull = Math.round((currentGrams / maxGrams) * 100);
      
      await pool.query(`
        INSERT INTO inventory_snapshots 
          (device_id, ingredient_name, current_grams, max_capacity_grams, percent_full, snapshot_timestamp)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
      `, [deviceId, setting.ingredient_name, currentGrams, maxGrams, percentFull]);
      
      if (percentFull <= setting.critical_threshold) {
        await createOrUpdateAlert(deviceId, setting, 'critical', percentFull, currentGrams);
        alerts.push({ ingredient: setting.ingredient_name, level: 'critical', percent: percentFull });
      } else if (percentFull <= setting.warning_threshold) {
        await createOrUpdateAlert(deviceId, setting, 'warning', percentFull, currentGrams);
        alerts.push({ ingredient: setting.ingredient_name, level: 'warning', percent: percentFull });
      } else {
        await resolveAlert(deviceId, setting.ingredient_name);
      }
    }
    
    res.json({ 
      success: true, 
      data: {
        deviceId,
        alertsGenerated: alerts.length,
        alerts,
        snapshotSaved: settings.length > 0,
        ingredientsChecked: settings.length
      }
    });
    
  } catch (error) {
    console.error('Check error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

async function createOrUpdateAlert(deviceId, setting, level, percentFull, currentGrams) {
  const existing = await pool.query(
    'SELECT id FROM refill_alerts WHERE device_id = $1 AND ingredient_name = $2 AND status = $3',
    [deviceId, setting.ingredient_name, 'active']
  );
  
  if (existing.rows.length === 0) {
    await pool.query(`
      INSERT INTO refill_alerts 
        (device_id, ingredient_name, alert_level, status, percent_when_triggered, grams_when_triggered, created_at)
      VALUES ($1, $2, $3, 'active', $4, $5, CURRENT_TIMESTAMP)
    `, [deviceId, setting.ingredient_name, level, percentFull, currentGrams]);
  } else {
    await pool.query(
      'UPDATE refill_alerts SET alert_level = $1, percent_when_triggered = $2, grams_when_triggered = $3 WHERE id = $4',
      [level, percentFull, currentGrams, existing.rows[0].id]
    );
  }
}

async function resolveAlert(deviceId, ingredientName) {
  await pool.query(
    "UPDATE refill_alerts SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP WHERE device_id = $1 AND ingredient_name = $2 AND status = 'active'",
    [deviceId, ingredientName]
  );
}

router.get('/flagged/:visitId', async (req, res) => {
  try {
    const { visitId } = req.params;
    
    const flaggedResult = await pool.query(`
      SELECT 
        a.*,
        s.container_type,
        s.container_size_grams,
        s.target_level
      FROM refill_alerts a
      JOIN replenishment_settings s 
        ON a.device_id = s.device_id 
        AND a.ingredient_name = s.ingredient_name
      WHERE a.flagged_for_visit_id = $1
        AND a.status = 'flagged_for_visit'
    `, [visitId]);
    
    const itemsWithInstructions = flaggedResult.rows.map(item => ({
      ...item,
      containersNeeded: calculateContainersNeeded(
        item.grams_when_triggered,
        item.container_size_grams,
        item.target_level
      )
    }));
    
    res.json({ success: true, data: itemsWithInstructions });
    
  } catch (error) {
    console.error('Flagged items error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/inventory/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    const inventoryResult = await yileApi.findInventory(deviceId);
    const tracks = inventoryResult.list || inventoryResult || [];
    
    const parsedIngredients = [];
    
    for (const track of tracks) {
      if (!track.goodsNoInfoList) continue;
      
      for (const item of track.goodsNoInfoList) {
        const normalized = normalizeIngredientName(item.goodsName);
        const current = parseInt(item.nowStock) || 0;
        const max = parseInt(item.maxStock) || 1;
        const percent = Math.round((current / max) * 100);
        
        parsedIngredients.push({
          originalName: item.goodsName,
          normalizedName: normalized,
          deviceTag: track.deviceTags,
          vmType: track.vmType,
          currentGrams: current,
          maxGrams: max,
          percentFull: percent,
          storeType: item.storeType,
          inventoryType: item.inventoryType
        });
      }
    }
    
    res.json({ success: true, data: parsedIngredients, raw: tracks });
    
  } catch (error) {
    console.error('Inventory fetch error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
