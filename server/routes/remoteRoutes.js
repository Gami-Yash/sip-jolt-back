import express from 'express';
import yileApi from '../services/yile/yileApiService.js';
import { pool } from '../../shared/db.js';
import rateLimit from 'express-rate-limit';
import { requireAuth, requireRole } from '../../shared/middleware/rbac.js';

const router = express.Router();

router.use(requireAuth);
router.use(requireRole('ops_manager', 'ops_admin', 'technician', 'partner'));

// Limit remote operations to 10 per minute per IP to prevent API abuse
const remoteLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: { success: false, error: 'Too many requests, please try again later' }
});

router.post('/brew', remoteLimiter, async (req, res) => {
  try {
    const { deviceId, recipeName, recipeId } = req.body;
    
    if (!deviceId || (!recipeName && !recipeId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Device ID and recipe name/ID are required' 
      });
    }

    // Validate recipe exists on device to prevent invalid API calls
    try {
      const deviceRecipes = await yileApi.queryCoffee(deviceId);
      const recipes = deviceRecipes.list || deviceRecipes.rows || deviceRecipes.data || (Array.isArray(deviceRecipes) ? deviceRecipes : []);
      
      const recipeExists = recipes.some(r => 
        (r.recipeName || r.name || r.coffeeName || r.coffee_name) === (recipeName || recipeId)
      );

      if (!recipeExists && recipes.length > 0) {
        return res.status(400).json({
          success: false,
          error: `Recipe "${recipeName || recipeId}" not available on this device`
        });
      }
    } catch (e) {
      console.warn('[Remote] Recipe validation skipped due to API error:', e.message);
    }

    console.log(`[Remote] Brew request: ${deviceId} - ${recipeName || recipeId}`);
    
    const pushId = await yileApi.pushRemoteDrinking(deviceId, recipeName || recipeId);
    
    res.json({
      success: true,
      data: {
        pushId,
        message: 'Brew command sent',
        deviceId,
        recipeName: recipeName || recipeId
      }
    });
  } catch (error) {
    console.error('[Remote] Brew error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/restart', remoteLimiter, async (req, res) => {
  try {
    const { deviceId } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ success: false, error: 'Device ID is required' });
    }

    console.log(`[Remote] Restart request: ${deviceId}`);
    
    const result = await yileApi.pushRestartMachine(deviceId);
    
    res.json({
      success: true,
      data: {
        message: 'Restart command sent',
        deviceId,
        pushId: result.pushId
      }
    });
  } catch (error) {
    console.error('[Remote] Restart error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/price', async (req, res) => {
  try {
    const { deviceId, recipeId, price } = req.body;
    
    if (!deviceId || !recipeId || price === undefined) {
      return res.status(400).json({ 
        success: false, 
        error: 'Device ID, recipe ID, and price are required' 
      });
    }

    console.log(`[Remote] Price update: ${deviceId} - ${recipeId} = $${price}`);
    
    res.json({
      success: false,
      error: 'Price update not implemented yet'
    });
  } catch (error) {
    console.error('[Remote] Price update error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/result/:pushId', async (req, res) => {
  try {
    const { pushId } = req.params;
    
    if (!pushId) {
      return res.status(400).json({ success: false, error: 'Push ID is required' });
    }

    const result = await yileApi.queryPushResult(pushId);
    
    res.json({
      success: true,
      data: {
        pushId,
        status: result.completed ? 'completed' : 'pending',
        result: result,
        completed: result.completed,
        success: result.success
      }
    });
  } catch (error) {
    console.error('[Remote] Result check error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/devices', async (req, res) => {
  try {
    const deviceId = process.env.YILE_DEFAULT_DEVICE || '00000020868';
    
    const deviceInfo = await yileApi.findDeviceInfo(deviceId);
    
    res.json({
      success: true,
      data: [{
        deviceId: deviceInfo.deviceId || deviceId,
        name: deviceInfo.deviceNikeName || `Machine ${deviceId}`,
        online: deviceInfo.deviceStatus === 1,
        type: deviceInfo.deviceType || 'Coffee Machine'
      }]
    });
  } catch (error) {
    console.error('[Remote] Devices list error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/recipes/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    console.log(`[Remote] Fetching recipes for device: ${deviceId}`);
    
    let recipes = [];
    let source = 'api';
    
    try {
      const result = await yileApi.queryCoffee(deviceId);
      console.log(`[Remote] queryCoffee response:`, JSON.stringify(result).slice(0, 500));
      
      // Yile API returns recipes in various formats
      recipes = result.list || result.rows || result.data || [];
      
      // If result is the array directly
      if (Array.isArray(result) && result.length > 0) {
        recipes = result;
      }
      
      console.log(`[Remote] Found ${recipes.length} recipes from API`);
    } catch (e) {
      console.log('[Remote] queryCoffee failed:', e.message);
      source = 'error';
    }
    
    // Only return what's actually on the machine - NO fallback to generic catalog
    // If API fails, return empty with error message so user knows
    if (recipes.length === 0) {
      return res.json({
        success: true,
        data: [],
        source: source,
        message: source === 'error' 
          ? 'Could not fetch recipes from machine. Check machine connectivity.' 
          : 'No recipes found on this machine.'
      });
    }
    
    res.json({
      success: true,
      source: 'machine',
      data: recipes.map(r => ({
        id: r.recipeId || r.id || r.coffeeId || r.recipe_id,
        name: r.recipeName || r.name || r.coffeeName || r.coffee_name,
        price: r.price || r.salePrice || r.sale_price || 0
      }))
    });
  } catch (error) {
    console.error('[Remote] Recipes list error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
