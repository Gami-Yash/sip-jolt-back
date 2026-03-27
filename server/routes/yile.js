/**
 * SIPJOLT Yile API Routes
 * REST endpoints that wrap Yile API V5.3 functionality
 * 
 * All routes prefixed with: /api/v1.01/yile
 */

import express from 'express';
import yileClient from '../services/yileApiClient.js';

const router = express.Router();

router.get('/health', async (req, res) => {
  try {
    const enabled = process.env.YILE_INTEGRATION_ENABLED === 'true';
    const hasCredentials = !!(process.env.YILE_DEPARTMENT_ID && process.env.YILE_SECRET_KEY);
    
    res.json({
      success: true,
      integration: {
        enabled,
        hasCredentials,
        baseUrl: process.env.YILE_API_BASE_URL,
        departmentId: process.env.YILE_DEPARTMENT_ID
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/token/test', async (req, res) => {
  try {
    const token = await yileClient.getToken();
    
    res.json({
      success: true,
      message: 'Token fetched successfully',
      tokenLength: token.length,
      tokenPreview: token.substring(0, 20) + '...',
      expiresAt: new Date(yileClient.tokenExpiry).toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/devices/:deviceId/status', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const result = await yileClient.getDeviceStatusSummary(deviceId);
    
    res.json({
      success: true,
      deviceId,
      status: result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/devices/:deviceId/status/raw', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const result = await yileClient.getDeviceStatus(deviceId);
    
    res.json({
      success: result.success,
      deviceId,
      data: result.data,
      isEncrypted: result.isEncrypted,
      serverTime: result.serverTime,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/devices/:deviceId/inventory', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const result = await yileClient.getInventory(deviceId);
    
    if (!result.success) {
      return res.status(500).json(result);
    }

    const mappedInventory = yileClient.mapInventoryToGate5(result.data);
    
    res.json({
      success: true,
      deviceId,
      inventory: mappedInventory,
      raw: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/devices/:deviceId/sales', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { startDate, endDate, pageNum, pageSize } = req.query;
    
    // Yile API expects format: "yyyy-MM-dd HH:mm:ss" AND dates must be in same month
    const formatDate = (dateStr, isEnd = false) => {
      const d = dateStr ? new Date(dateStr) : new Date();
      const pad = n => n.toString().padStart(2, '0');
      const time = isEnd ? '23:59:59' : '00:00:00';
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
    };
    
    // Default to current month (Yile requires same month for start/end)
    const now = new Date();
    const firstOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    
    const result = await yileClient.getSales(
      deviceId,
      formatDate(startDate || firstOfMonth.toISOString().split('T')[0]),
      formatDate(endDate || now.toISOString().split('T')[0], true),
      parseInt(pageNum) || 1,
      parseInt(pageSize) || 20
    );
    
    res.json({
      success: result.success,
      deviceId,
      sales: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/devices/:deviceId/sales/failed', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { startDate, endDate, pageNum, pageSize } = req.query;
    
    // Yile API expects format: "yyyy-MM-dd HH:mm:ss" AND dates must be in same month
    const formatDate = (dateStr, isEnd = false) => {
      const d = dateStr ? new Date(dateStr) : new Date();
      const pad = n => n.toString().padStart(2, '0');
      const time = isEnd ? '23:59:59' : '00:00:00';
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
    };
    
    // Default to current month (Yile requires same month for start/end)
    const now = new Date();
    const firstOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    
    const result = await yileClient.getFailedSales(
      deviceId,
      formatDate(startDate || firstOfMonth.toISOString().split('T')[0]),
      formatDate(endDate || now.toISOString().split('T')[0], true),
      parseInt(pageNum) || 1,
      parseInt(pageSize) || 20
    );
    
    res.json({
      success: result.success,
      deviceId,
      failedSales: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/recipes', async (req, res) => {
  try {
    const result = await yileClient.getRecipeCatalog();
    
    res.json({
      success: result.success,
      recipes: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/devices/:deviceId/menu', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const result = await yileClient.getMachineMenu(deviceId);
    
    res.json({
      success: result.success,
      deviceId,
      menu: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/recipes', async (req, res) => {
  try {
    const recipeData = req.body;
    const result = await yileClient.addRecipe(recipeData);
    
    res.json({
      success: result.success,
      recipe: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.put('/recipes/:recipeId', async (req, res) => {
  try {
    const { recipeId } = req.params;
    const recipeData = { ...req.body, recipeId };
    const result = await yileClient.editRecipe(recipeData);
    
    res.json({
      success: result.success,
      recipe: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/devices/:deviceId/brew', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { recipeName } = req.body;
    
    if (!recipeName) {
      return res.status(400).json({ 
        success: false, 
        error: 'recipeName is required' 
      });
    }

    console.log(`[API] Initiating brew: ${recipeName} on device ${deviceId}`);
    
    const brewResult = await yileClient.remoteBrew(deviceId, recipeName);
    
    if (!brewResult.success) {
      return res.status(500).json(brewResult);
    }

    const pushId = brewResult.data?.pushId;
    
    if (!pushId) {
      return res.status(500).json({
        success: false,
        error: 'No pushId returned from brew command'
      });
    }

    console.log(`[API] Brew initiated, pushId: ${pushId}, polling for result...`);
    
    const finalResult = await yileClient.pollPushResult(pushId, 60, 2000);
    
    res.json({
      success: finalResult.success,
      deviceId,
      recipeName,
      pushId,
      result: finalResult.result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('[API] Brew error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/devices/:deviceId/restart', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    console.log(`[API] Initiating restart for device ${deviceId}`);
    
    const status = await yileClient.getDeviceStatusSummary(deviceId);
    
    if (status.workStatus !== 0) {
      return res.status(400).json({
        success: false,
        error: `Cannot restart while machine is busy (${status.workStatusText})`,
        workStatus: status.workStatus
      });
    }

    const restartResult = await yileClient.restartMachine(deviceId);
    
    if (!restartResult.success) {
      return res.status(500).json(restartResult);
    }

    const pushId = restartResult.data?.pushId;
    
    res.json({
      success: true,
      deviceId,
      pushId,
      message: 'Restart initiated',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('[API] Restart error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/push/:pushId/status', async (req, res) => {
  try {
    const { pushId } = req.params;
    const result = await yileClient.queryPushResult(pushId);
    
    res.json({
      success: result.success,
      pushId,
      result: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/department/info', async (req, res) => {
  try {
    const result = await yileClient.getDepartmentInfo();
    
    res.json({
      success: result.success,
      department: result.data,
      isEncrypted: result.isEncrypted,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/devices/:deviceId/recipes/push', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { recipeId } = req.body;
    
    if (!recipeId) {
      return res.status(400).json({ success: false, error: 'recipeId is required' });
    }

    const result = await yileClient.pushRecipeToDevice(deviceId, recipeId);
    res.json({
      success: result.success,
      deviceId,
      recipeId,
      pushId: result.data?.pushId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/sales/summary', async (req, res) => {
  try {
    const { deviceId, startDate, endDate, status } = req.query;
    
    if (!deviceId) {
      return res.status(400).json({ success: false, error: 'deviceId is required' });
    }

    // Yile API expects format: "yyyy-MM-dd HH:mm:ss" AND dates must be in same month
    const formatDate = (dateStr, isEnd = false) => {
      const d = dateStr ? new Date(dateStr) : new Date();
      const pad = n => n.toString().padStart(2, '0');
      const time = isEnd ? '23:59:59' : '00:00:00';
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
    };
    
    // Default to current month (Yile requires same month for start/end)
    const now = new Date();
    const firstOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const formattedStart = formatDate(startDate || firstOfMonth.toISOString().split('T')[0]);
    const formattedEnd = formatDate(endDate || now.toISOString().split('T')[0], true);

    const result = status === 'failed' 
      ? await yileClient.getFailedSales(deviceId, formattedStart, formattedEnd)
      : await yileClient.getSales(deviceId, formattedStart, formattedEnd);

    res.json({
      success: result.success,
      deviceId,
      status: status || 'success',
      count: result.total || 0,
      sales: result.rows || [],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});
router.get('/test/all/:deviceId', async (req, res) => {
  const { deviceId } = req.params;
  const results = {};
  
  console.log(`[API] Running comprehensive test for device ${deviceId}`);
  
  try {
    console.log('[Test 1/7] Token fetch...');
    try {
      const token = await yileClient.getToken();
      results.token = { success: true, tokenLength: token.length };
    } catch (error) {
      results.token = { success: false, error: error.message };
    }

    console.log('[Test 2/7] Device status...');
    try {
      const status = await yileClient.getDeviceStatusSummary(deviceId);
      results.deviceStatus = { success: true, status };
    } catch (error) {
      results.deviceStatus = { success: false, error: error.message };
    }

    console.log('[Test 3/7] Inventory...');
    try {
      const inventory = await yileClient.getInventory(deviceId);
      results.inventory = { 
        success: inventory.success, 
        isEncrypted: inventory.isEncrypted 
      };
    } catch (error) {
      results.inventory = { success: false, error: error.message };
    }

    console.log('[Test 4/7] Recipe catalog...');
    try {
      const recipes = await yileClient.getRecipeCatalog();
      results.recipes = { 
        success: recipes.success, 
        isEncrypted: recipes.isEncrypted 
      };
    } catch (error) {
      results.recipes = { success: false, error: error.message };
    }

    console.log('[Test 5/7] Machine menu...');
    try {
      const menu = await yileClient.getMachineMenu(deviceId);
      results.machineMenu = { 
        success: menu.success, 
        isEncrypted: menu.isEncrypted 
      };
    } catch (error) {
      results.machineMenu = { success: false, error: error.message };
    }

    console.log('[Test 6/7] Sales data...');
    try {
      const sales = await yileClient.getSales(deviceId, '2026-01-01', '2026-12-31', 1, 5);
      results.sales = { 
        success: sales.success, 
        isEncrypted: sales.isEncrypted 
      };
    } catch (error) {
      results.sales = { success: false, error: error.message };
    }

    console.log('[Test 7/7] Department info...');
    try {
      const dept = await yileClient.getDepartmentInfo();
      results.department = { 
        success: dept.success, 
        isEncrypted: dept.isEncrypted 
      };
    } catch (error) {
      results.department = { success: false, error: error.message };
    }

    const successCount = Object.values(results).filter(r => r.success).length;
    const totalTests = Object.keys(results).length;

    res.json({
      success: true,
      summary: {
        passed: successCount,
        total: totalTests,
        passRate: `${Math.round((successCount / totalTests) * 100)}%`
      },
      results,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      results
    });
  }
});

export default router;
