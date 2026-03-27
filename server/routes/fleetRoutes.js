import express from 'express';
import yileApi from '../services/yileApi/index.js';

const router = express.Router();

function getDeviceTypeLabel(type) {
  const types = {
    '1': 'Vending Machine',
    '2': 'Coffee Machine',
    '3': 'Tea Machine',
    '4': 'Smart Locker',
    '5': 'Combo (Coffee + Vending)',
    '6': 'Fixed Code Machine'
  };
  return types[String(type)] || 'Unknown';
}

function getStatusLabel(statusCode) {
  const labels = {
    '-1': 'Unknown',
    '0': 'Faulted',
    '1': 'Normal'
  };
  return labels[String(statusCode)] || 'Unknown';
}

function getWorkStatusLabel(workStatus) {
  if (workStatus === null || workStatus === undefined) return 'Idle';
  const labels = {
    0: 'Idle',
    1: 'Selecting Recipe',
    2: 'Processing Payment',
    3: 'Brewing',
    5: 'Lid Dispensing',
    6: 'Settings Mode'
  };
  return labels[workStatus] || 'Unknown';
}

function formatYileDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

router.get('/dashboard', async (req, res) => {
  try {
    const result = await yileApi.devices.getDeviceStatus();
    
    if (!result.success) {
      return res.status(500).json({
        success: false,
        error: result.error
      });
    }

    const rawDevices = Array.isArray(result.data) ? result.data : (result.rows || []);
    
    const devices = rawDevices.map(device => ({
      deviceId: device.deviceId,
      name: device.deviceNikeName || device.deviceId,
      type: getDeviceTypeLabel(device.deviceType),
      location: {
        lat: parseFloat(device.deviceLatitude) || 0,
        lng: parseFloat(device.deviceLongitude) || 0,
        address: device.deviceAddress || 'Unknown'
      },
      status: {
        online: device.deviceStatus === 1,
        statusCode: device.deviceStatus,
        statusLabel: getStatusLabel(device.deviceStatus),
        workStatus: device.workStatus,
        workStatusLabel: getWorkStatusLabel(device.workStatus)
      },
      network: {
        type: device.netType,
        signal: device.netSignal
      },
      fault: device.deviceStatus === 0 ? {
        hasError: true,
        errorInfo: device.deviceErrorInfo || 'Unknown error',
        trackErrorCount: device.trackErrorCount || 0
      } : null,
      lastSeen: device.gmtUpdate,
      deviceDate: device.deviceDate,
      tags: device.deviceTags
    }));

    res.json({
      success: true,
      data: {
        total: devices.length,
        online: devices.filter(d => d.status.online).length,
        faulted: devices.filter(d => d.fault !== null).length,
        offline: devices.filter(d => !d.status.online && !d.fault).length,
        devices
      }
    });

  } catch (error) {
    console.error('Fleet dashboard error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/:deviceId/details', async (req, res) => {
  try {
    const { deviceId } = req.params;

    const [statusResult, inventoryResult, recipesResult] = await Promise.all([
      yileApi.devices.getDeviceStatus(deviceId),
      yileApi.devices.getDeviceInventory(deviceId),
      yileApi.devices.getDeviceRecipes(deviceId)
    ]);

    if (!statusResult.success) {
      return res.status(404).json({
        success: false,
        error: 'Device not found'
      });
    }

    const rawDevices = Array.isArray(statusResult.data) ? statusResult.data : (statusResult.rows || [statusResult.data]);
    const device = rawDevices[0];
    
    if (!device) {
      return res.status(404).json({
        success: false,
        error: 'Device not found'
      });
    }

    res.json({
      success: true,
      data: {
        device: {
          deviceId: device.deviceId,
          name: device.deviceNikeName || device.deviceId,
          type: getDeviceTypeLabel(device.deviceType),
          location: {
            lat: parseFloat(device.deviceLatitude) || 0,
            lng: parseFloat(device.deviceLongitude) || 0,
            address: device.deviceAddress || 'Unknown'
          },
          status: {
            online: device.deviceStatus === 1,
            statusCode: device.deviceStatus,
            statusLabel: getStatusLabel(device.deviceStatus),
            workStatus: device.workStatus,
            workStatusLabel: getWorkStatusLabel(device.workStatus)
          },
          network: {
            type: device.netType,
            signal: device.netSignal
          },
          fault: device.deviceStatus === 0 ? {
            hasError: true,
            errorInfo: device.deviceErrorInfo || 'Unknown error',
            trackErrorCount: device.trackErrorCount || 0
          } : null,
          lastSeen: device.gmtUpdate,
          deviceDate: device.deviceDate
        },
        inventory: inventoryResult.success ? inventoryResult.data : null,
        recipes: recipesResult.success ? (recipesResult.data || recipesResult.rows || []) : []
      }
    });

  } catch (error) {
    console.error('Device details error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/:deviceId/inventory', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const result = await yileApi.devices.getDeviceInventory(deviceId);

    if (!result.success) {
      return res.status(404).json({
        success: false,
        error: 'Device inventory not found'
      });
    }

    const rawData = Array.isArray(result.data) ? result.data : [result.data];
    
    const inventory = rawData.map(track => {
      const items = (track.goodsNoInfoList || []).map(item => {
        const currentStock = parseInt(item.nowStock) || 0;
        const maxStock = parseInt(item.maxStock) || 1;
        const percentRemaining = (currentStock / maxStock) * 100;
        const daysRemaining = Math.floor(percentRemaining / 10);

        return {
          name: item.goodsName,
          type: item.storeType || item.inventoryType,
          current: currentStock,
          max: maxStock,
          percentRemaining: Math.round(percentRemaining),
          daysRemaining,
          needsRefill: daysRemaining < 3,
          status: daysRemaining < 1 ? 'critical' : daysRemaining < 3 ? 'warning' : 'ok'
        };
      });

      return {
        deviceId: track.deviceId,
        deviceTag: track.deviceTags,
        vmType: track.vmType,
        lastUpdate: track.gmtUpdate,
        items
      };
    });

    res.json({
      success: true,
      data: inventory
    });

  } catch (error) {
    console.error('Inventory error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/:deviceId/sales', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { days = 7 } = req.query;

    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    if (startDate.getMonth() !== endDate.getMonth()) {
      startDate.setDate(1);
    }

    const result = await yileApi.sales.getSalesSuccess({
      deviceId,
      currPage: 1,
      pageSize: 100,
      startTime: formatYileDate(startDate),
      endTime: formatYileDate(endDate)
    });

    if (!result.success) {
      return res.status(500).json({
        success: false,
        error: result.error
      });
    }

    const rows = result.rows || result.data?.rows || [];
    
    const salesByRecipe = {};
    rows.forEach(sale => {
      const key = sale.goodsName || 'Unknown';
      if (!salesByRecipe[key]) {
        salesByRecipe[key] = {
          name: sale.goodsName,
          count: 0,
          revenue: 0
        };
      }
      salesByRecipe[key].count++;
      salesByRecipe[key].revenue += parseFloat(sale.goodsPrice || 0);
    });

    res.json({
      success: true,
      data: {
        period: { days: parseInt(days), startDate, endDate },
        total: result.total || rows.length,
        sales: rows,
        summary: Object.values(salesByRecipe).sort((a, b) => b.count - a.count)
      }
    });

  } catch (error) {
    console.error('Sales error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.post('/:deviceId/restart', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const result = await yileApi.devices.restartDevice(deviceId);
    
    res.json({
      success: result.success,
      message: result.success ? 'Restart command sent' : result.error,
      data: result.data
    });
  } catch (error) {
    console.error('Restart error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.post('/:deviceId/brew', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { recipeName } = req.body;
    
    if (!recipeName) {
      return res.status(400).json({
        success: false,
        error: 'recipeName is required'
      });
    }

    const result = await yileApi.remote.pushRemoteBrew(deviceId, recipeName);
    
    res.json({
      success: result.success,
      message: result.success ? 'Brew command sent' : result.error,
      pushId: result.data?.pushId,
      data: result.data
    });
  } catch (error) {
    console.error('Brew error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/:deviceId/recipes', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    console.log(`[Fleet] Fetching recipes for device: ${deviceId}`);
    
    const result = await yileApi.devices.getDeviceRecipes(deviceId);
    
    if (!result.success) {
      return res.json({
        success: false,
        error: result.error || 'Could not fetch recipes from machine',
        data: []
      });
    }
    
    const rawRecipes = result.data || result.rows || [];
    console.log(`[Fleet] Found ${rawRecipes.length} recipes on device ${deviceId}`);
    
    // Normalize recipe field names for frontend compatibility
    const recipes = rawRecipes.map((r, idx) => ({
      id: r.id || r.recipeId || r.coffeeId || idx,
      coffeeName: r.coffeeName || r.coffee_name || r.recipeName || r.name || 'Unknown Recipe',
      price: r.price || r.salePrice || 0,
      type: r.type,
      steps: r.steps
    }));
    
    res.json({
      success: true,
      source: 'device',
      data: recipes
    });
  } catch (error) {
    console.error('Device recipes error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      data: []
    });
  }
});

export default router;
