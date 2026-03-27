/**
 * SIPJOLT Yile API Client Library
 * Complete implementation of Yile Coffee Machine API V5.3
 * 
 * Usage:
 *   import yileApi from './server/services/yileApi/index.js';
 *   
 *   // Get device status
 *   const status = await yileApi.devices.getDeviceStatus('00000020868');
 *   
 *   // Get all recipes
 *   const recipes = await yileApi.recipes.getAllRecipes();
 *   
 *   // Remote brew
 *   const brew = await yileApi.remote.pushRemoteBrew('00000020868', 'Latte');
 */

import YileApiClient from './client.js';
import createAuthModule from './auth.js';
import createDevicesModule from './devices.js';
import createSalesModule from './sales.js';
import createRecipesModule from './recipes.js';
import createRemoteModule from './remote.js';
import createInventoryModule from './inventory.js';
import createOperatorsModule from './operators.js';
import createGoodsModule from './goods.js';
import * as utils from './utils.js';

const client = new YileApiClient({
  baseURL: process.env.YILE_API_BASE_URL || 'http://yleapi.yilevme.com',
  departmentId: process.env.YILE_DEPARTMENT_ID || '13905',
  secretKey: process.env.YILE_SECRET_KEY,
  enabled: process.env.YILE_INTEGRATION_ENABLED === 'true'
});

const auth = createAuthModule(client);
client.setAuthModule(auth);

const devices = createDevicesModule(client);
const sales = createSalesModule(client);
const recipes = createRecipesModule(client);
const remote = createRemoteModule(client);
const inventory = createInventoryModule(client);
const operators = createOperatorsModule(client);
const goods = createGoodsModule(client);

const yileApi = {
  client,
  auth,
  devices,
  sales,
  recipes,
  remote,
  inventory,
  operators,
  goods,
  utils,
  
  async testConnection() {
    const results = {};
    
    console.log('[YileAPI] Running connection test...');
    
    try {
      results.token = await auth.testToken();
    } catch (error) {
      results.token = { success: false, error: error.message };
    }

    if (results.token.success) {
      try {
        results.operator = await operators.getOperatorInfo();
      } catch (error) {
        results.operator = { success: false, error: error.message };
      }
    }

    const successCount = Object.values(results).filter(r => r.success).length;
    
    return {
      success: successCount === Object.keys(results).length,
      passed: successCount,
      total: Object.keys(results).length,
      results
    };
  },

  async runDiagnostics(deviceId) {
    const results = {};
    
    console.log(`[YileAPI] Running diagnostics for device ${deviceId}...`);
    
    const tests = [
      ['token', () => auth.testToken()],
      ['deviceStatus', () => devices.getDeviceStatus(deviceId)],
      ['inventory', () => devices.getDeviceInventory(deviceId)],
      ['menu', () => devices.getDeviceRecipes(deviceId)],
      ['recipes', () => recipes.getOperatorRecipes(1, 5)],
      ['sales', () => sales.getSalesSuccess({ deviceId, pageSize: 1 })],
      ['operator', () => operators.getOperatorInfo()]
    ];

    for (const [name, test] of tests) {
      console.log(`[Diagnostics] Testing ${name}...`);
      try {
        results[name] = await test();
      } catch (error) {
        results[name] = { success: false, error: error.message };
      }
    }

    const successCount = Object.values(results).filter(r => r.success).length;
    
    return {
      success: true,
      summary: {
        passed: successCount,
        total: tests.length,
        passRate: `${Math.round((successCount / tests.length) * 100)}%`
      },
      results,
      timestamp: new Date().toISOString()
    };
  }
};

export default yileApi;
export { client, auth, devices, sales, recipes, remote, inventory, operators, goods, utils };
