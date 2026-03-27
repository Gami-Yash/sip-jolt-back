/**
 * SIPJOLT Yile API V5.3 Client
 * Official integration with Yile/CoffeeNet APIs
 * 
 * Base URL: https://new.yilevme.com/ylvm3.0
 * Department ID: 13905
 * 
 * Features:
 * - Auto token refresh (every 2.5 hours)
 * - Comprehensive error handling
 * - Request retry logic
 * - Rate limit awareness
 * - All official V5.3 endpoints
 */

import axios from 'axios';

class YileApiClient {
  constructor() {
    this.baseUrl = process.env.YILE_API_BASE_URL || 'http://yleapi.yilevme.com';
    this.departmentId = process.env.YILE_DEPARTMENT_ID;
    this.secretKey = process.env.YILE_SECRET_KEY;
    this.enabled = process.env.YILE_INTEGRATION_ENABLED === 'true';
    
    this.token = null;
    this.tokenExpiry = null;
    this.tokenRefreshInProgress = false;
    
    this.requestCount = 0;
    this.requestWindowStart = Date.now();
    this.maxRequestsPerMinute = 100;
    
    console.log('[YileAPI] Client initialized', {
      baseUrl: this.baseUrl,
      departmentId: this.departmentId,
      enabled: this.enabled
    });
  }

  checkEnabled() {
    if (!this.enabled) {
      throw new Error('Yile integration is disabled. Set YILE_INTEGRATION_ENABLED=true in environment.');
    }
  }

  async getToken() {
    this.checkEnabled();
    
    if (this.token && this.tokenExpiry && Date.now() < this.tokenExpiry) {
      return this.token;
    }

    if (this.tokenRefreshInProgress) {
      console.log('[YileAPI] Token refresh in progress, waiting...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      return this.getToken();
    }

    this.tokenRefreshInProgress = true;

    try {
      console.log('[YileAPI] Fetching new token...');
      
      const response = await axios.post(`${this.baseUrl}/token/getToken.do`, {
        departmentId: parseInt(this.departmentId),
        secretKey: this.secretKey
      }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 10000
      });

      console.log('[YileAPI] Token response:', {
        code: response.data.code,
        hasMsg: !!response.data.msg
      });

      if (String(response.data.code) === '1') {
        this.token = response.data.msg;
        this.tokenExpiry = Date.now() + (2.5 * 60 * 60 * 1000);
        
        console.log('[YileAPI] Token refreshed successfully', {
          expiresAt: new Date(this.tokenExpiry).toISOString()
        });
        
        return this.token;
      } else {
        throw new Error(`Token fetch failed with code ${response.data.code}: ${response.data.message || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('[YileAPI] Token fetch error:', {
        message: error.message,
        response: error.response?.data
      });
      throw new Error(`Failed to get Yile token: ${error.message}`);
    } finally {
      this.tokenRefreshInProgress = false;
    }
  }

  checkRateLimit() {
    const now = Date.now();
    const windowElapsed = now - this.requestWindowStart;
    
    if (windowElapsed >= 60000) {
      this.requestCount = 0;
      this.requestWindowStart = now;
    }
    
    if (this.requestCount >= this.maxRequestsPerMinute) {
      throw new Error(`Rate limit exceeded: ${this.maxRequestsPerMinute} requests per minute. Wait ${Math.ceil((60000 - windowElapsed) / 1000)}s.`);
    }
    
    this.requestCount++;
  }

  async request(endpoint, data = {}, options = {}) {
    this.checkEnabled();
    this.checkRateLimit();
    
    const maxRetries = options.maxRetries || 2;
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const token = await this.getToken();
        
        console.log(`[YileAPI] Request to ${endpoint} (attempt ${attempt}/${maxRetries})`);
        
        const response = await axios.post(
          `${this.baseUrl}/${endpoint}`,
          data,
          {
            headers: {
              'Content-Type': 'application/json',
              'YiToken': token
            },
            timeout: options.timeout || 30000
          }
        );

        console.log(`[YileAPI] Response from ${endpoint}:`, {
          code: response.data.code,
          success: response.data.success,
          isDataEncrypted: response.data.isDataEncrypted
        });

        if (response.data.code === 9) {
          console.log('[YileAPI] Token expired (Code 9), forcing refresh...');
          this.token = null;
          
          if (attempt < maxRetries) {
            await new Promise(resolve => setTimeout(resolve, 1000));
            continue;
          }
        }

        if (response.data.code === 0) {
          console.warn('[YileAPI] Business error:', response.data.message);
          return {
            success: false,
            code: 0,
            message: response.data.message || 'Business error',
            data: null
          };
        }

        // Yile API returns data in 'msg' field, not 'data'
        const responseData = response.data.msg || response.data.data;
        
        return {
          success: true,
          code: response.data.code,
          data: responseData,
          rows: responseData?.rows || [],
          total: responseData?.total || 0,
          isEncrypted: response.data.isDataEncrypted === true,
          serverTime: response.data.serverTime,
          raw: response.data
        };

      } catch (error) {
        lastError = error;
        console.error(`[YileAPI] Request failed (attempt ${attempt}/${maxRetries}):`, {
          endpoint,
          error: error.message,
          response: error.response?.data
        });
        
        if (error.response?.status === 404 || error.response?.status === 400) {
          break;
        }
        
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
        }
      }
    }

    throw new Error(`Request to ${endpoint} failed after ${maxRetries} attempts: ${lastError.message}`);
  }

  async getDeviceStatus(deviceId) {
    return this.request('deviceinfo/find.do', { deviceId });
  }

  async getInventory(deviceId) {
    return this.request('track/find.do', { deviceId });
  }

  async getSales(deviceId, startTime, endTime, pageNum = 1, pageSize = 20) {
    return this.request('sale/queryPage.do', {
      deviceId,
      startTime,
      endTime,
      pageNum,
      pageSize
    });
  }

  async getFailedSales(deviceId, startTime, endTime, pageNum = 1, pageSize = 20) {
    return this.request('saleFailed/queryPage.do', {
      deviceId,
      startTime,
      endTime,
      pageNum,
      pageSize
    });
  }

  async getRecipeCatalog(pageNum = 1, pageSize = 50) {
    return this.request('goods/queryCoffeeRecipe.do', { currPage: pageNum, pageSize });
  }

  async getAllRecipes() {
    const allRecipes = [];
    let page = 1;
    const pageSize = 50;
    let total = 0;

    do {
      const result = await this.getRecipeCatalog(page, pageSize);
      if (!result.success) {
        throw new Error(`Failed to fetch recipes page ${page}: ${result.message}`);
      }

      const recipes = result.rows || [];
      total = result.total || 0;
      allRecipes.push(...recipes);

      console.log(`[YileAPI] Fetched page ${page}: ${recipes.length} recipes (${allRecipes.length}/${total})`);
      page++;
    } while (allRecipes.length < total && page <= 20); // Safety limit

    return { success: true, rows: allRecipes, total: allRecipes.length };
  }

  async getMachineMenu(deviceId) {
    return this.request('push/queryCoffee.do', { deviceId });
  }

  async addRecipe(recipeData) {
    return this.request('coffee/addCoffeeRecipe.do', recipeData);
  }

  async editRecipe(recipeData) {
    return this.request('coffee/editCoffeeRecipe.do', recipeData);
  }

  async deleteRecipe(recipeId) {
    return this.request('coffee/deleteCoffeeRecipe.do', { recipeId });
  }

  async remoteBrew(deviceId, recipeName) {
    const status = await this.getDeviceStatus(deviceId);
    
    if (!status.success) {
      throw new Error('Failed to get device status before brew');
    }

    const workStatus = status.data?.workStatus;
    
    if (workStatus !== undefined && workStatus !== 0) {
      throw new Error(`Machine is busy (workStatus=${workStatus}). Cannot brew.`);
    }

    return this.request('push/pushRemoteDrinking.do', {
      deviceId,
      recipeName
    });
  }

  async queryPushResult(pushId) {
    return this.request('push/queryPushResult.do', { pushId });
  }

  async pollPushResult(pushId, maxAttempts = 60, intervalMs = 2000) {
    console.log(`[YileAPI] Polling push result for pushId: ${pushId}`);
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const result = await this.queryPushResult(pushId);
      
      if (!result.success) {
        console.warn(`[YileAPI] Poll attempt ${attempt} failed:`, result);
        continue;
      }

      const makeResult = result.data?.makeResult;
      
      if (makeResult === 1) {
        console.log(`[YileAPI] Push completed successfully after ${attempt} attempts`);
        return { success: true, result: result.data };
      } else if (makeResult === 0) {
        console.log(`[YileAPI] Push failed after ${attempt} attempts`);
        return { success: false, result: result.data };
      }

      console.log(`[YileAPI] Push in progress (attempt ${attempt}/${maxAttempts})...`);
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }

    throw new Error(`Push result polling timed out after ${maxAttempts * intervalMs / 1000}s`);
  }

  async restartMachine(deviceId) {
    return this.request('push/pushRestartMachine.do', { deviceId });
  }

  async pushRecipeToDevice(deviceId, recipeId) {
    return this.request('push/pushCoffeeRecipe.do', {
      deviceId,
      recipeId
    });
  }

  async pushPrice(deviceId, priceData) {
    return this.request('push/pushPrice.do', {
      deviceId,
      ...priceData
    });
  }

  async pushAds(deviceId, adData) {
    return this.request('push/pushAds.do', {
      deviceId,
      ...adData
    });
  }

  async getDepartmentInfo() {
    return this.request('department/queryDepartment.do', {});
  }

  mapInventoryToGate5(inventoryData) {
    if (!inventoryData) return null;
    
    return {
      'Zone B - Oat Powder': inventoryData['powder-1'],
      'Zone B - Dairy Powder': inventoryData['powder-2'],
      'Zone B - Coffee Beans': inventoryData['powder-3'],
      'Zone C - Matcha': inventoryData['powder-4'],
      'Zone C - Chai': inventoryData['powder-5'],
      'Zone C - Cocoa': inventoryData['powder-6'],
      'Cups': inventoryData['cup'],
      'Coffee Beans (Hopper)': inventoryData['coffeeBean']
    };
  }

  async getDeviceStatusSummary(deviceId) {
    const result = await this.getDeviceStatus(deviceId);
    
    if (!result.success) {
      return { online: false, error: result.message };
    }

    const data = result.data;
    
    return {
      online: data.deviceStatus === 1,
      workStatus: data.workStatus,
      workStatusText: this.getWorkStatusText(data.workStatus),
      signalStrength: data.netSignal,
      errorInfo: data.deviceErrorInfo,
      lastUpdate: data.gmtUpdate,
      location: {
        latitude: data.deviceLatitude,
        longitude: data.deviceLongitude
      }
    };
  }

  getWorkStatusText(workStatus) {
    const statusMap = {
      0: 'Ready (Idle)',
      1: 'Selecting Sugar',
      2: 'Processing Payment',
      3: 'Brewing',
      5: 'Dispensing Lid',
      6: 'Settings Mode'
    };
    return statusMap[workStatus] || `Unknown (${workStatus})`;
  }
}

const yileClient = new YileApiClient();
export default yileClient;
