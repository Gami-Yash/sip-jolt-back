/**
 * SIPJOLT OS - Yile API Service
 * Production-ready for Replit (Single-Site Deployment)
 * 
 * COPY TO: /server/services/yile/yileApiService.js
 */

import axios from 'axios';
import { pool } from '../../../shared/db.js';

class YileApiService {
  constructor() {
    this.baseUrl = process.env.YILE_API_BASE_URL || 'https://new.yilevme.com/ylvm3.0';
    this.departmentId = process.env.YILE_DEPARTMENT_ID || '13905';
    this.secretKey = process.env.YILE_SECRET_KEY || '20b98a1461af3b276ba81eadc40ba999';
    
    // Rate limiting (prevent vendor ban)
    this.callsThisMinute = 0;
    this.minuteStart = Date.now();
    this.MAX_CALLS_PER_MINUTE = 100;
    
    console.log('[YileAPI] Service initialized');
  }

  async checkRateLimit() {
    const now = Date.now();
    
    if (now - this.minuteStart > 60000) {
      this.callsThisMinute = 0;
      this.minuteStart = now;
    }

    if (this.callsThisMinute >= this.MAX_CALLS_PER_MINUTE) {
      throw new Error('Rate limit exceeded (100 calls/min)');
    }

    this.callsThisMinute++;
  }

  async getYiToken() {
    try {
      const result = await pool.query(`
        SELECT token, expires_at 
        FROM vendor_tokens 
        WHERE vendor = 'YILE'
        AND expires_at > NOW() + INTERVAL '30 minutes'
        ORDER BY refreshed_at DESC 
        LIMIT 1
      `);

      if (result.rows.length > 0) {
        return result.rows[0].token;
      }

      return await this.refreshToken();
    } catch (error) {
      console.error('[YileAPI] Token error:', error);
      throw error;
    }
  }

  async refreshToken() {
    try {
      console.log('[YileAPI] Refreshing token...');

      const response = await axios.post(`${this.baseUrl}/token/getToken.do`, {
        departmentId: this.departmentId,
        secretKey: this.secretKey,
      }, { timeout: 10000 });

      console.log('[YileAPI] Token response:', JSON.stringify(response.data));
      
      if (response.data.code !== '1') {
        throw new Error(`Token refresh failed: ${response.data.msg}`);
      }

      // Token may be in yiToken or msg field depending on API version
      const yiToken = response.data.yiToken || response.data.msg;
      
      if (!yiToken) {
        throw new Error('No token returned from Yile API');
      }
      const expiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000);

      await pool.query(`
        INSERT INTO vendor_tokens (vendor, token, expires_at, refreshed_at)
        VALUES ('YILE', $1, $2, NOW())
      `, [yiToken, expiresAt]);

      console.log('[YileAPI] Token refreshed, expires', expiresAt.toISOString());
      return yiToken;
    } catch (error) {
      console.error('[YileAPI] Refresh failed:', error.message);
      throw error;
    }
  }

  async apiCall(endpoint, payload = {}, options = {}) {
    await this.checkRateLimit();

    const maxRetries = options.maxRetries || 3;
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const yiToken = await this.getYiToken();

        const response = await axios.post(`${this.baseUrl}${endpoint}`, payload, {
          headers: {
            'Content-Type': 'application/json',
            'YiToken': yiToken,
          },
          timeout: 30000,
        });

        if (response.data.code === '9') {
          console.log('[YileAPI] Token exception, refreshing...');
          await this.refreshToken();
          continue;
        }

        if (response.data.code !== '1') {
          throw new Error(`API error (code ${response.data.code}): ${response.data.msg}`);
        }

        return response.data;
      } catch (error) {
        lastError = error;
        
        if (error.response?.status >= 400 && error.response?.status < 500) {
          throw error;
        }

        if (attempt < maxRetries) {
          console.log(`[YileAPI] Retry ${attempt}/${maxRetries}`);
          await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        }
      }
    }

    throw lastError;
  }

  async findDeviceInfo(deviceId) {
    const response = await this.apiCall('/deviceinfo/find.do', { deviceId });

    try {
      await pool.query(`
        INSERT INTO yile_machine_status (
          device_id, device_status, work_status, net_signal,
          device_longitude, device_latitude, device_error_info,
          gmt_update, device_date, cached_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        ON CONFLICT (device_id) DO UPDATE SET
          device_status = EXCLUDED.device_status,
          work_status = EXCLUDED.work_status,
          net_signal = EXCLUDED.net_signal,
          device_longitude = EXCLUDED.device_longitude,
          device_latitude = EXCLUDED.device_latitude,
          device_error_info = EXCLUDED.device_error_info,
          gmt_update = EXCLUDED.gmt_update,
          device_date = EXCLUDED.device_date,
          cached_at = NOW()
      `, [
        deviceId, response.deviceStatus, response.workStatus, response.netSignal,
        response.deviceLongitude, response.deviceLatitude, response.deviceErrorInfo,
        response.gmtUpdate, response.deviceDate,
      ]);
    } catch (err) {
      console.error('[YileAPI] Cache error:', err.message);
    }

    return response;
  }

  async getCachedStatus(deviceId) {
    const result = await pool.query(`
      SELECT * FROM yile_machine_status
      WHERE device_id = $1
      AND cached_at > NOW() - INTERVAL '60 seconds'
      LIMIT 1
    `, [deviceId]);

    return result.rows[0] || null;
  }

  async pushRemoteDrinking(deviceId, recipeName) {
    // Send brew command directly - machine will reject if busy
    const response = await this.apiCall('/push/pushRemoteDrinking.do', {
      deviceId,
      recipeName,
    });

    console.log('[YileAPI] Brew initiated:', response.pushId);
    return response.pushId;
  }

  async queryPushResult(pushId) {
    const response = await this.apiCall('/push/queryPushResult.do', { pushId });

    return {
      completed: response.makeResult !== undefined,
      success: response.makeResult === '1',
      message: response.msg,
      makeResult: response.makeResult,
    };
  }

  async pushRestartMachine(deviceId) {
    return await this.apiCall('/push/pushRestartMachine.do', { deviceIds: deviceId });
  }

  async findInventory(deviceId) {
    const response = await this.apiCall('/track/find.do', { deviceId });

    try {
      for (const item of response.list || []) {
        await pool.query(`
          INSERT INTO yile_inventory_cache (
            device_id, store_type, vm_now_store, vm_max_store, gmt_update, cached_at
          )
          VALUES ($1, $2, $3, $4, $5, NOW())
          ON CONFLICT (device_id, store_type) DO UPDATE SET
            vm_now_store = EXCLUDED.vm_now_store,
            vm_max_store = EXCLUDED.vm_max_store,
            gmt_update = EXCLUDED.gmt_update,
            cached_at = NOW()
        `, [deviceId, item.storeType, item.vmNowStore, item.vmMaxStore, item.gmtUpdate]);
      }
    } catch (err) {
      console.error('[YileAPI] Inventory cache error:', err.message);
    }

    return response;
  }

  async queryCoffee(deviceId) {
    return await this.apiCall('/push/queryCoffee.do', { deviceId });
  }

  async queryCoffeeRecipe(page = 1, pageSize = 100) {
    return await this.apiCall('/goods/queryCoffeeRecipe.do', { page, pageSize });
  }

  async addCoffeeRecipe(recipePayload) {
    return await this.apiCall('/coffee/addCoffeeRecipe.do', recipePayload);
  }

  async pushCoffeeRecipe(deviceIds, recipeIds) {
    const response = await this.apiCall('/push/pushCoffeeRecipe.do', { deviceIds, recipeIds });
    return response.pushId;
  }

  async querySales(deviceId, page = 1, pageSize = 100) {
    return await this.apiCall('/sale/queryPage.do', { deviceId, page, pageSize });
  }

  async queryFailedSales(deviceId, page = 1, pageSize = 100) {
    return await this.apiCall('/saleFailed/queryPage.do', { deviceId, page, pageSize });
  }
}

export default new YileApiService();
