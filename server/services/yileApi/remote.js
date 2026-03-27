/**
 * Yile API Remote Operations Module
 * Remote brew, ads, price updates, and push result polling
 */

import { parseCommaSeparated, validateDeviceId } from './utils.js';

export default function createRemoteModule(client) {
  return {
    async pushRemoteBrew(deviceId, recipeName) {
      if (!recipeName) {
        return { success: false, error: 'Recipe name is required' };
      }

      const statusResult = await client.request('deviceinfo/find.do', { 
        deviceId: validateDeviceId(deviceId) 
      });
      
      if (statusResult.success) {
        const data = Array.isArray(statusResult.data) ? statusResult.data[0] : statusResult.data;
        if (data?.workStatus !== undefined && data.workStatus !== 0) {
          return { 
            success: false, 
            error: `Machine is busy (workStatus=${data.workStatus}). Cannot brew.`
          };
        }
      }

      return client.request('push/pushRemoteDrinking.do', {
        deviceId: validateDeviceId(deviceId),
        recipeName
      });
    },

    async queryPushResult(pushId) {
      return client.request('push/queryPushResult.do', { pushId });
    },

    async pollPushResult(pushId, maxAttempts = 60, intervalMs = 2000) {
      console.log(`[YileAPI] Polling push result for pushId: ${pushId}`);
      
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        const result = await this.queryPushResult(pushId);
        
        if (!result.success) {
          console.warn(`[YileAPI] Poll attempt ${attempt} failed:`, result.error);
          continue;
        }

        const data = result.data;
        const makeResult = data?.makeResult;
        
        if (makeResult === 1 || makeResult === '1') {
          console.log(`[YileAPI] Push completed successfully after ${attempt} attempts`);
          return { success: true, result: data };
        } else if (makeResult === 0 || makeResult === '0') {
          console.log(`[YileAPI] Push failed after ${attempt} attempts`);
          return { success: false, result: data };
        }

        console.log(`[YileAPI] Push in progress (attempt ${attempt}/${maxAttempts})...`);
        await new Promise(resolve => setTimeout(resolve, intervalMs));
      }

      return { 
        success: false, 
        error: `Push result polling timed out after ${maxAttempts * intervalMs / 1000}s` 
      };
    },

    async pushPrice(deviceIds, name, price) {
      return client.request('push/pushPrice.do', {
        deviceIds: parseCommaSeparated(deviceIds),
        name,
        price
      });
    },

    async pushAds(deviceIds, adType, scene, urls, updateWay = null) {
      const body = {
        deviceIds: parseCommaSeparated(deviceIds),
        adType,
        scene,
        urls: Array.isArray(urls) ? urls.join(',') : urls
      };
      
      if (updateWay !== null) {
        body.updateWay = updateWay;
      }

      return client.request('push/pushAds.do', body);
    },

    async pushOptionalFormula(deviceIds, optionalFormulaId) {
      return client.request('push/pushOptionalFormula.do', {
        deviceIds: parseCommaSeparated(deviceIds),
        optionalFormulaId
      });
    }
  };
}
