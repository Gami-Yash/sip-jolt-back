/**
 * Yile API Sales Module
 * Success and failed sales records
 */

import { formatYileDate, validateDateRange, getSameMonthRange, validateDeviceId } from './utils.js';

export default function createSalesModule(client) {
  return {
    async getSalesSuccess(params = {}) {
      const { startTime, endTime } = params.startTime && params.endTime 
        ? { startTime: params.startTime, endTime: params.endTime }
        : getSameMonthRange();
      
      if (params.startTime && params.endTime) {
        validateDateRange(params.startTime, params.endTime);
      }

      const body = {
        currPage: params.currPage || 1,
        pageSize: params.pageSize || 20,
        startTime: typeof startTime === 'string' && startTime.includes(':') 
          ? startTime 
          : formatYileDate(startTime),
        endTime: typeof endTime === 'string' && endTime.includes(':') 
          ? endTime 
          : formatYileDate(endTime, true)
      };

      if (params.deviceId) {
        body.deviceId = validateDeviceId(params.deviceId);
      }

      if (params.useDeviceDate !== undefined) {
        body.useDeviceDate = params.useDeviceDate ? 1 : 0;
      }

      return client.request('sale/queryPage.do', body);
    },

    async getSalesFailed(params = {}) {
      const { startTime, endTime } = params.startTime && params.endTime 
        ? { startTime: params.startTime, endTime: params.endTime }
        : getSameMonthRange();
      
      if (params.startTime && params.endTime) {
        validateDateRange(params.startTime, params.endTime);
      }

      const body = {
        currPage: params.currPage || 1,
        pageSize: params.pageSize || 20,
        startTime: typeof startTime === 'string' && startTime.includes(':') 
          ? startTime 
          : formatYileDate(startTime),
        endTime: typeof endTime === 'string' && endTime.includes(':') 
          ? endTime 
          : formatYileDate(endTime, true)
      };

      if (params.deviceId) {
        body.deviceId = validateDeviceId(params.deviceId);
      }

      if (params.useDeviceDate !== undefined) {
        body.useDeviceDate = params.useDeviceDate ? 1 : 0;
      }

      return client.request('saleFailed/queryPage.do', body);
    },

    async getSalesSummary(deviceId, month = null) {
      const dateRange = month ? getSameMonthRange(new Date(month)) : getSameMonthRange();
      
      const [success, failed] = await Promise.all([
        this.getSalesSuccess({ deviceId, ...dateRange, pageSize: 1 }),
        this.getSalesFailed({ deviceId, ...dateRange, pageSize: 1 })
      ]);

      return {
        success: success.success && failed.success,
        deviceId,
        period: dateRange,
        successCount: success.total || 0,
        failedCount: failed.total || 0,
        totalTransactions: (success.total || 0) + (failed.total || 0)
      };
    }
  };
}
