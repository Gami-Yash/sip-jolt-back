/**
 * Yile API Devices Module
 * Device status, inventory, recipes, and control
 */

import { validateDeviceId, parseCommaSeparated } from './utils.js';

export default function createDevicesModule(client) {
  return {
    async getDeviceStatus(deviceId = null) {
      const body = deviceId ? { deviceId: validateDeviceId(deviceId) } : {};
      return client.request('deviceinfo/find.do', body);
    },

    async getDeviceStatusSummary(deviceId) {
      const result = await this.getDeviceStatus(deviceId);
      
      if (!result.success) {
        return { online: false, error: result.error };
      }

      const data = Array.isArray(result.data) ? result.data[0] : result.data;
      
      return {
        online: data?.deviceStatus === 1,
        deviceId: data?.deviceId,
        workStatus: data?.workStatus,
        workStatusText: this.getWorkStatusText(data?.workStatus),
        signalStrength: data?.netSignal,
        errorInfo: data?.deviceErrorInfo,
        lastUpdate: data?.gmtUpdate,
        location: {
          latitude: data?.deviceLatitude,
          longitude: data?.deviceLongitude
        }
      };
    },

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
    },

    async getDeviceInventory(deviceId, deviceTags = null) {
      const body = { deviceId: validateDeviceId(deviceId) };
      if (deviceTags) {
        body.deviceTags = deviceTags;
      }
      return client.request('track/find.do', body);
    },

    async getDeviceRecipes(deviceId) {
      return client.request('push/queryCoffee.do', {
        deviceId: validateDeviceId(deviceId)
      });
    },

    async restartDevice(deviceIds) {
      return client.request('push/pushRestartMachine.do', {
        deviceIds: parseCommaSeparated(deviceIds)
      });
    },

    mapInventoryToGate5(inventoryData) {
      if (!inventoryData) return null;
      
      const item = Array.isArray(inventoryData) ? inventoryData[0] : inventoryData;
      
      return {
        'Zone B - Oat Powder': item?.['powder-1'],
        'Zone B - Dairy Powder': item?.['powder-2'],
        'Zone B - Coffee Beans': item?.['powder-3'],
        'Zone C - Matcha': item?.['powder-4'],
        'Zone C - Chai': item?.['powder-5'],
        'Zone C - Cocoa': item?.['powder-6'],
        'Cups': item?.cup,
        'Coffee Beans (Hopper)': item?.coffeeBean
      };
    }
  };
}
