/**
 * Yile API Goods Module
 * Vending machine products catalog
 */

import { validateDeviceId } from './utils.js';

export default function createGoodsModule(client) {
  return {
    async getVendingGoods(currPage = 1, pageSize = 15) {
      return client.request('goods/queryPage.do', { currPage, pageSize });
    },

    async getDeviceGoods(deviceId) {
      return client.request('goods/deviceGoods.do', {
        deviceId: validateDeviceId(deviceId)
      });
    },

    async getAllVendingGoods() {
      const allGoods = [];
      let page = 1;
      const pageSize = 50;
      let total = 0;

      do {
        const result = await this.getVendingGoods(page, pageSize);
        if (!result.success) {
          break;
        }

        const goods = result.rows || [];
        total = result.total || 0;
        allGoods.push(...goods);
        page++;
      } while (allGoods.length < total && page <= 20);

      return { success: true, rows: allGoods, total: allGoods.length };
    }
  };
}
