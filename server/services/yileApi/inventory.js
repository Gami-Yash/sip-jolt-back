/**
 * Yile API Inventory Module
 * Powders and optional formulas management
 */

export default function createInventoryModule(client) {
  return {
    async getPowders(currPage = 1, pageSize = 15) {
      return client.request('coffee/selectCoffeePowder.do', { currPage, pageSize });
    },

    async addPowder(name) {
      if (!name || typeof name !== 'string') {
        return { success: false, error: 'Powder name is required' };
      }
      return client.request('coffee/addCoffeePowder.do', { name });
    },

    async deletePowder(id) {
      return client.request('coffee/deleteCoffeePowder.do', { id });
    },

    async getOptionalFormulas(currPage = 1, pageSize = 15) {
      return client.request('coffee/selectCoffeeOptionalFormula.do', { currPage, pageSize });
    },

    async getOptionalFormulaById(id) {
      return client.request('coffee/selectCoffeeOptionalFormulaById.do', { id });
    },

    async addOptionalFormula(name, steps, powderName) {
      if (!name || !steps) {
        return { success: false, error: 'Name and steps are required' };
      }
      
      return client.request('coffee/addCoffeeOptionalFormula.do', {
        name,
        steps: typeof steps === 'string' ? steps : JSON.stringify(steps),
        powderName: powderName || null
      });
    },

    async updateOptionalFormula(id, name, steps, powderName) {
      return client.request('coffee/updateCoffeeOptionalFormulaById.do', {
        id,
        name,
        steps: typeof steps === 'string' ? steps : JSON.stringify(steps),
        powderName: powderName || null
      });
    },

    async deleteOptionalFormula(id) {
      return client.request('coffee/deleteCoffeeOptionalFormula.do', { id });
    }
  };
}
