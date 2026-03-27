/**
 * Yile API Recipes Module
 * Recipe CRUD operations and device push
 */

import { parseCommaSeparated } from './utils.js';

export default function createRecipesModule(client) {
  return {
    async getOperatorRecipes(currPage = 1, pageSize = 50) {
      return client.request('goods/queryCoffeeRecipe.do', { currPage, pageSize });
    },

    async getAllRecipes() {
      const allRecipes = [];
      let page = 1;
      const pageSize = 50;
      let total = 0;

      do {
        const result = await this.getOperatorRecipes(page, pageSize);
        if (!result.success) {
          throw new Error(`Failed to fetch recipes page ${page}: ${result.error}`);
        }

        const recipes = result.rows || [];
        total = result.total || 0;
        allRecipes.push(...recipes);

        console.log(`[YileAPI] Fetched page ${page}: ${recipes.length} recipes (${allRecipes.length}/${total})`);
        page++;
      } while (allRecipes.length < total && page <= 20);

      return { success: true, rows: allRecipes, total: allRecipes.length };
    },

    async getRecipeById(id) {
      return client.request('coffee/findCoffeeRecipeById.do', { id });
    },

    async addRecipe(recipeData) {
      const requiredFields = ['boxNum', 'price', 'coffeeName', 'steps'];
      for (const field of requiredFields) {
        if (recipeData[field] === undefined) {
          return { success: false, error: `Missing required field: ${field}` };
        }
      }

      return client.request('coffee/addCoffeeRecipe.do', recipeData);
    },

    async updateRecipe(id, recipeData) {
      return client.request('coffee/editCoffeeRecipe.do', { id, ...recipeData });
    },

    async deleteRecipe(id) {
      return client.request('coffee/deleteCoffeeRecipe.do', { id });
    },

    async pushRecipeToDevice(deviceIds, recipeIds) {
      return client.request('push/pushCoffeeRecipe.do', {
        deviceIds: parseCommaSeparated(deviceIds),
        recipeIds: parseCommaSeparated(recipeIds)
      });
    },

    buildRecipePayload(params) {
      return {
        boxNum: params.boxNum,
        price: params.price,
        coffeeCostPrice: params.coffeeCostPrice || 0,
        coffeeName: params.coffeeName,
        coffeeImg: params.coffeeImg || null,
        coffeeInfo: params.coffeeInfo || null,
        nikeName: params.nikeName || '',
        steps: typeof params.steps === 'string' ? params.steps : JSON.stringify(params.steps),
        classifyIndex: params.classifyIndex || 0,
        groupName: params.groupName || null,
        coffeeNum: params.coffeeNum || 1,
        type: params.type || 0
      };
    }
  };
}
