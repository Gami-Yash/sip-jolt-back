/**
 * Maps Yile API ingredient names to SIPJOLT standard names
 * Handles both Chinese and English variations
 */
const INGREDIENT_MAPPING = {
  // Coffee beans
  '咖啡豆': 'Coffee Beans',
  'Coffee Beans': 'Coffee Beans',
  'coffeeBean': 'Coffee Beans',
  
  // Powders
  'Oat Milk': 'Oat Milk',
  '燕麦奶': 'Oat Milk',
  'Matcha': 'Matcha',
  '抹茶': 'Matcha',
  'Chai': 'Chai',
  'Cocoa': 'Cocoa',
  '可可': 'Cocoa',
  
  // Syrups
  'Vanilla Syrup': 'Vanilla Syrup',
  '香草糖浆': 'Vanilla Syrup',
  'Brown Sugar Syrup': 'Brown Sugar Syrup',
  'Coconut Syrup': 'Coconut Syrup',
  'Lavendar Syrup': 'Lavender Syrup',
  
  // Cups & Water
  '杯子': 'Cups',
  'Cups': 'Cups',
  'cup': 'Cups',
  '水': 'Hot Water',
  'Hot Water': 'Hot Water',
  'hotWater': 'Hot Water'
};

function normalizeIngredientName(yileName) {
  return INGREDIENT_MAPPING[yileName] || yileName;
}

module.exports = { normalizeIngredientName, INGREDIENT_MAPPING };
