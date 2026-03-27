const { normalizeIngredientName } = require('./ingredientMapping.cjs');

/**
 * Finds and normalizes a Yile inventory item by its name.
 */
function findYileItem(yileData, ingredientName) {
  if (!yileData || !Array.isArray(yileData)) return null;
  
  for (const track of yileData) {
    if (!track.goodsNoInfoList) continue;
    
    for (const item of track.goodsNoInfoList) {
      const normalizedName = normalizeIngredientName(item.goodsName);
      
      if (normalizedName === ingredientName) {
        return {
          ...item,
          normalizedName,
          deviceTag: track.deviceTags,
          nowStock: parseInt(item.nowStock) || 0,
          maxStock: parseInt(item.maxStock) || 1,
          typeId: item.storeType || item.inventoryType
        };
      }
    }
  }
  
  return null;
}

module.exports = { findYileItem };
