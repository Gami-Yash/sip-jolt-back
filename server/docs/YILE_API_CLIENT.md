# SIPJOLT Yile API Client Library

Complete client library for Yile Coffee Machine API V5.3.

## Quick Start

```javascript
import yileApi from './server/services/yileApi/index.js';

// Get device status
const status = await yileApi.devices.getDeviceStatus('00000020868');

// Get all recipes (332 total)
const recipes = await yileApi.recipes.getAllRecipes();

// Get sales for current month
const sales = await yileApi.sales.getSalesSuccess({ deviceId: '00000020868' });
```

## Configuration

Set environment variables:
```bash
YILE_API_BASE_URL=http://yleapi.yilevme.com
YILE_DEPARTMENT_ID=13905
YILE_SECRET_KEY=your_secret_key
YILE_INTEGRATION_ENABLED=true
```

## Modules

### Auth
```javascript
// Get token (auto-cached for 2h 55m)
const token = await yileApi.auth.getToken();

// Test token validity
const result = await yileApi.auth.testToken();

// Force refresh
yileApi.auth.invalidateToken();
await yileApi.auth.getToken(true);
```

### Devices
```javascript
// Get device status
await yileApi.devices.getDeviceStatus(deviceId);

// Get status summary (parsed)
await yileApi.devices.getDeviceStatusSummary(deviceId);

// Get inventory
await yileApi.devices.getDeviceInventory(deviceId);

// Get device menu (recipes on machine)
await yileApi.devices.getDeviceRecipes(deviceId);

// Restart device
await yileApi.devices.restartDevice(deviceId);
```

### Sales
```javascript
// Get successful sales (current month)
await yileApi.sales.getSalesSuccess({ 
  deviceId, 
  pageSize: 20 
});

// Get failed sales
await yileApi.sales.getSalesFailed({ deviceId });

// Get sales summary
await yileApi.sales.getSalesSummary(deviceId);
```

**Note:** Yile API requires start/end dates to be in the same month.

### Recipes
```javascript
// Get operator recipe catalog (paginated)
await yileApi.recipes.getOperatorRecipes(page, pageSize);

// Get ALL recipes (auto-pagination)
await yileApi.recipes.getAllRecipes();

// Get recipe by ID
await yileApi.recipes.getRecipeById(id);

// Add recipe
await yileApi.recipes.addRecipe({
  boxNum: 5,
  price: 4.50,
  coffeeName: 'Latte',
  steps: [...],
  type: 0
});

// Update recipe
await yileApi.recipes.updateRecipe(id, recipeData);

// Delete recipe
await yileApi.recipes.deleteRecipe(id);

// Push recipe to device
await yileApi.recipes.pushRecipeToDevice(deviceIds, recipeIds);
```

### Remote Operations
```javascript
// Remote brew (checks machine status first)
await yileApi.remote.pushRemoteBrew(deviceId, recipeName);

// Query push result
await yileApi.remote.queryPushResult(pushId);

// Poll for push completion
await yileApi.remote.pollPushResult(pushId, maxAttempts, intervalMs);

// Push price update
await yileApi.remote.pushPrice(deviceIds, name, price);

// Push ads
await yileApi.remote.pushAds(deviceIds, adType, scene, urls);
```

### Inventory
```javascript
// Get powders
await yileApi.inventory.getPowders();

// Add powder
await yileApi.inventory.addPowder(name);

// Get optional formulas (sugar levels)
await yileApi.inventory.getOptionalFormulas();

// Add optional formula
await yileApi.inventory.addOptionalFormula(name, steps, powderName);
```

### Operators
```javascript
// Get operator/department info
await yileApi.operators.getOperatorInfo();

// Get parsed details
await yileApi.operators.getOperatorDetails();
```

### Goods (Vending Machines)
```javascript
// Get vending goods catalog
await yileApi.goods.getVendingGoods();

// Get goods on specific device
await yileApi.goods.getDeviceGoods(deviceId);
```

## Utilities
```javascript
import { 
  formatYileDate, 
  validateDateRange, 
  getSameMonthRange 
} from './server/services/yileApi/utils.js';

// Format date for Yile API
formatYileDate(new Date()); // "2026-01-27 00:00:00"

// Get current month range
getSameMonthRange(); // { startTime, endTime }

// Validate date range (throws if cross-month)
validateDateRange(start, end);
```

## Diagnostics
```javascript
// Run full diagnostics for a device
const report = await yileApi.runDiagnostics('00000020868');
console.log(report.summary.passRate); // "85%"

// Test connection
const conn = await yileApi.testConnection();
```

## Running Tests
```bash
node server/tests/yileApi/runAllTests.js
```

## Response Format
All methods return normalized responses:
```javascript
{
  success: true,
  data: {...},
  rows: [...],
  total: 332,
  currPage: 1,
  pageSize: 50
}
```

## Error Handling
```javascript
const result = await yileApi.devices.getDeviceStatus(deviceId);

if (!result.success) {
  console.error('Error:', result.error);
  if (result.tokenError) {
    // Token expired - will auto-retry
  }
}
```

## Known Quirks
1. Response data is in `msg.rows[]` not `data[]` - normalized automatically
2. Code is string `"1"` not integer `1` - handled automatically
3. Date queries must be same month/year - validated with error
4. Token errors return code `"9"` - auto-refresh triggered
5. Rate limiting possible - 100ms delay between requests
