/**
 * Machine Config Import Script
 * Imports actual Yile machine config (coffeeConfig.json) as Archive2 reference library
 * This is the real machine data - better than Excel!
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from '../../shared/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CONFIG_PATH = path.join(__dirname, '../../data/vm/config/coffeeConfig.json');
const MATERIALS_PATH = path.join(__dirname, '../../data/vm/config/coffeeMaterialPath.json');
const IMAGES_PATH = path.join(__dirname, '../../data/vm/goodsimg');

async function importMachineConfig() {
  console.log('Recipe Builder: Machine Config Import');
  console.log('Reading actual Yile machine configuration\n');

  try {
    const coffeeConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    const materialPaths = JSON.parse(fs.readFileSync(MATERIALS_PATH, 'utf8'));

    console.log(`Found ${coffeeConfig.length} recipes in coffeeConfig.json`);
    console.log(`Found ${materialPaths.length} material paths\n`);

    await importIngredients(materialPaths);
    await importRecipes(coffeeConfig, materialPaths);

    console.log('\nMachine config import complete!');
    console.log('Archive2 reference library populated with real machine data');

    process.exit(0);

  } catch (error) {
    console.error('Import failed:', error.message);
    console.error('Stack:', error.stack);
    process.exit(1);
  }
}

async function importIngredients(materialPaths) {
  console.log('Importing ingredients from material paths...');

  let imported = 0;

  for (const material of materialPaths) {
    if (!material.materialName || material.materialName === '') continue;

    const ingredientKey = material.materialName.toUpperCase().replace(/\s+/g, '_');
    const ingredientType = detectIngredientType(material.materialName);

    await pool.query(`
      INSERT INTO recipe_ingredients (
        ingredient_key, display_name, material_path_id, 
        ingredient_type, is_seasonal, notes
      ) VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (ingredient_key) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        material_path_id = EXCLUDED.material_path_id
    `, [
      ingredientKey,
      material.materialName,
      material.pathId,
      ingredientType,
      material.materialName.toLowerCase().includes('seasonal'),
      `Max stock: ${material.maxStock}, Alarm at: ${material.alarmStock}`
    ]);

    imported++;
  }

  console.log(`   Imported ${imported} ingredients\n`);
}

async function importRecipes(coffeeConfig, materialPaths) {
  console.log('Importing recipes from coffeeConfig...');

  const materialMap = new Map();
  materialPaths.forEach(m => materialMap.set(m.pathId, m.materialName));

  let imported = 0;

  for (const recipe of coffeeConfig) {
    if (!recipe.coffeeName || !recipe.isUse) {
      continue;
    }

    const steps = (recipe.steps || []).slice(0, 5).map((step, index) => ({
      stepNumber: index + 1,
      enabled: step.isUse === true,
      ingredientKey: step.isUse ? (materialMap.get(step.materialPathId) || step.box || null) : null,
      materialPathId: step.materialPathId || -1,
      box: step.box || null,
      water: step.isUse ? (step.water || 0) : -1,
      powderTime: step.isUse ? (step.powderTime || 0) : -1,
      mixTime: step.isUse ? (step.stirTime || 0) : -1,
      isIceWater: step.isIceWater || false
    }));

    const recipeType = recipe.type || 0;
    const milkType = detectMilkType(recipe.coffeeName, steps);
    const isCore = !recipe.coffeeName.toLowerCase().includes('seasonal');

    const archive2RecipeId = `MACHINE_${recipe.coffeeId}`;

    await pool.query(`
      INSERT INTO archive2_reference_library (
        archive2_recipe_id, recipe_name, display_name, recipe_type,
        milk_type, is_core, price, steps_json, tags, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (archive2_recipe_id) DO UPDATE SET
        recipe_name = EXCLUDED.recipe_name,
        steps_json = EXCLUDED.steps_json,
        price = EXCLUDED.price,
        updated_at = NOW()
    `, [
      archive2RecipeId,
      recipe.coffeeName,
      recipe.coffeeName,
      recipeType,
      milkType,
      isCore,
      recipe.price || 4.50,
      JSON.stringify(steps),
      generateTags(recipe.coffeeName, recipeType, milkType, steps),
      `Imported from Yile machine config. ClassifyIndex: ${recipe.classifyIndex}`
    ]);

    imported++;
    console.log(`   [${imported}] ${recipe.coffeeName} (${recipeType === 0 ? 'HOT' : 'ICED'})`);
  }

  console.log(`\n   Imported ${imported} recipe templates`);
}

function detectIngredientType(name) {
  const n = name.toLowerCase();
  if (n.includes('bean') || n.includes('coffee bean')) return 'BEANS';
  if (n.includes('milk') && !n.includes('syrup')) return 'POWDER';
  if (n.includes('syrup')) return 'SYRUP';
  if (n.includes('matcha') || n.includes('cocoa') || n.includes('chai')) return 'POWDER';
  if (n.includes('tea')) return 'POWDER';
  if (n.includes('sugar')) return 'SUGAR';
  return 'OTHER';
}

function detectMilkType(recipeName, steps) {
  const name = recipeName.toLowerCase();
  if (name.includes('oat')) return 'OAT';
  
  const hasMilkStep = steps.some(s => 
    s.enabled && s.ingredientKey && 
    (s.ingredientKey.toLowerCase().includes('milk') || s.ingredientKey.toLowerCase().includes('oat'))
  );
  
  if (hasMilkStep) {
    const oatStep = steps.find(s => s.ingredientKey?.toLowerCase().includes('oat'));
    if (oatStep) return 'OAT';
    return 'DAIRY';
  }
  
  return 'NONE';
}

function generateTags(recipeName, recipeType, milkType, steps) {
  const tags = [];
  const name = recipeName.toLowerCase();
  
  tags.push(recipeType === 0 ? 'HOT' : 'ICED');
  
  if (milkType !== 'NONE') tags.push(milkType);
  
  if (name.includes('latte')) tags.push('LATTE');
  if (name.includes('matcha')) tags.push('MATCHA');
  if (name.includes('chai')) tags.push('CHAI');
  if (name.includes('cocoa') || name.includes('chocolate')) tags.push('CHOCOLATE');
  if (name.includes('cappuccino')) tags.push('CAPPUCCINO');
  if (name.includes('espresso') || name.includes('americano')) tags.push('ESPRESSO');
  if (name.includes('macchiato')) tags.push('MACCHIATO');

  const hasCoffee = steps.some(s => 
    s.enabled && s.ingredientKey && s.ingredientKey.toLowerCase().includes('coffee')
  );
  if (hasCoffee) tags.push('COFFEE');
  
  tags.push('CORE');
  
  return tags;
}

importMachineConfig();
