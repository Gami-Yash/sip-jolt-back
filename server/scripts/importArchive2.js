/**
 * Archive2 Import Script - ISOLATED
 * Imports Archive2 Excel as reference library ONLY
 * Works independently - no API needed
 */

import XLSX from 'xlsx';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ARCHIVE2_PATH = path.join(__dirname, '../../data/JOLT_Archive2_Recipes_Export_Final.xlsx');

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('neon.tech') ? { rejectUnauthorized: false } : false
});

async function importArchive2() {
  console.log('Recipe Builder: Archive2 Import');
  console.log('Reading:', ARCHIVE2_PATH);
  console.log('This is ADDITIVE - existing app unaffected\n');

  try {
    const workbook = XLSX.readFile(ARCHIVE2_PATH);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(worksheet);

    console.log(`Found ${data.length} recipes in Archive2\n`);

    await importIngredients(data);
    await importRecipes(data);

    console.log('\nArchive2 import complete!');
    console.log('Existing app tables unmodified');
    console.log('You can now create drafts from these templates');
    
    await pool.end();
    process.exit(0);

  } catch (error) {
    console.error('Import failed:', error.message);
    console.error('Stack:', error.stack);
    await pool.end();
    process.exit(1);
  }
}

async function importIngredients(recipes) {
  console.log('Importing ingredients...');

  const ingredientMap = new Map();

  recipes.forEach(recipe => {
    for (let i = 1; i <= 7; i++) {
      const ingredientKey = recipe[`Order ${i} Ingredient`];
      const materialPathId = recipe[`Order ${i} Material Path ID`];
      const boxNumber = recipe[`Order ${i} Box`];

      if (ingredientKey && ingredientKey !== 'UNUSED' && ingredientKey !== '-1') {
        if (!ingredientMap.has(ingredientKey)) {
          ingredientMap.set(ingredientKey, {
            ingredient_key: ingredientKey,
            display_name: ingredientKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
            material_path_id: materialPathId || null,
            box_number: boxNumber || null,
            ingredient_type: detectIngredientType(ingredientKey),
            is_seasonal: ingredientKey.toLowerCase().includes('seasonal') || boxNumber === 4
          });
        }
      }
    }
  });

  console.log(`   Found ${ingredientMap.size} unique ingredients`);

  for (const [key, ingredient] of ingredientMap) {
    await pool.query(`
      INSERT INTO recipe_ingredients (
        ingredient_key, display_name, material_path_id, box_number, 
        ingredient_type, is_seasonal
      ) VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (ingredient_key) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        material_path_id = EXCLUDED.material_path_id,
        box_number = EXCLUDED.box_number
    `, [
      ingredient.ingredient_key,
      ingredient.display_name,
      ingredient.material_path_id,
      ingredient.box_number,
      ingredient.ingredient_type,
      ingredient.is_seasonal
    ]);
  }

  console.log(`   Imported ${ingredientMap.size} ingredients\n`);
}

async function importRecipes(recipes) {
  console.log('Importing recipe templates...');

  let imported = 0;
  let skipped = 0;

  for (const row of recipes) {
    const recipeName = row['Recipe Name'] || row['recipeName'] || row['name'];
    if (!recipeName) {
      skipped++;
      continue;
    }

    const steps = [];
    for (let i = 1; i <= 5; i++) {
      const ingredientKey = row[`Order ${i} Ingredient`];
      const enabled = ingredientKey && ingredientKey !== 'UNUSED' && ingredientKey !== '-1';

      steps.push({
        stepNumber: i,
        enabled: enabled,
        ingredientKey: enabled ? ingredientKey : null,
        water: enabled ? (parseFloat(row[`Order ${i} Water`]) || 0) : -1,
        powderTime: enabled ? (parseFloat(row[`Order ${i} Powder Time`]) || 0) : -1,
        mixTime: enabled ? (parseFloat(row[`Order ${i} Mix Time`]) || 0) : -1,
        materialPathId: enabled ? (parseInt(row[`Order ${i} Material Path ID`]) || null) : -1,
        box: enabled ? (parseInt(row[`Order ${i} Box`]) || null) : -1
      });
    }

    const recipeType = detectRecipeType(recipeName, row['Type']);
    const milkType = detectMilkType(recipeName);
    const isCore = !recipeName.toLowerCase().includes('seasonal');

    const archive2RecipeId = row['Recipe ID'] || `ARCH2_${imported + 1}`;

    await pool.query(`
      INSERT INTO archive2_reference_library (
        archive2_recipe_id, recipe_name, display_name, recipe_type, 
        milk_type, is_core, price, steps_json, tags, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (archive2_recipe_id) DO UPDATE SET
        recipe_name = EXCLUDED.recipe_name,
        steps_json = EXCLUDED.steps_json,
        updated_at = NOW()
    `, [
      archive2RecipeId,
      recipeName,
      formatDisplayName(recipeName),
      recipeType,
      milkType,
      isCore,
      parseFloat(row['Price']) || 4.50,
      JSON.stringify(steps),
      generateTags(recipeName, recipeType, milkType),
      'Imported from Archive2 as reference template'
    ]);

    imported++;
    
    if (imported % 10 === 0) {
      console.log(`   Progress: ${imported} recipes imported...`);
    }
  }

  console.log(`   Imported ${imported} recipe templates`);
  if (skipped > 0) {
    console.log(`   Skipped ${skipped} rows (missing recipe name)`);
  }
}

function detectIngredientType(ingredientKey) {
  const key = ingredientKey.toUpperCase();
  if (key.includes('POWDER') || key.includes('MILK')) return 'POWDER';
  if (key.includes('SYRUP')) return 'SYRUP';
  if (key.includes('BEAN') || key.includes('COFFEE')) return 'BEANS';
  if (key.includes('FRUIT') || key.includes('PULP')) return 'FRUIT';
  return 'OTHER';
}

function detectRecipeType(recipeName, typeField) {
  if (typeField !== undefined && typeField !== null) {
    return parseInt(typeField);
  }
  const name = recipeName.toUpperCase();
  return name.includes('ICED') ? 1 : 0;
}

function detectMilkType(recipeName) {
  const name = recipeName.toUpperCase();
  if (name.includes('OAT')) return 'OAT';
  if (name.includes('DAIRY') || name.includes('MILK') || name.includes('LATTE')) return 'DAIRY';
  return 'NONE';
}

function formatDisplayName(recipeName) {
  return recipeName
    .replace(/_/g, ' ')
    .replace(/\b\w/g, l => l.toUpperCase())
    .trim();
}

function generateTags(recipeName, recipeType, milkType) {
  const tags = [];
  
  tags.push(recipeType === 0 ? 'HOT' : 'ICED');
  
  if (milkType !== 'NONE') tags.push(milkType);
  
  const name = recipeName.toUpperCase();
  if (name.includes('LATTE')) tags.push('LATTE');
  if (name.includes('MATCHA')) tags.push('MATCHA');
  if (name.includes('CHAI')) tags.push('CHAI');
  if (name.includes('COCOA')) tags.push('COCOA');
  if (name.includes('SEASONAL')) tags.push('SEASONAL');
  else tags.push('CORE');
  
  return tags;
}

importArchive2();
