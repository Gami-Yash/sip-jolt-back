/**
 * Upload Recipe Images to Object Storage
 * Maps 21 source images to 53 recipes intelligently
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from '../../shared/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const IMAGES_PATH = path.join(__dirname, '../../data/vm/goodsimg');
const PUBLIC_IMAGES_PATH = path.join(__dirname, '../../public/images/recipes');

const IMAGE_MAPPING = {
  'latte': 'Coffee Latte (拿铁咖啡).png',
  'matcha': 'Matcha (抹茶).png',
  'chai': 'chai latte.png',
  'chocolate': 'Hot chocolate (热巧克力).png',
  'vanilla white chocolate': 'Chocolate latte (巧克力拿铁).png',
  'cappuccino': 'Cappuccino (卡布奇诺).png',
  'americano': 'Americano (美式咖啡).png',
  'espresso': 'Espresso Shot.png',
  'double espresso': 'Double Italian Coffee (double意式咖啡).png',
  'brown sugar matcha': 'Brown‑Sugar Matcha Latte.png',
  'brown sugar latte': '1762237297717.png',
  'coconut': 'White coffee (白咖啡).png',
  'strawberry': 'Matcha (抹茶).png',
  'lavender': 'Matcha (抹茶).png',
  'tea': 'Milk tea (奶茶).png',
  'milk': 'Hot milk (热牛奶).png',
};

const FALLBACK_IMAGE = 'Coffee Latte (拿铁咖啡).png';

async function uploadRecipeImages() {
  console.log('Recipe Image Upload');
  console.log('====================\n');

  if (!fs.existsSync(PUBLIC_IMAGES_PATH)) {
    fs.mkdirSync(PUBLIC_IMAGES_PATH, { recursive: true });
    console.log(`Created: ${PUBLIC_IMAGES_PATH}\n`);
  }

  const sourceImages = fs.readdirSync(IMAGES_PATH).filter(f => 
    f.endsWith('.png') && !f.startsWith('.')
  );
  console.log(`Found ${sourceImages.length} source images\n`);

  let copied = 0;
  for (const img of sourceImages) {
    const safeName = img.replace(/[^\w.-]/g, '_').replace(/__+/g, '_');
    const srcPath = path.join(IMAGES_PATH, img);
    const destPath = path.join(PUBLIC_IMAGES_PATH, safeName);
    
    fs.copyFileSync(srcPath, destPath);
    copied++;
  }
  console.log(`Copied ${copied} images to public folder\n`);

  const recipes = await pool.query('SELECT ref_id, recipe_name FROM archive2_reference_library ORDER BY ref_id');
  console.log(`Mapping images to ${recipes.rows.length} recipes...\n`);

  let updated = 0;
  for (const recipe of recipes.rows) {
    const imageName = findBestImage(recipe.recipe_name, sourceImages);
    const safeName = imageName.replace(/[^\w.-]/g, '_').replace(/__+/g, '_');
    const imageUrl = `/images/recipes/${safeName}`;

    await pool.query(
      'UPDATE archive2_reference_library SET image_url = $1 WHERE ref_id = $2',
      [imageUrl, recipe.ref_id]
    );

    updated++;
    console.log(`   [${updated}] ${recipe.recipe_name} -> ${safeName.substring(0, 30)}...`);
  }

  console.log(`\nUpdated ${updated} recipes with image URLs`);
  console.log('Images accessible at /images/recipes/');
  
  process.exit(0);
}

function findBestImage(recipeName, availableImages) {
  const name = recipeName.toLowerCase();

  if (name.includes('brown sugar') && name.includes('matcha')) {
    return IMAGE_MAPPING['brown sugar matcha'];
  }
  if (name.includes('brown sugar') && name.includes('latte')) {
    return IMAGE_MAPPING['brown sugar latte'];
  }
  if (name.includes('vanilla white chocolate') || name.includes('white chocolate')) {
    return IMAGE_MAPPING['vanilla white chocolate'];
  }
  if (name.includes('double') && name.includes('espresso')) {
    return IMAGE_MAPPING['double espresso'];
  }

  for (const [keyword, image] of Object.entries(IMAGE_MAPPING)) {
    if (name.includes(keyword)) {
      return image;
    }
  }

  return FALLBACK_IMAGE;
}

uploadRecipeImages();
