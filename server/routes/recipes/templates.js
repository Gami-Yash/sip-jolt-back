/**
 * Recipe Templates Routes - ISOLATED
 * Handles Archive2 templates and Yile catalog
 * Most endpoints work WITHOUT API credentials
 */

import express from 'express';
import { pool } from '../../../shared/db.js';
import yileRecipeService from '../../services/recipes/yileRecipeService.js';

const router = express.Router();

/**
 * GET /archive2
 * List all Archive2 reference templates
 * WORKS WITHOUT API
 */
router.get('/archive2', async (req, res) => {
  try {
    const { type, milkType, tags, isCore } = req.query;

    let query = 'SELECT * FROM archive2_reference_library WHERE 1=1';
    const params = [];
    let paramCount = 1;

    if (type !== undefined) {
      query += ` AND recipe_type = $${paramCount}`;
      params.push(parseInt(type));
      paramCount++;
    }

    if (milkType) {
      query += ` AND milk_type = $${paramCount}`;
      params.push(milkType.toUpperCase());
      paramCount++;
    }

    if (isCore !== undefined) {
      query += ` AND is_core = $${paramCount}`;
      params.push(isCore === 'true');
      paramCount++;
    }

    if (tags) {
      query += ` AND tags && $${paramCount}`;
      params.push(tags.split(','));
      paramCount++;
    }

    query += ' ORDER BY recipe_name';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      templates: result.rows,
      note: 'Archive2 reference library - proven recipes you can clone',
      message: 'These work without API credentials'
    });

  } catch (error) {
    console.error('[Templates] Archive2 list error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /archive2/:id
 * Get single Archive2 template by ID
 * WORKS WITHOUT API
 */
router.get('/archive2/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT * FROM archive2_reference_library WHERE ref_id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Template not found'
      });
    }

    res.json({
      success: true,
      template: result.rows[0]
    });

  } catch (error) {
    console.error('[Templates] Archive2 get error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /archive2/search
 * Search Archive2 templates
 * WORKS WITHOUT API
 */
router.get('/archive2/search', async (req, res) => {
  try {
    const { q } = req.query;

    if (!q) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter "q" required'
      });
    }

    const result = await pool.query(`
      SELECT * FROM archive2_reference_library
      WHERE 
        recipe_name ILIKE $1 OR
        display_name ILIKE $1 OR
        $2 = ANY(tags)
      ORDER BY recipe_name
    `, [`%${q}%`, q.toUpperCase()]);

    res.json({
      success: true,
      count: result.rows.length,
      templates: result.rows,
      query: q
    });

  } catch (error) {
    console.error('[Templates] Archive2 search error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /yile-catalog
 * List Yile recipes mirror (local cache)
 * WORKS WITHOUT API (shows local cache)
 */
router.get('/yile-catalog', async (req, res) => {
  try {
    const recipes = await yileRecipeService.getYileCatalogMirror();

    res.json({
      success: true,
      count: recipes.length,
      recipes,
      lastSync: recipes[0]?.last_synced || null,
      note: recipes.length === 0 
        ? 'Empty - run /yile-sync to populate (needs API credentials)'
        : 'Showing cached Yile catalog from last sync'
    });

  } catch (error) {
    console.error('[Templates] Yile catalog error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /yile-sync
 * Sync Yile operator catalog from API
 * NEEDS API CREDENTIALS
 */
router.post('/yile-sync', async (req, res) => {
  try {
    const result = await yileRecipeService.syncYileCatalog();

    if (!result.success) {
      return res.status(500).json({
        success: false,
        error: result.error,
        note: result.note,
        message: 'API credentials not working yet - use Archive2 templates instead'
      });
    }

    res.json({
      success: true,
      synced: result.synced,
      isEncrypted: result.isEncrypted,
      message: `Successfully synced ${result.synced} recipes from Yile`
    });

  } catch (error) {
    console.error('[Templates] Yile sync error:', error);
    
    if (error.message.includes('401') || error.message.includes('未登录')) {
      return res.status(401).json({
        success: false,
        error: 'API credentials not configured',
        note: 'Waiting for factory to fix credentials. Archive2 templates still work!',
        canUseArchive2: true
      });
    }

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /ingredients
 * List all ingredients from Archive2
 * WORKS WITHOUT API
 */
router.get('/ingredients', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM recipe_ingredients
      ORDER BY display_name
    `);

    res.json({
      success: true,
      count: result.rows.length,
      ingredients: result.rows
    });

  } catch (error) {
    console.error('[Templates] Ingredients error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /stats
 * Get template statistics
 * WORKS WITHOUT API
 */
router.get('/stats', async (req, res) => {
  try {
    const archive2Count = await pool.query(
      'SELECT COUNT(*) as count FROM archive2_reference_library'
    );

    const yileCount = await pool.query(
      'SELECT COUNT(*) as count FROM yile_recipes_mirror'
    );

    const ingredientCount = await pool.query(
      'SELECT COUNT(*) as count FROM recipe_ingredients'
    );

    const typeBreakdown = await pool.query(`
      SELECT recipe_type, COUNT(*) as count
      FROM archive2_reference_library
      GROUP BY recipe_type
    `);

    const milkBreakdown = await pool.query(`
      SELECT milk_type, COUNT(*) as count
      FROM archive2_reference_library
      GROUP BY milk_type
    `);

    res.json({
      success: true,
      stats: {
        archive2Templates: parseInt(archive2Count.rows[0].count),
        yileRecipes: parseInt(yileCount.rows[0].count),
        ingredients: parseInt(ingredientCount.rows[0].count),
        byType: typeBreakdown.rows.map(r => ({
          type: r.recipe_type === 0 ? 'HOT' : 'ICED',
          count: parseInt(r.count)
        })),
        byMilk: milkBreakdown.rows.map(r => ({
          milkType: r.milk_type,
          count: parseInt(r.count)
        }))
      }
    });

  } catch (error) {
    console.error('[Templates] Stats error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

export default router;
