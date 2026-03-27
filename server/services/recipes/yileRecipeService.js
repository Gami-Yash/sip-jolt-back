/**
 * Yile Recipe Service - ISOLATED
 * Handles Yile catalog sync and recipe management
 * Uses existing yileApiClient.js when credentials work
 */

import yileClient from '../yileApiClient.js';
import { pool } from '../../../shared/db.js';
import { randomUUID } from 'crypto';

class YileRecipeService {
  
  /**
   * Sync Yile operator catalog to local mirror
   * NEEDS API CREDENTIALS - Will work when factory fixes 401 error
   */
  async syncYileCatalog() {
    console.log('[YileRecipeService] Starting catalog sync...');
    
    try {
      // Fetch all recipes with pagination
      const result = await yileClient.getAllRecipes();
      
      if (!result.success) {
        throw new Error(`Yile API error: ${result.code} - ${result.message || 'Unknown error'}`);
      }

      // Yile API returns recipes in msg.rows (paginated)
      const recipes = result.rows || (Array.isArray(result.data) ? result.data : []);
      const totalAvailable = result.total || recipes.length;
      let synced = 0;

      console.log(`[YileRecipeService] Processing ${recipes.length} recipes (total: ${totalAvailable})`);

      for (const recipe of recipes) {
        await pool.query(`
          INSERT INTO yile_recipes_mirror (
            yile_recipe_id, coffee_name, coffee_type, price, coffee_img,
            steps_raw, classify_index, coffee_num, is_synced, last_synced
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, NOW())
          ON CONFLICT (yile_recipe_id) DO UPDATE SET
            coffee_name = EXCLUDED.coffee_name,
            coffee_type = EXCLUDED.coffee_type,
            price = EXCLUDED.price,
            coffee_img = EXCLUDED.coffee_img,
            steps_raw = EXCLUDED.steps_raw,
            is_synced = true,
            last_synced = NOW()
        `, [
          recipe.id || recipe.recipeId,
          recipe.coffeeName,
          recipe.coffeeType || recipe.type,
          recipe.price,
          recipe.coffeeImg || null,
          typeof recipe.steps === 'string' ? recipe.steps : JSON.stringify(recipe.steps || recipe.coffeeInfo),
          recipe.classifyIndex,
          recipe.coffeeNum || recipe.boxNum
        ]);
        
        synced++;
      }

      console.log(`[YileRecipeService] Synced ${synced} recipes from Yile`);
      
      return {
        success: true,
        synced,
        isEncrypted: result.isEncrypted
      };

    } catch (error) {
      console.error('[YileRecipeService] Sync failed:', error.message);
      
      if (error.message.includes('401') || error.message.includes('未登录')) {
        return {
          success: false,
          error: 'API credentials not configured (waiting for factory)',
          note: 'Archive2 templates still work! You can create/edit drafts without Yile sync.'
        };
      }
      
      throw error;
    }
  }

  /**
   * Get local mirror of Yile catalog
   * WORKS WITHOUT API - Returns local database copy
   */
  async getYileCatalogMirror() {
    const result = await pool.query(`
      SELECT * FROM yile_recipes_mirror
      ORDER BY last_synced DESC NULLS LAST
    `);
    
    return result.rows;
  }

  /**
   * Publish draft to Yile operator catalog
   * NEEDS API CREDENTIALS - Will work when factory fixes 401 error
   */
  async publishDraftToYile(draftId, userId) {
    console.log(`[YileRecipeService] Publishing draft ${draftId}...`);

    const draftResult = await pool.query(`
      SELECT * FROM recipe_drafts WHERE draft_id = $1
    `, [draftId]);

    if (draftResult.rows.length === 0) {
      throw new Error('Draft not found');
    }

    const draft = draftResult.rows[0];
    const yilePayload = draft.draft_yile_payload;

    const jobId = randomUUID();
    
    await pool.query(`
      INSERT INTO recipe_publish_jobs (
        job_id, draft_id, action, api_endpoint, api_payload, 
        status, initiated_by
      ) VALUES ($1, $2, 'WRITE_TO_YILE', 'coffee/addCoffeeRecipe.do', $3, 'RUNNING', $4)
    `, [jobId, draftId, yilePayload, userId]);

    try {
      const result = await yileClient.addRecipe(yilePayload);

      if (!result.success) {
        throw new Error(`Yile API error: ${result.code}`);
      }

      const yileRecipeId = result.data?.recipeId;

      await pool.query(`
        UPDATE recipe_publish_jobs 
        SET status = 'SUCCESS', 
            api_response = $1,
            yile_recipe_id = $2,
            completed_at = NOW()
        WHERE job_id = $3
      `, [JSON.stringify(result), yileRecipeId, jobId]);

      await pool.query(`
        UPDATE recipe_drafts
        SET status = 'PUBLISHED',
            published_at = NOW(),
            published_yile_recipe_id = $1
        WHERE draft_id = $2
      `, [yileRecipeId, draftId]);

      console.log(`[YileRecipeService] Published to Yile: ${yileRecipeId}`);

      return {
        success: true,
        jobId,
        yileRecipeId
      };

    } catch (error) {
      await pool.query(`
        UPDATE recipe_publish_jobs 
        SET status = 'FAILED',
            error_message = $1,
            completed_at = NOW()
        WHERE job_id = $2
      `, [error.message, jobId]);

      if (error.message.includes('401') || error.message.includes('未登录')) {
        return {
          success: false,
          jobId,
          error: 'API credentials not configured',
          note: 'Draft saved successfully! It will publish when API credentials are fixed.'
        };
      }

      throw error;
    }
  }

  /**
   * Push recipe to device(s)
   * NEEDS API CREDENTIALS - Will work when factory fixes 401 error
   */
  async pushRecipeToDevice(yileRecipeId, deviceId, userId) {
    console.log(`[YileRecipeService] Pushing recipe ${yileRecipeId} to device ${deviceId}...`);

    const jobId = randomUUID();

    await pool.query(`
      INSERT INTO recipe_publish_jobs (
        job_id, action, yile_recipe_id, device_id, api_endpoint,
        api_payload, status, initiated_by
      ) VALUES ($1, 'PUSH_TO_DEVICE', $2, $3, 'push/pushCoffeeRecipe.do', $4, 'RUNNING', $5)
    `, [jobId, yileRecipeId, deviceId, JSON.stringify({ deviceId, recipeId: yileRecipeId }), userId]);

    try {
      const result = await yileClient.pushRecipeToDevice(deviceId, yileRecipeId);

      if (!result.success) {
        throw new Error(`Push failed: ${result.code}`);
      }

      const pushId = result.data?.pushId;

      await pool.query(`
        UPDATE recipe_publish_jobs
        SET api_response = $1,
            push_id = $2,
            completed_at = NOW()
        WHERE job_id = $3
      `, [JSON.stringify(result), pushId, jobId]);

      if (pushId) {
        const pollResult = await yileClient.pollPushResult(pushId, 30, 2000);
        
        await pool.query(`
          UPDATE recipe_publish_jobs
          SET status = $1,
              api_response = $2
          WHERE job_id = $3
        `, [pollResult.success ? 'SUCCESS' : 'FAILED', JSON.stringify(pollResult), jobId]);

        return { success: pollResult.success, jobId, pushId };
      }

      return { success: true, jobId, pushId };

    } catch (error) {
      await pool.query(`
        UPDATE recipe_publish_jobs
        SET status = 'FAILED',
            error_message = $1,
            completed_at = NOW()
        WHERE job_id = $2
      `, [error.message, jobId]);

      if (error.message.includes('401') || error.message.includes('未登录')) {
        return {
          success: false,
          jobId,
          error: 'API credentials not configured',
          note: 'Push command will work when API credentials are fixed.'
        };
      }

      throw error;
    }
  }
}

export default new YileRecipeService();
