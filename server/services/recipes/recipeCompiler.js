/**
 * Recipe Compiler - ISOLATED
 * Compiles drafts to Yile API format (5-step)
 * WORKS WITHOUT API - Pure data transformation
 * Enforces all locked rules from Recipe Builder spec
 */

class RecipeCompiler {
  
  /**
   * Compile draft to Yile API format (5-step)
   * WORKS WITHOUT API
   */
  compile(draftData) {
    const { recipeName, recipeType, price, steps, imageUrl } = draftData;

    this.validateSteps(steps);

    const compiledSteps = steps.slice(0, 5).map((step, index) => ({
      step: index + 1,
      isUse: step.enabled ? 1 : 0,
      materialPathId: step.enabled ? (step.materialPathId || -1) : -1,
      box: step.enabled ? (step.box || -1) : -1,
      water: step.enabled ? (step.water || 0) : -1,
      powderTime: step.enabled ? (step.powderTime || 0) : -1,
      stirTime: step.enabled ? (step.mixTime || 0) : -1
    }));

    return {
      coffeeName: recipeName,
      type: recipeType,
      price: price || 4.50,
      coffeeImg: imageUrl || '',
      coffeeInfo: compiledSteps
    };
  }

  /**
   * Validate steps against locked rules
   * WORKS WITHOUT API
   */
  validateSteps(steps) {
    if (!Array.isArray(steps) || steps.length !== 5) {
      throw new Error('Must have exactly 5 steps');
    }

    const enabledSteps = steps.filter(s => s.enabled);
    if (enabledSteps.length === 0) {
      throw new Error('At least 1 step must be enabled');
    }

    steps.forEach((step, index) => {
      if (!step.enabled) return;

      if (step.ingredientKey && step.ingredientKey.toLowerCase().includes('coffee')) {
        if (step.water !== 45) {
          throw new Error(`Step ${index + 1}: Coffee water must be 45ml (locked rule)`);
        }
      }

      if (step.water !== undefined && (step.water < 0 || step.water > 200)) {
        throw new Error(`Step ${index + 1}: Water must be 0-200ml`);
      }

      if (step.powderTime !== undefined && (step.powderTime < 0 || step.powderTime > 30)) {
        throw new Error(`Step ${index + 1}: Powder time must be 0-30 seconds`);
      }

      if (step.mixTime !== undefined && (step.mixTime < 0 || step.mixTime > 30)) {
        throw new Error(`Step ${index + 1}: Mix time must be 0-30 seconds`);
      }

      if (!step.ingredientKey) {
        throw new Error(`Step ${index + 1}: Ingredient required when enabled`);
      }
    });
  }

  /**
   * Decompile Yile format back to internal format
   * WORKS WITHOUT API
   */
  decompile(yileRecipe) {
    const steps = [];
    
    const coffeeInfo = yileRecipe.steps_raw?.coffeeInfo || yileRecipe.coffeeInfo || [];
    
    for (let i = 0; i < 5; i++) {
      const yileStep = coffeeInfo[i] || {};
      
      steps.push({
        stepNumber: i + 1,
        enabled: yileStep.isUse === 1,
        ingredientKey: yileStep.materialPathId > 0 ? `MATERIAL_${yileStep.materialPathId}` : null,
        materialPathId: yileStep.materialPathId || -1,
        box: yileStep.box || -1,
        water: yileStep.water || -1,
        powderTime: yileStep.powderTime || -1,
        mixTime: yileStep.stirTime || -1
      });
    }

    return {
      recipeName: yileRecipe.coffee_name,
      recipeType: yileRecipe.coffee_type,
      price: yileRecipe.price,
      imageUrl: yileRecipe.coffee_img,
      steps
    };
  }

  /**
   * Validate recipe name
   * WORKS WITHOUT API
   */
  validateRecipeName(recipeName) {
    if (!recipeName || recipeName.trim().length === 0) {
      throw new Error('Recipe name is required');
    }

    if (recipeName.length > 100) {
      throw new Error('Recipe name must be 100 characters or less');
    }

    return true;
  }

  /**
   * Validate price
   * WORKS WITHOUT API
   */
  validatePrice(price) {
    if (price === undefined || price === null) {
      return 4.50;
    }

    const numPrice = parseFloat(price);
    
    if (isNaN(numPrice) || numPrice < 0) {
      throw new Error('Price must be a positive number');
    }

    if (numPrice > 100) {
      throw new Error('Price must be less than $100');
    }

    return numPrice;
  }

  /**
   * Get validation summary for a draft
   * WORKS WITHOUT API
   */
  getValidationSummary(draftData) {
    const errors = [];
    const warnings = [];

    try {
      this.validateRecipeName(draftData.recipeName);
    } catch (e) {
      errors.push(e.message);
    }

    try {
      this.validatePrice(draftData.price);
    } catch (e) {
      errors.push(e.message);
    }

    try {
      this.validateSteps(draftData.steps);
    } catch (e) {
      errors.push(e.message);
    }

    const enabledSteps = draftData.steps?.filter(s => s.enabled) || [];
    
    if (enabledSteps.length < 2) {
      warnings.push('Most drinks use 2-3 steps for best quality');
    }

    if (!draftData.imageUrl) {
      warnings.push('Consider adding an image for better presentation');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      enabledStepCount: enabledSteps.length
    };
  }
}

export default new RecipeCompiler();
