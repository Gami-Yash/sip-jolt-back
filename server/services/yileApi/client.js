/**
 * Base HTTP Client for Yile API
 * Handles token management, rate limiting, and response normalization
 */

import axios from 'axios';
import { normalizeResponse } from './utils.js';

export default class YileApiClient {
  constructor(config) {
    this.baseURL = config.baseURL || process.env.YILE_API_BASE_URL || 'http://yleapi.yilevme.com';
    this.departmentId = config.departmentId || process.env.YILE_DEPARTMENT_ID;
    this.secretKey = config.secretKey || process.env.YILE_SECRET_KEY;
    this.enabled = config.enabled !== undefined ? config.enabled : process.env.YILE_INTEGRATION_ENABLED === 'true';
    
    this.token = null;
    this.tokenExpiry = null;
    this.tokenRefreshInProgress = false;
    
    this.requestQueue = [];
    this.isProcessingQueue = false;
    this.rateLimitMs = config.rateLimitMs || 100;
    this.maxRequestsPerMinute = config.maxRequestsPerMinute || 100;
    this.requestCount = 0;
    this.requestWindowStart = Date.now();
    
    console.log('[YileAPI] Client initialized', {
      baseURL: this.baseURL,
      departmentId: this.departmentId,
      enabled: this.enabled
    });
  }

  checkEnabled() {
    if (!this.enabled) {
      throw new Error('Yile integration is disabled. Set YILE_INTEGRATION_ENABLED=true');
    }
  }

  checkRateLimit() {
    const now = Date.now();
    const windowElapsed = now - this.requestWindowStart;
    
    if (windowElapsed >= 60000) {
      this.requestCount = 0;
      this.requestWindowStart = now;
    }
    
    if (this.requestCount >= this.maxRequestsPerMinute) {
      const waitTime = Math.ceil((60000 - windowElapsed) / 1000);
      throw new Error(`Rate limit exceeded. Wait ${waitTime}s.`);
    }
    
    this.requestCount++;
  }

  async request(endpoint, body = {}, options = {}) {
    this.checkEnabled();
    this.checkRateLimit();
    
    const maxRetries = options.maxRetries || 2;
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const token = await this.auth.getToken();
        
        console.log(`[YileAPI] ${endpoint} (attempt ${attempt}/${maxRetries})`);
        
        const response = await axios.post(
          `${this.baseURL}/${endpoint}`,
          body,
          {
            headers: {
              'Content-Type': 'application/json',
              'YiToken': token
            },
            timeout: options.timeout || 30000
          }
        );

        const normalized = normalizeResponse(response.data);

        if (normalized.tokenError && attempt < maxRetries) {
          console.log('[YileAPI] Token expired, refreshing...');
          this.auth.invalidateToken();
          await new Promise(resolve => setTimeout(resolve, 1000));
          continue;
        }

        return normalized;

      } catch (error) {
        lastError = error;
        console.error(`[YileAPI] ${endpoint} failed (attempt ${attempt}/${maxRetries}):`, error.message);
        
        if (error.response?.status === 404 || error.response?.status === 400) {
          break;
        }
        
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
        }
      }
    }

    return {
      success: false,
      data: null,
      error: `Request to ${endpoint} failed: ${lastError.message}`
    };
  }

  setAuthModule(authModule) {
    this.auth = authModule;
  }
}
