/**
 * Yile API Authentication Module
 * Token generation and caching (3hr validity, 2h55m cache)
 */

import axios from 'axios';

const TOKEN_CACHE_MS = 2 * 60 * 60 * 1000 + 55 * 60 * 1000; // 2hr 55min

export default function createAuthModule(client) {
  return {
    async getToken(forceRefresh = false) {
      if (!forceRefresh && client.token && client.tokenExpiry && Date.now() < client.tokenExpiry) {
        return client.token;
      }

      if (client.tokenRefreshInProgress) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        return this.getToken();
      }

      client.tokenRefreshInProgress = true;

      try {
        console.log('[YileAPI] Fetching new token...');
        
        const response = await axios.post(`${client.baseURL}/token/getToken.do`, {
          departmentId: parseInt(client.departmentId),
          secretKey: client.secretKey
        }, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000
        });

        const code = String(response.data.code);
        
        if (code === '1') {
          client.token = response.data.msg;
          client.tokenExpiry = Date.now() + TOKEN_CACHE_MS;
          
          console.log('[YileAPI] Token refreshed successfully', {
            expiresAt: new Date(client.tokenExpiry).toISOString()
          });
          
          return client.token;
        } else {
          throw new Error(`Token fetch failed with code ${code}: ${response.data.msg || 'Unknown error'}`);
        }
      } catch (error) {
        console.error('[YileAPI] Token fetch error:', error.message);
        throw new Error(`Failed to get Yile token: ${error.message}`);
      } finally {
        client.tokenRefreshInProgress = false;
      }
    },

    async testToken() {
      try {
        const token = await this.getToken();
        return {
          success: true,
          tokenLength: token.length,
          tokenPreview: token.substring(0, 20) + '...',
          expiresAt: new Date(client.tokenExpiry).toISOString()
        };
      } catch (error) {
        return {
          success: false,
          error: error.message
        };
      }
    },

    invalidateToken() {
      client.token = null;
      client.tokenExpiry = null;
      console.log('[YileAPI] Token invalidated');
    }
  };
}
