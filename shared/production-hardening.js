import { getPool } from './db.js';

const isProduction = process.env.NODE_ENV === 'production' || process.env.REPL_SLUG;

const sensitiveRateLimits = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMITS = {
  login: { max: 5, window: 60000 },
  upload: { max: 20, window: 60000 },
  export: { max: 10, window: 300000 },
  api: { max: 100, window: 60000 }
};

export function sensitiveRateLimit(limitType = 'api') {
  const config = RATE_LIMITS[limitType] || RATE_LIMITS.api;
  
  return (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    const userId = req.headers['x-user-id'] || 'anonymous';
    const key = `${limitType}:${ip}:${userId}`;
    const now = Date.now();
    
    if (!sensitiveRateLimits.has(key)) {
      sensitiveRateLimits.set(key, { count: 1, resetTime: now + config.window });
      return next();
    }
    
    const record = sensitiveRateLimits.get(key);
    
    if (now > record.resetTime) {
      sensitiveRateLimits.set(key, { count: 1, resetTime: now + config.window });
      return next();
    }
    
    record.count++;
    
    if (record.count > config.max) {
      logSecurityDeny(req, 'RATE_LIMIT_EXCEEDED', { limitType, count: record.count });
      return res.status(429).json({ 
        error: 'Too many requests. Please wait before trying again.',
        retryAfter: Math.ceil((record.resetTime - now) / 1000)
      });
    }
    
    next();
  };
}

export function strictRBAC(allowedRoles) {
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  
  return async (req, res, next) => {
    const userRole = req.headers['x-user-role'];
    const userId = req.headers['x-user-id'];
    const tenantId = req.headers['x-tenant-id'];
    
    if (!userId) {
      await logSecurityDeny(req, 'MISSING_USER_ID', { path: req.path });
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!userRole || !roles.includes(userRole)) {
      // v1.00.1: Backward compatibility for TECHNICIAN role
      const effectiveRole = userRole === 'TECHNICIAN' ? 'PARTNER_TECHNICIAN' : userRole;
      if (!roles.includes(effectiveRole)) {
        await logSecurityDeny(req, 'RBAC_DENIED', { 
          userId, userRole, requiredRoles: roles, path: req.path 
        });
        return res.status(403).json({ error: 'Access denied: insufficient permissions' });
      }
    }
    
    next();
  };
}

export function enforceTenantIsolation(tenantIdParam = 'tenantId') {
  return async (req, res, next) => {
    const userTenantId = req.headers['x-tenant-id'];
    const requestedTenantId = req.params[tenantIdParam] || req.body?.[tenantIdParam] || req.query?.[tenantIdParam];
    
    if (requestedTenantId && userTenantId && requestedTenantId !== userTenantId) {
      await logSecurityDeny(req, 'TENANT_MISMATCH', {
        userTenantId,
        requestedTenantId,
        path: req.path
      });
      return res.status(403).json({ error: 'Access denied: tenant mismatch' });
    }
    
    next();
  };
}

export async function logSecurityDeny(req, denyType, metadata = {}) {
  try {
    const pool = getPool();
    const denyId = `DENY-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    
    await pool.query(`
      INSERT INTO security_deny_log 
        (deny_id, deny_type, user_id, user_role, tenant_id, ip_address, path, method, metadata, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
    `, [
      denyId,
      denyType,
      req.headers['x-user-id'] || null,
      req.headers['x-user-role'] || null,
      req.headers['x-tenant-id'] || null,
      req.ip || req.headers['x-forwarded-for'] || null,
      req.path,
      req.method,
      JSON.stringify({ ...metadata, userAgent: req.headers['user-agent'] })
    ]);
    
    console.warn(`[SECURITY DENY] ${denyType}: ${JSON.stringify(metadata)}`);
  } catch (error) {
    console.error('Failed to log security deny:', error.message);
  }
}

const activeSessions = new Map();

export const sessionManager = {
  async revokeUserSessions(userId, revokedBy) {
    const pool = getPool();
    
    const result = await pool.query(
      `UPDATE auth_sessions SET revoked_at = NOW(), revoked_by = $2
       WHERE user_id = $1 AND revoked_at IS NULL
       RETURNING session_token`,
      [userId, revokedBy]
    );
    
    await logSecurityEvent('SESSIONS_REVOKED', revokedBy, { 
      targetUserId: userId, 
      sessionsRevoked: result.rows.length 
    });
    
    return { revokedCount: result.rows.length };
  },

  async revokeSession(sessionToken, revokedBy) {
    const pool = getPool();
    
    await pool.query(
      `UPDATE auth_sessions SET revoked_at = NOW(), revoked_by = $2
       WHERE session_token = $1`,
      [sessionToken, revokedBy]
    );
    
    await logSecurityEvent('SESSION_REVOKED', revokedBy, { sessionToken: sessionToken.substring(0, 8) + '...' });
    
    return { success: true };
  },

  async getActiveSessions(userId) {
    const pool = getPool();
    
    const result = await pool.query(
      `SELECT session_token, created_at, last_activity_at, user_agent, ip_address 
       FROM auth_sessions WHERE user_id = $1 AND revoked_at IS NULL
       ORDER BY last_activity_at DESC`,
      [userId]
    );
    
    return result.rows.map(s => ({
      tokenPreview: s.session_token.substring(0, 8) + '...',
      createdAt: s.created_at,
      lastActiveAt: s.last_activity_at,
      userAgent: s.user_agent,
      ipAddress: s.ip_address
    }));
  },

  async killAllSessions(exceptSessionToken, revokedBy) {
    const pool = getPool();
    
    let query = `UPDATE auth_sessions SET revoked_at = NOW(), revoked_by = $1
                 WHERE revoked_at IS NULL`;
    const params = [revokedBy];
    
    if (exceptSessionToken) {
      query += ` AND session_token != $2`;
      params.push(exceptSessionToken);
    }
    
    const result = await pool.query(query + ' RETURNING session_token', params);
    
    await logSecurityEvent('ALL_SESSIONS_KILLED', revokedBy, { 
      sessionsKilled: result.rows.length,
      excepted: !!exceptSessionToken
    });
    
    return { killedCount: result.rows.length };
  }
};

export async function logSecurityEvent(eventType, actorId, metadata = {}) {
  try {
    const pool = getPool();
    const eventId = `SEC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    
    await pool.query(`
      INSERT INTO security_events (event_id, event_type, actor_id, metadata, created_at)
      VALUES ($1, $2, $3, $4, NOW())
    `, [eventId, eventType, actorId, JSON.stringify(metadata)]);
    
  } catch (error) {
    console.error('Failed to log security event:', error.message);
  }
}

export function removeDevBypasses(req, res, next) {
  if (isProduction) {
    if (req.query.skipValidation || req.body?.skipValidation) {
      delete req.query.skipValidation;
      delete req.body?.skipValidation;
    }
    if (req.query.debug || req.body?.debug) {
      delete req.query.debug;
      delete req.body?.debug;
    }
    if (req.query.bypassPhoto || req.body?.bypassPhoto) {
      delete req.query.bypassPhoto;
      delete req.body?.bypassPhoto;
    }
  }
  next();
}

export function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  if (isProduction) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  next();
}

export const healthChecks = {
  async database() {
    try {
      const pool = getPool();
      const start = Date.now();
      await pool.query('SELECT 1');
      return { status: 'healthy', latencyMs: Date.now() - start };
    } catch (error) {
      return { status: 'unhealthy', error: error.message };
    }
  },

  async storage() {
    try {
      const bucketId = process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID;
      return { 
        status: bucketId ? 'configured' : 'not_configured',
        bucketId: bucketId ? bucketId.substring(0, 8) + '...' : null
      };
    } catch (error) {
      return { status: 'error', error: error.message };
    }
  },

  async all() {
    const [db, storage] = await Promise.all([
      this.database(),
      this.storage()
    ]);
    
    const allHealthy = db.status === 'healthy' && storage.status !== 'error';
    
    return {
      status: allHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      checks: { database: db, storage }
    };
  }
};

export function withRetry(fn, maxRetries = 3, delayMs = 1000) {
  return async (...args) => {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await fn(...args);
      } catch (error) {
        lastError = error;
        console.warn(`Retry attempt ${attempt}/${maxRetries} failed:`, error.message);
        
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, delayMs * attempt));
        }
      }
    }
    
    throw lastError;
  };
}

const featureFlags = new Map([
  ['exports_enabled', true],
  ['notifications_enabled', true],
  ['new_cadence_jobs', true],
  ['landlord_portal', true]
]);

export const featureFlagService = {
  isEnabled(flagName) {
    return featureFlags.get(flagName) ?? false;
  },
  
  setFlag(flagName, enabled) {
    featureFlags.set(flagName, enabled);
    console.log(`[FEATURE FLAG] ${flagName} = ${enabled}`);
  },
  
  getAllFlags() {
    return Object.fromEntries(featureFlags);
  }
};

export function requireFeatureFlag(flagName) {
  return (req, res, next) => {
    if (!featureFlagService.isEnabled(flagName)) {
      return res.status(503).json({ 
        error: 'This feature is currently disabled',
        feature: flagName
      });
    }
    next();
  };
}

export function addPagination(defaultLimit = 50, maxLimit = 200) {
  return (req, res, next) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(maxLimit, Math.max(1, parseInt(req.query.limit) || defaultLimit));
    const offset = (page - 1) * limit;
    
    req.pagination = { page, limit, offset };
    next();
  };
}

export function paginatedResponse(data, total, pagination) {
  const { page, limit } = pagination;
  const totalPages = Math.ceil(total / limit);
  
  return {
    data,
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  };
}
