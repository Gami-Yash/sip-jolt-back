import { authService } from '../services/auth.js';

export function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

export function requireAuth(req, res, next) {
  const token = extractToken(req);
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  authService.validateSession(token)
    .then(session => {
      if (!session) {
        return res.status(401).json({ error: 'Invalid or expired session' });
      }
      
      req.user = session.user;
      req.siteAssignments = session.siteAssignments;
      req.sessionId = session.sessionId;
      next();
    })
    .catch(error => {
      console.error('Auth validation error:', error);
      res.status(500).json({ error: 'Authentication error' });
    });
}

export function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const hasRole = req.siteAssignments.some(a => allowedRoles.includes(a.role));
    
    if (!hasRole) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: `Required role: ${allowedRoles.join(' or ')}`
      });
    }
    
    next();
  };
}

export function requireSiteAccess(getSiteId) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const siteId = typeof getSiteId === 'function' ? getSiteId(req) : req.params.siteId || req.body.siteId;
    
    if (!siteId) {
      return res.status(400).json({ error: 'Site ID required' });
    }
    
    const hasAccess = req.siteAssignments.some(a => a.siteId === siteId);
    
    const isAdmin = req.siteAssignments.some(a => a.role === 'ops_admin');
    
    if (!hasAccess && !isAdmin) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: 'You do not have access to this site'
      });
    }
    
    req.currentSiteId = siteId;
    req.currentSiteRole = req.siteAssignments.find(a => a.siteId === siteId)?.role || (isAdmin ? 'ops_admin' : null);
    
    next();
  };
}

export function requireSiteRole(siteIdGetter, ...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const siteId = typeof siteIdGetter === 'function' ? siteIdGetter(req) : req.params.siteId || req.body.siteId;
    
    if (!siteId) {
      return res.status(400).json({ error: 'Site ID required' });
    }
    
    const assignment = req.siteAssignments.find(a => a.siteId === siteId);
    const isAdmin = req.siteAssignments.some(a => a.role === 'ops_admin');
    
    if (isAdmin) {
      req.currentSiteId = siteId;
      req.currentSiteRole = 'ops_admin';
      return next();
    }
    
    if (!assignment || !allowedRoles.includes(assignment.role)) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: `Required role at this site: ${allowedRoles.join(' or ')}`
      });
    }
    
    req.currentSiteId = siteId;
    req.currentSiteRole = assignment.role;
    
    next();
  };
}

export function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const isAdmin = req.siteAssignments.some(a => a.role === 'ops_admin');
  
  if (!isAdmin) {
    return res.status(403).json({ 
      error: 'Forbidden',
      message: 'Admin access required'
    });
  }
  
  next();
}

export function readOnly(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const isBuildingManager = req.siteAssignments.some(a => a.role === 'building_manager');
  const hasOtherRole = req.siteAssignments.some(a => a.role !== 'building_manager');
  
  if (isBuildingManager && !hasOtherRole) {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: 'Building manager access is read-only'
      });
    }
  }
  
  next();
}

const loginRateLimitMap = new Map();

export function loginRateLimit(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxAttempts = 10;
  
  const key = `login:${ip}`;
  
  if (!loginRateLimitMap.has(key)) {
    loginRateLimitMap.set(key, { count: 1, resetTime: now + windowMs });
    return next();
  }
  
  const record = loginRateLimitMap.get(key);
  
  if (now > record.resetTime) {
    loginRateLimitMap.set(key, { count: 1, resetTime: now + windowMs });
    return next();
  }
  
  if (record.count >= maxAttempts) {
    const remainingMinutes = Math.ceil((record.resetTime - now) / 60000);
    return res.status(429).json({ 
      error: 'Too many login attempts',
      message: `Please try again in ${remainingMinutes} minutes`
    });
  }
  
  record.count++;
  next();
}

export function requireWorkflowSession(req, res, next) {
  const workflowSessionId = req.headers['x-workflow-session'] || req.body.workflowSessionId;
  
  if (!workflowSessionId) {
    return res.status(400).json({ 
      error: 'Workflow session required',
      message: 'Scan the site QR code to start a workflow session'
    });
  }
  
  req.workflowSessionId = workflowSessionId;
  next();
}
