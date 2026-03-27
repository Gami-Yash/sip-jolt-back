import { logSecurityDeny } from '../../shared/production-hardening.js';

const isProduction = process.env.NODE_ENV === 'production' || process.env.REPL_SLUG;

const normalizeRole = (role) => {
  if (!role) return '';
  return String(role).trim().toLowerCase();
};

const resolveRoleAlias = (role) => {
  const normalized = normalizeRole(role);
  const aliasMap = {
    partner_technician: 'technician',
    tech: 'technician',
    ops: 'ops_manager',
    opsadmin: 'ops_admin',
    ops_admin: 'ops_admin',
    opsmanager: 'ops_manager',
    ops_manager: 'ops_manager',
  };
  return aliasMap[normalized] || normalized;
};

const normalizeRoles = (roles) => roles.map(resolveRoleAlias);

export const requireHeaderAuth = (allowedRoles = []) => {
  const normalizedAllowed = normalizeRoles(allowedRoles);

  return async (req, res, next) => {
    const userId = req.headers['x-user-id'];
    const rawRole = req.headers['x-user-role'];

    if (!userId || !rawRole) {
      if (!isProduction) {
        req.user = {
          id: userId || 'dev-user',
          role: resolveRoleAlias(rawRole || 'ops_manager')
        };
        return next();
      }

      await logSecurityDeny(req, 'MISSING_USER_ID_OR_ROLE', { path: req.path });
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userRole = resolveRoleAlias(rawRole);

    if (normalizedAllowed.length > 0 && !normalizedAllowed.includes(userRole)) {
      await logSecurityDeny(req, 'RBAC_DENIED', {
        userId,
        userRole,
        requiredRoles: normalizedAllowed,
        path: req.path
      });
      return res.status(403).json({ error: 'Access denied: insufficient permissions' });
    }

    req.user = { id: userId, role: userRole };
    next();
  };
};

export const requireSelfOrRole = (getTargetUserId, allowedRoles = []) => {
  const normalizedAllowed = normalizeRoles(allowedRoles);

  return async (req, res, next) => {
    const userId = req.user?.id || req.headers['x-user-id'];
    const rawRole = req.user?.role || req.headers['x-user-role'];
    const userRole = resolveRoleAlias(rawRole);
    const targetUserId = typeof getTargetUserId === 'function' ? getTargetUserId(req) : getTargetUserId;

    if (!userId || !targetUserId) {
      return next();
    }

    if (String(userId) !== String(targetUserId) && !normalizedAllowed.includes(userRole)) {
      await logSecurityDeny(req, 'CROSS_USER_ACCESS', {
        userId,
        targetUserId,
        userRole,
        path: req.path
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    next();
  };
};
