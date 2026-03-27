import { db } from '../db.js';
import { tenants, opsSites, joltUsers, events, photos, workflowSessions, userSiteAssignments, attachments } from '../schema.js';
import { eq, and, isNull, desc } from 'drizzle-orm';

const DEFAULT_TENANT_ID = 'JOLT_INTERNAL';

export async function createTenant({ tenantId, name, contactEmail, contactPhone, createdBy }) {
  const [tenant] = await db.insert(tenants).values({
    tenantId,
    name,
    contactEmail,
    contactPhone,
    isActive: true,
    createdBy,
    createdAt: new Date(),
    updatedAt: new Date()
  }).returning();
  return tenant;
}

export async function getTenantById(tenantId) {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.tenantId, tenantId)).limit(1);
  return tenant || null;
}

export async function getAllTenants(includeInactive = false) {
  if (includeInactive) {
    return db.select().from(tenants).orderBy(tenants.name);
  }
  return db.select().from(tenants).where(eq(tenants.isActive, true)).orderBy(tenants.name);
}

export async function updateTenant(tenantId, updates) {
  const [updated] = await db.update(tenants)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(tenants.tenantId, tenantId))
    .returning();
  return updated || null;
}

export async function deactivateTenant(tenantId) {
  return updateTenant(tenantId, { isActive: false });
}

export async function getSitesByTenant(tenantId) {
  return db.select().from(opsSites).where(eq(opsSites.tenantId, tenantId)).orderBy(opsSites.venueName);
}

export async function assignSiteToTenant(siteId, tenantId) {
  const [updated] = await db.update(opsSites)
    .set({ tenantId, updatedAt: new Date() })
    .where(eq(opsSites.siteId, siteId))
    .returning();
  return updated || null;
}

export async function getUsersByTenant(tenantId, includeRevoked = false) {
  const conditions = [eq(joltUsers.tenantId, tenantId)];
  if (!includeRevoked) {
    conditions.push(isNull(joltUsers.revokedAt));
  }
  return db.select().from(joltUsers).where(and(...conditions)).orderBy(joltUsers.name);
}

export async function assignUserToTenant(userId, tenantId) {
  const [updated] = await db.update(joltUsers)
    .set({ tenantId, updatedAt: new Date() })
    .where(eq(joltUsers.id, userId))
    .returning();
  return updated || null;
}

export async function getEventsByTenant(tenantId, limit = 100) {
  return db.select()
    .from(events)
    .where(eq(events.tenantId, tenantId))
    .orderBy(desc(events.serverTimestamp))
    .limit(limit);
}

export async function getPhotosByTenant(tenantId, limit = 100) {
  return db.select()
    .from(photos)
    .where(eq(photos.tenantId, tenantId))
    .orderBy(desc(photos.serverReceivedAt))
    .limit(limit);
}

export async function getWorkflowSessionsByTenant(tenantId, limit = 100) {
  return db.select()
    .from(workflowSessions)
    .where(eq(workflowSessions.tenantId, tenantId))
    .orderBy(desc(workflowSessions.startedAt))
    .limit(limit);
}

export async function getTenantStats(tenantId) {
  const [siteCount] = await db.select({ count: opsSites.id })
    .from(opsSites)
    .where(eq(opsSites.tenantId, tenantId));
    
  const [userCount] = await db.select({ count: joltUsers.id })
    .from(joltUsers)
    .where(and(eq(joltUsers.tenantId, tenantId), isNull(joltUsers.revokedAt)));
    
  const [eventCount] = await db.select({ count: events.id })
    .from(events)
    .where(eq(events.tenantId, tenantId));
    
  return {
    sites: parseInt(siteCount?.count || 0),
    activeUsers: parseInt(userCount?.count || 0),
    totalEvents: parseInt(eventCount?.count || 0)
  };
}

export function validateTenantAccess(user, requiredTenantId) {
  if (!user) return false;
  if (user.role === 'ops_admin') return true;
  if (!user.tenantId) return false;
  return user.tenantId === requiredTenantId;
}

export function tenantScopeMiddleware(requiredRole = null) {
  return (req, res, next) => {
    const user = req.authUser;
    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const tenantId = req.params.tenantId || req.query.tenantId || req.body?.tenantId;
    
    if (user.role === 'ops_admin') {
      req.tenantId = tenantId || user.tenantId || DEFAULT_TENANT_ID;
      return next();
    }
    
    if (!user.tenantId) {
      return res.status(403).json({ error: 'User not assigned to a tenant' });
    }
    
    if (tenantId && tenantId !== user.tenantId) {
      return res.status(403).json({ error: 'Access denied: cross-tenant access not permitted' });
    }
    
    if (requiredRole && user.role !== requiredRole) {
      return res.status(403).json({ error: `Access denied: ${requiredRole} role required` });
    }
    
    req.tenantId = user.tenantId;
    next();
  };
}

export const getDefaultTenantId = () => DEFAULT_TENANT_ID;
