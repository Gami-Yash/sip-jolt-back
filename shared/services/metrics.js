import { db } from '../db.js';
import { 
  systemMetrics, uploadFailures, geoDenials, sessionMetrics, 
  loginLockouts, rateLimits, visitReceipts, tenantIsolationAlerts 
} from '../schema.js';
import { eq, and, gte, lte, desc, sql } from 'drizzle-orm';
import crypto from 'crypto';

const generateId = () => crypto.randomBytes(8).toString('hex');

export async function recordUploadFailure({
  tenantId, userId, siteId, workflowSessionId, failureType, errorMessage, fileSizeBytes, mimeType
}) {
  const [failure] = await db.insert(uploadFailures).values({
    tenantId,
    userId,
    siteId,
    workflowSessionId,
    failureType,
    errorMessage,
    fileSizeBytes,
    mimeType,
    retryCount: 0,
    resolved: false,
    createdAt: new Date()
  }).returning();
  return failure;
}

export async function recordGeoDenial({
  tenantId, userId, siteId, workflowSessionId, denialReason,
  expectedLat, expectedLng, actualLat, actualLng, distanceMeters, accuracyMeters, deviceInfo
}) {
  const [denial] = await db.insert(geoDenials).values({
    tenantId,
    userId,
    siteId,
    workflowSessionId,
    denialReason,
    expectedLat,
    expectedLng,
    actualLat,
    actualLng,
    distanceMeters,
    accuracyMeters,
    deviceInfo,
    createdAt: new Date()
  }).returning();
  return denial;
}

export async function recordSessionMetric({
  tenantId, workflowSessionId, userId, siteId, workflowType, status,
  startedAt, completedAt, stepCount, photoCount, issueCount, receiptHash
}) {
  const durationSeconds = completedAt && startedAt 
    ? Math.floor((new Date(completedAt) - new Date(startedAt)) / 1000) 
    : null;

  const [metric] = await db.insert(sessionMetrics).values({
    tenantId,
    workflowSessionId,
    userId,
    siteId,
    workflowType,
    status,
    startedAt,
    completedAt,
    durationSeconds,
    stepCount,
    photoCount,
    issueCount,
    receiptHash,
    createdAt: new Date()
  }).returning();
  return metric;
}

export async function recordLoginLockout({
  userId, employeeCode, lockoutReason, failedAttempts, lockedUntil, ipAddress, userAgent
}) {
  const [lockout] = await db.insert(loginLockouts).values({
    userId,
    employeeCode,
    lockoutReason,
    failedAttempts,
    lockedAt: new Date(),
    lockedUntil,
    ipAddress,
    userAgent,
    createdAt: new Date()
  }).returning();
  return lockout;
}

export async function unlockUser(userId, unlockedBy) {
  const [updated] = await db.update(loginLockouts)
    .set({ unlockedAt: new Date(), unlockedBy })
    .where(and(
      eq(loginLockouts.userId, userId),
      sql`${loginLockouts.unlockedAt} IS NULL`
    ))
    .returning();
  return updated;
}

export async function checkRateLimit(limitKey, limitType, maxCount, windowSeconds) {
  const now = new Date();
  const windowStart = new Date(now.getTime() - windowSeconds * 1000);

  const [existing] = await db.select()
    .from(rateLimits)
    .where(eq(rateLimits.limitKey, limitKey))
    .limit(1);

  if (!existing) {
    const [newLimit] = await db.insert(rateLimits).values({
      limitKey,
      limitType,
      currentCount: 1,
      maxCount,
      windowStart: now,
      windowSeconds,
      lastRequestAt: now,
      blocked: false
    }).returning();
    return { allowed: true, remaining: maxCount - 1, resetAt: new Date(now.getTime() + windowSeconds * 1000) };
  }

  if (new Date(existing.windowStart) < windowStart) {
    const [reset] = await db.update(rateLimits)
      .set({ currentCount: 1, windowStart: now, lastRequestAt: now, blocked: false, blockedAt: null, blockedUntil: null })
      .where(eq(rateLimits.limitKey, limitKey))
      .returning();
    return { allowed: true, remaining: maxCount - 1, resetAt: new Date(now.getTime() + windowSeconds * 1000) };
  }

  if (existing.currentCount >= maxCount) {
    if (!existing.blocked) {
      await db.update(rateLimits)
        .set({ blocked: true, blockedAt: now, blockedUntil: new Date(new Date(existing.windowStart).getTime() + windowSeconds * 1000) })
        .where(eq(rateLimits.limitKey, limitKey));
    }
    return { allowed: false, remaining: 0, resetAt: new Date(new Date(existing.windowStart).getTime() + windowSeconds * 1000) };
  }

  const [updated] = await db.update(rateLimits)
    .set({ currentCount: existing.currentCount + 1, lastRequestAt: now })
    .where(eq(rateLimits.limitKey, limitKey))
    .returning();
  
  return { 
    allowed: true, 
    remaining: maxCount - updated.currentCount, 
    resetAt: new Date(new Date(existing.windowStart).getTime() + windowSeconds * 1000) 
  };
}

export async function createVisitReceipt({
  tenantId, workflowSessionId, userId, siteId, workflowType,
  events, photos, issues, startedAt, completedAt, geoVerified
}) {
  const receiptId = `RCP-${generateId()}`;
  const eventCount = events?.length || 0;
  const photoCount = photos?.length || 0;
  const issueCount = issues?.length || 0;
  const durationSeconds = Math.floor((new Date(completedAt) - new Date(startedAt)) / 1000);

  const receiptPayload = {
    workflowSessionId,
    userId,
    siteId,
    workflowType,
    eventCount,
    photoCount,
    issueCount,
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date(completedAt).toISOString(),
    durationSeconds,
    geoVerified,
    eventIds: events?.map(e => e.eventId) || [],
    photoIds: photos?.map(p => p.photoId) || [],
    issueIds: issues?.map(i => i.id) || [],
    generatedAt: new Date().toISOString()
  };

  const receiptHash = crypto.createHash('sha256')
    .update(JSON.stringify(receiptPayload))
    .digest('hex');

  const [receipt] = await db.insert(visitReceipts).values({
    receiptId,
    tenantId,
    workflowSessionId,
    userId,
    siteId,
    workflowType,
    receiptHash,
    receiptPayload,
    eventCount,
    photoCount,
    issueCount,
    startedAt,
    completedAt,
    durationSeconds,
    geoVerified,
    createdAt: new Date()
  }).returning();

  return receipt;
}

export async function confirmVisitReceipt(receiptId, clientConfirmedAt = new Date()) {
  const [updated] = await db.update(visitReceipts)
    .set({ clientConfirmedAt })
    .where(eq(visitReceipts.receiptId, receiptId))
    .returning();
  return updated;
}

export async function recordTenantIsolationAlert({
  alertType, tableName, recordIds, expectedTenantId, actualTenantId, queryContext, severity = 'warning'
}) {
  const [alert] = await db.insert(tenantIsolationAlerts).values({
    alertType,
    tableName,
    recordIds,
    expectedTenantId,
    actualTenantId,
    queryContext,
    severity,
    resolved: false,
    createdAt: new Date()
  }).returning();
  return alert;
}

export async function getMetricsSummary(tenantId = null, periodDays = 7) {
  const periodStart = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);
  
  const tenantFilter = tenantId ? eq(uploadFailures.tenantId, tenantId) : sql`1=1`;
  
  const uploadFailureCount = await db.select({ count: sql`COUNT(*)` })
    .from(uploadFailures)
    .where(and(tenantFilter, gte(uploadFailures.createdAt, periodStart)));
  
  const geoDenialCount = await db.select({ count: sql`COUNT(*)` })
    .from(geoDenials)
    .where(and(
      tenantId ? eq(geoDenials.tenantId, tenantId) : sql`1=1`,
      gte(geoDenials.createdAt, periodStart)
    ));
  
  const sessionStats = await db.select({
    total: sql`COUNT(*)`,
    completed: sql`SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)`,
    avgDuration: sql`AVG(duration_seconds)`
  })
    .from(sessionMetrics)
    .where(and(
      tenantId ? eq(sessionMetrics.tenantId, tenantId) : sql`1=1`,
      gte(sessionMetrics.createdAt, periodStart)
    ));
  
  const lockoutCount = await db.select({ count: sql`COUNT(*)` })
    .from(loginLockouts)
    .where(gte(loginLockouts.createdAt, periodStart));
  
  const isolationAlerts = await db.select({ count: sql`COUNT(*)`, unresolved: sql`SUM(CASE WHEN resolved = false THEN 1 ELSE 0 END)` })
    .from(tenantIsolationAlerts)
    .where(gte(tenantIsolationAlerts.createdAt, periodStart));

  return {
    period: { start: periodStart, end: new Date(), days: periodDays },
    uploadFailures: parseInt(uploadFailureCount[0]?.count || 0),
    geoDenials: parseInt(geoDenialCount[0]?.count || 0),
    sessions: {
      total: parseInt(sessionStats[0]?.total || 0),
      completed: parseInt(sessionStats[0]?.completed || 0),
      completionRate: sessionStats[0]?.total > 0 
        ? Math.round((sessionStats[0].completed / sessionStats[0].total) * 100) 
        : 0,
      avgDurationMinutes: Math.round((sessionStats[0]?.avgDuration || 0) / 60)
    },
    loginLockouts: parseInt(lockoutCount[0]?.count || 0),
    tenantIsolationAlerts: {
      total: parseInt(isolationAlerts[0]?.count || 0),
      unresolved: parseInt(isolationAlerts[0]?.unresolved || 0)
    }
  };
}

export async function getRecentUploadFailures(tenantId = null, limit = 50) {
  const conditions = [sql`1=1`];
  if (tenantId) conditions.push(eq(uploadFailures.tenantId, tenantId));
  
  return db.select()
    .from(uploadFailures)
    .where(and(...conditions))
    .orderBy(desc(uploadFailures.createdAt))
    .limit(limit);
}

export async function getRecentGeoDenials(tenantId = null, limit = 50) {
  const conditions = [sql`1=1`];
  if (tenantId) conditions.push(eq(geoDenials.tenantId, tenantId));
  
  return db.select()
    .from(geoDenials)
    .where(and(...conditions))
    .orderBy(desc(geoDenials.createdAt))
    .limit(limit);
}

export async function getActiveLockouts() {
  return db.select()
    .from(loginLockouts)
    .where(sql`${loginLockouts.unlockedAt} IS NULL AND (${loginLockouts.lockedUntil} IS NULL OR ${loginLockouts.lockedUntil} > NOW())`)
    .orderBy(desc(loginLockouts.lockedAt));
}

export async function getUnresolvedIsolationAlerts() {
  return db.select()
    .from(tenantIsolationAlerts)
    .where(eq(tenantIsolationAlerts.resolved, false))
    .orderBy(desc(tenantIsolationAlerts.createdAt));
}

export async function resolveIsolationAlert(alertId, resolvedBy) {
  const [updated] = await db.update(tenantIsolationAlerts)
    .set({ resolved: true, resolvedAt: new Date(), resolvedBy })
    .where(eq(tenantIsolationAlerts.id, alertId))
    .returning();
  return updated;
}
