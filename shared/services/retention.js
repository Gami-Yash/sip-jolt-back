import { db } from '../db.js';
import { retentionTracking, photos, events, attachments } from '../schema.js';
import { eq, and, lte, sql } from 'drizzle-orm';

const DEFAULT_RETENTION_DAYS = 365;

export async function trackRetention({ tableName, recordId, tenantId, retentionDays = DEFAULT_RETENTION_DAYS, createdAt }) {
  const expiresAt = new Date(new Date(createdAt).getTime() + retentionDays * 24 * 60 * 60 * 1000);
  
  const [tracking] = await db.insert(retentionTracking).values({
    tableName,
    recordId,
    tenantId,
    retentionDays,
    createdAt: new Date(createdAt),
    expiresAt,
    markedForDeletion: false
  }).returning();
  
  return tracking;
}

export async function getExpiredRecords(limit = 100) {
  const now = new Date();
  
  return db.select()
    .from(retentionTracking)
    .where(and(
      lte(retentionTracking.expiresAt, now),
      eq(retentionTracking.markedForDeletion, false),
      sql`${retentionTracking.deletedAt} IS NULL`
    ))
    .limit(limit);
}

export async function markForDeletion(ids) {
  const updated = await db.update(retentionTracking)
    .set({ markedForDeletion: true })
    .where(sql`id = ANY(${ids})`)
    .returning();
  
  return updated;
}

export async function confirmDeletion(recordId, tableName) {
  const [updated] = await db.update(retentionTracking)
    .set({ deletedAt: new Date() })
    .where(and(
      eq(retentionTracking.recordId, recordId),
      eq(retentionTracking.tableName, tableName)
    ))
    .returning();
  
  return updated;
}

export async function getRetentionStats(tenantId = null) {
  const conditions = [sql`1=1`];
  if (tenantId) {
    conditions.push(eq(retentionTracking.tenantId, tenantId));
  }
  
  const stats = await db.select({
    tableName: retentionTracking.tableName,
    total: sql`COUNT(*)`,
    markedForDeletion: sql`SUM(CASE WHEN marked_for_deletion = true THEN 1 ELSE 0 END)`,
    deleted: sql`SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END)`,
    expiringInWeek: sql`SUM(CASE WHEN expires_at <= NOW() + INTERVAL '7 days' AND deleted_at IS NULL THEN 1 ELSE 0 END)`,
    expiringInMonth: sql`SUM(CASE WHEN expires_at <= NOW() + INTERVAL '30 days' AND deleted_at IS NULL THEN 1 ELSE 0 END)`
  })
    .from(retentionTracking)
    .where(and(...conditions))
    .groupBy(retentionTracking.tableName);
  
  return stats;
}

export async function bulkTrackRetention(records, tableName, tenantId = null, retentionDays = DEFAULT_RETENTION_DAYS) {
  if (!records || records.length === 0) return [];
  
  const trackingRecords = records.map(record => {
    const createdAt = record.createdAt || record.serverReceivedAt || new Date();
    const expiresAt = new Date(new Date(createdAt).getTime() + retentionDays * 24 * 60 * 60 * 1000);
    
    return {
      tableName,
      recordId: record.id?.toString() || record.photoId || record.eventId || record.attachmentId,
      tenantId: record.tenantId || tenantId,
      retentionDays,
      createdAt: new Date(createdAt),
      expiresAt,
      markedForDeletion: false
    };
  });
  
  const inserted = await db.insert(retentionTracking)
    .values(trackingRecords)
    .onConflictDoNothing()
    .returning();
  
  return inserted;
}

export async function runRetentionCleanup(dryRun = true) {
  const expired = await getExpiredRecords(1000);
  
  if (dryRun) {
    return {
      dryRun: true,
      expiredCount: expired.length,
      byTable: expired.reduce((acc, r) => {
        acc[r.tableName] = (acc[r.tableName] || 0) + 1;
        return acc;
      }, {})
    };
  }
  
  const results = {
    processed: 0,
    deleted: 0,
    errors: []
  };
  
  for (const record of expired) {
    try {
      await db.update(retentionTracking)
        .set({ markedForDeletion: true })
        .where(eq(retentionTracking.id, record.id));
      
      results.processed++;
    } catch (error) {
      results.errors.push({ recordId: record.recordId, error: error.message });
    }
  }
  
  return results;
}

export async function extendRetention(recordId, tableName, additionalDays) {
  const [record] = await db.select()
    .from(retentionTracking)
    .where(and(
      eq(retentionTracking.recordId, recordId),
      eq(retentionTracking.tableName, tableName)
    ))
    .limit(1);
  
  if (!record) {
    throw new Error('Retention record not found');
  }
  
  const newExpiry = new Date(new Date(record.expiresAt).getTime() + additionalDays * 24 * 60 * 60 * 1000);
  
  const [updated] = await db.update(retentionTracking)
    .set({
      retentionDays: record.retentionDays + additionalDays,
      expiresAt: newExpiry,
      markedForDeletion: false
    })
    .where(eq(retentionTracking.id, record.id))
    .returning();
  
  return updated;
}
