import crypto from 'crypto';

const conversationLogs = new Map();
const lastHashes = new Map();
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function hashContent(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function createChainHash(entry) {
  const payload = JSON.stringify({
    id: entry.id,
    conversationId: entry.conversationId,
    timestamp: entry.timestamp,
    userId: entry.userId,
    direction: entry.direction,
    contentHash: entry.contentHash,
    previousHash: entry.previousHash,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

export class ConversationAuditLogger {
  constructor(userId, userRole, siteId) {
    this.conversationId = `CONV_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    this.userId = userId;
    this.userRole = userRole;
    this.siteId = siteId;
    conversationLogs.set(this.conversationId, []);
    lastHashes.set(this.conversationId, GENESIS_HASH);
  }

  logUserMessage(content, metadata = {}) {
    return this.log('USER_TO_AI', content, metadata);
  }

  logAIResponse(content, metadata = {}, responseTimeMs) {
    return this.log('AI_TO_USER', content, { ...metadata, responseTimeMs });
  }

  logRestrictedQuery(userContent, restrictionReason, responseContent) {
    const userLog = this.log('USER_TO_AI', userContent, { restricted: true, restrictionReason });
    const responseLog = this.log('AI_TO_USER', responseContent, { restricted: true, restrictionReason });
    return { userLog, responseLog };
  }

  log(direction, content, metadata) {
    const timestamp = new Date().toISOString();
    const contentHash = hashContent(content);
    const previousHash = lastHashes.get(this.conversationId) || GENESIS_HASH;

    const entry = {
      id: `LOG_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
      conversationId: this.conversationId,
      timestamp,
      userId: this.userId,
      userRole: this.userRole,
      siteId: this.siteId,
      direction,
      content,
      contentHash,
      previousHash,
      currentHash: '',
      metadata,
    };

    entry.currentHash = createChainHash(entry);
    lastHashes.set(this.conversationId, entry.currentHash);

    const logs = conversationLogs.get(this.conversationId) || [];
    logs.push(entry);
    conversationLogs.set(this.conversationId, logs);

    console.log(`[AUDIT] ${direction} | User: ${this.userId} | Hash: ${entry.currentHash.slice(0, 16)}...`);
    return entry;
  }

  getSummary() {
    const logs = conversationLogs.get(this.conversationId) || [];
    return {
      conversationId: this.conversationId,
      userId: this.userId,
      userRole: this.userRole,
      siteId: this.siteId,
      startedAt: logs[0]?.timestamp || new Date().toISOString(),
      endedAt: logs[logs.length - 1]?.timestamp,
      messageCount: logs.length,
      restrictedQueries: logs.filter(l => l.metadata.restricted).length,
      hashChainValid: this.verifyChain(),
    };
  }

  verifyChain() {
    const logs = conversationLogs.get(this.conversationId) || [];
    if (logs.length === 0) return true;
    if (logs[0].previousHash !== GENESIS_HASH) return false;
    for (let i = 1; i < logs.length; i++) {
      if (logs[i].previousHash !== logs[i - 1].currentHash) return false;
      const recalculatedHash = createChainHash(logs[i]);
      if (recalculatedHash !== logs[i].currentHash) return false;
    }
    return true;
  }

  exportForEvidence() {
    const logs = conversationLogs.get(this.conversationId) || [];
    const summary = this.getSummary();
    const exportedAt = new Date().toISOString();
    const exportPayload = JSON.stringify({ summary, entries: logs, exportedAt });
    const exportHash = hashContent(exportPayload);
    return { summary, entries: logs, exportedAt, exportHash };
  }

  getConversationId() {
    return this.conversationId;
  }
}

export function getLogsForUser(userId) {
  const allLogs = [];
  for (const logs of conversationLogs.values()) {
    allLogs.push(...logs.filter(l => l.userId === userId));
  }
  return allLogs.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export function getLogsForSite(siteId) {
  const allLogs = [];
  for (const logs of conversationLogs.values()) {
    allLogs.push(...logs.filter(l => l.siteId === siteId));
  }
  return allLogs.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export function getRestrictedQueryStats() {
  const stats = { total: 0, byRole: {}, byReason: {} };
  for (const logs of conversationLogs.values()) {
    for (const log of logs) {
      if (log.metadata.restricted) {
        stats.total++;
        stats.byRole[log.userRole] = (stats.byRole[log.userRole] || 0) + 1;
        const reason = log.metadata.restrictionReason || 'UNKNOWN';
        stats.byReason[reason] = (stats.byReason[reason] || 0) + 1;
      }
    }
  }
  return stats;
}

export function cleanupOldConversations(maxAgeDays = 30) {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - maxAgeDays);
  const cutoffStr = cutoff.toISOString();
  let deleted = 0;
  for (const [convId, logs] of conversationLogs.entries()) {
    if (logs.length > 0 && logs[logs.length - 1].timestamp < cutoffStr) {
      conversationLogs.delete(convId);
      lastHashes.delete(convId);
      deleted++;
    }
  }
  return deleted;
}
