import crypto from 'crypto';
import { db } from '../db.js';
import { siteQrCodes, workflowSessions, userSiteAssignments } from '../schema.js';
import { eq, and, isNull, desc } from 'drizzle-orm';

const QR_SECRET = process.env.QR_SECRET || 'jolt-qr-secret-key-2026';

function signQrPayload(payload) {
  const data = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', QR_SECRET).update(data).digest('hex');
  return Buffer.from(JSON.stringify({ data: payload, sig: signature })).toString('base64');
}

function verifyQrPayload(token) {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    const { data, sig } = decoded;
    
    const expectedSig = crypto.createHmac('sha256', QR_SECRET).update(JSON.stringify(data)).digest('hex');
    
    if (sig !== expectedSig) {
      return { valid: false, error: 'Invalid signature' };
    }
    
    return { valid: true, payload: data };
  } catch (error) {
    return { valid: false, error: 'Invalid token format' };
  }
}

export const qrCodeService = {
  async generateSiteQrCode(siteId, generatedByUserId, qrType = 'site_presence', machineId = null) {
    const qrId = crypto.randomUUID();
    
    const payload = {
      qrId,
      siteId,
      qrType,
      machineId,
      generatedAt: new Date().toISOString()
    };
    
    const qrToken = signQrPayload(payload);
    
    const [qrCode] = await db.insert(siteQrCodes).values({
      qrId,
      siteId,
      qrToken,
      qrType,
      machineId,
      isActive: true,
      generatedBy: generatedByUserId,
      generatedAt: new Date()
    }).returning();
    
    return {
      ...qrCode,
      qrDataUrl: `jolt://verify/${qrToken}`
    };
  },

  async verifyQrCode(qrToken) {
    const verification = verifyQrPayload(qrToken);
    
    if (!verification.valid) {
      return { valid: false, error: verification.error };
    }
    
    const { payload } = verification;
    
    const [qrCode] = await db.select()
      .from(siteQrCodes)
      .where(eq(siteQrCodes.qrId, payload.qrId))
      .limit(1);
    
    if (!qrCode) {
      return { valid: false, error: 'QR code not found in database' };
    }
    
    if (!qrCode.isActive) {
      return { valid: false, error: 'QR code has been revoked' };
    }
    
    if (qrCode.revokedAt) {
      return { valid: false, error: 'QR code has been revoked' };
    }
    
    return {
      valid: true,
      siteId: qrCode.siteId,
      qrType: qrCode.qrType,
      machineId: qrCode.machineId,
      qrId: qrCode.qrId
    };
  },

  async revokeQrCode(qrId) {
    const [qrCode] = await db.update(siteQrCodes)
      .set({
        isActive: false,
        revokedAt: new Date()
      })
      .where(eq(siteQrCodes.qrId, qrId))
      .returning();
    
    return qrCode;
  },

  async getSiteQrCodes(siteId) {
    return db.select()
      .from(siteQrCodes)
      .where(and(
        eq(siteQrCodes.siteId, siteId),
        eq(siteQrCodes.isActive, true)
      ));
  },

  async getActiveQrCodeForSite(siteId) {
    const [qrCode] = await db.select()
      .from(siteQrCodes)
      .where(and(
        eq(siteQrCodes.siteId, siteId),
        eq(siteQrCodes.isActive, true),
        eq(siteQrCodes.qrType, 'site_presence')
      ))
      .orderBy(desc(siteQrCodes.generatedAt))
      .limit(1);
    
    return qrCode;
  }
};

export const workflowSessionService = {
  async startSession({
    userId,
    siteId,
    machineId,
    workflowType,
    qrToken,
    geoLat,
    geoLng,
    geoAccuracy
  }) {
    const qrVerification = await qrCodeService.verifyQrCode(qrToken);
    
    if (!qrVerification.valid) {
      throw new Error(`QR verification failed: ${qrVerification.error}`);
    }
    
    if (qrVerification.siteId !== siteId) {
      throw new Error('QR code does not match the requested site');
    }
    
    const [assignment] = await db.select()
      .from(userSiteAssignments)
      .where(and(
        eq(userSiteAssignments.userId, userId),
        eq(userSiteAssignments.siteId, siteId),
        isNull(userSiteAssignments.revokedAt)
      ))
      .limit(1);
    
    if (!assignment) {
      throw new Error('User is not assigned to this site');
    }
    
    const validWorkflowsForRole = {
      technician: ['weekly_visit', 'monthly_clean'],
      partner: ['refill_task', 'weekly_visit'],
      driver: ['pod_delivery'],
      ops_admin: ['weekly_visit', 'monthly_clean', 'refill_task', 'pod_delivery']
    };
    
    const allowedWorkflows = validWorkflowsForRole[assignment.role] || [];
    if (!allowedWorkflows.includes(workflowType)) {
      throw new Error(`Role ${assignment.role} cannot start ${workflowType} workflow`);
    }
    
    const sessionId = crypto.randomUUID();
    
    const [session] = await db.insert(workflowSessions).values({
      sessionId,
      userId,
      siteId,
      machineId,
      workflowType,
      qrScanTimestamp: new Date(),
      qrScanGeoLat: geoLat,
      qrScanGeoLng: geoLng,
      qrScanGeoAccuracy: geoAccuracy,
      startedAt: new Date(),
      status: 'in_progress',
      eventCount: 0
    }).returning();
    
    return {
      ...session,
      userRole: assignment.role
    };
  },

  async completeSession(sessionId) {
    const [session] = await db.update(workflowSessions)
      .set({
        status: 'completed',
        completedAt: new Date()
      })
      .where(eq(workflowSessions.sessionId, sessionId))
      .returning();
    
    return session;
  },

  async abandonSession(sessionId) {
    const [session] = await db.update(workflowSessions)
      .set({
        status: 'abandoned',
        abandonedAt: new Date()
      })
      .where(eq(workflowSessions.sessionId, sessionId))
      .returning();
    
    return session;
  },

  async incrementEventCount(sessionId) {
    const [session] = await db.select()
      .from(workflowSessions)
      .where(eq(workflowSessions.sessionId, sessionId))
      .limit(1);
    
    if (!session) return null;
    
    const [updated] = await db.update(workflowSessions)
      .set({ eventCount: (session.eventCount || 0) + 1 })
      .where(eq(workflowSessions.sessionId, sessionId))
      .returning();
    
    return updated;
  },

  async getSessionById(sessionId) {
    const [session] = await db.select()
      .from(workflowSessions)
      .where(eq(workflowSessions.sessionId, sessionId))
      .limit(1);
    return session;
  },

  async getActiveSessionForUser(userId) {
    const [session] = await db.select()
      .from(workflowSessions)
      .where(and(
        eq(workflowSessions.userId, userId),
        eq(workflowSessions.status, 'in_progress')
      ))
      .orderBy(desc(workflowSessions.startedAt))
      .limit(1);
    
    return session;
  },

  async getSessionsBySite(siteId, limit = 50) {
    return db.select()
      .from(workflowSessions)
      .where(eq(workflowSessions.siteId, siteId))
      .orderBy(desc(workflowSessions.startedAt))
      .limit(limit);
  },

  async validateSessionActive(sessionId) {
    const session = await this.getSessionById(sessionId);
    
    if (!session) {
      return { valid: false, error: 'Session not found' };
    }
    
    if (session.status !== 'in_progress') {
      return { valid: false, error: `Session is ${session.status}` };
    }
    
    const hoursSinceStart = (Date.now() - new Date(session.startedAt).getTime()) / (1000 * 60 * 60);
    if (hoursSinceStart > 8) {
      await this.abandonSession(sessionId);
      return { valid: false, error: 'Session expired (8 hour limit)' };
    }
    
    return { valid: true, session };
  }
};
