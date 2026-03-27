import crypto from 'crypto';
import { db } from '../db.js';
import { events, correctionEvents, attachments } from '../schema.js';
import { eq, desc } from 'drizzle-orm';

function generateULID() {
  const timestamp = Date.now().toString(36).padStart(10, '0');
  const randomPart = crypto.randomBytes(10).toString('hex').slice(0, 16);
  return (timestamp + randomPart).toUpperCase();
}

function normalizeDate(date) {
  if (!date) return null;
  if (typeof date === 'string') return date;
  return date.toISOString();
}

function computeEventHash(eventData, previousHash) {
  const payload = JSON.stringify({
    eventId: eventData.eventId,
    eventType: eventData.eventType,
    actorUserId: eventData.actorUserId,
    siteId: eventData.siteId,
    machineId: eventData.machineId,
    workflowSessionId: eventData.workflowSessionId,
    payloadJson: eventData.payloadJson,
    clientTimestamp: normalizeDate(eventData.clientTimestamp),
    serverTimestamp: normalizeDate(eventData.serverTimestamp),
    previousEventHash: previousHash
  });
  
  return crypto.createHash('sha256').update(payload).digest('hex');
}

export const eventLogService = {
  async appendEvent({
    eventType,
    actorUserId,
    siteId,
    machineId,
    workflowSessionId,
    payload,
    clientTimestamp,
    geoLat,
    geoLng,
    geoAccuracy,
    attachmentIds = []
  }) {
    const [lastEvent] = await db.select({ eventHash: events.eventHash })
      .from(events)
      .orderBy(desc(events.id))
      .limit(1);
    
    const previousEventHash = lastEvent?.eventHash || null;
    
    const eventId = generateULID();
    const serverTimestamp = new Date();
    
    const eventData = {
      eventId,
      eventType,
      actorUserId,
      siteId,
      machineId,
      workflowSessionId,
      payloadJson: payload,
      clientTimestamp: clientTimestamp ? new Date(clientTimestamp) : null,
      serverTimestamp
    };
    
    const eventHash = computeEventHash(eventData, previousEventHash);
    
    const [event] = await db.insert(events).values({
      eventId,
      eventType,
      actorUserId,
      siteId,
      machineId,
      workflowSessionId,
      payloadJson: payload,
      clientTimestamp: clientTimestamp ? new Date(clientTimestamp) : null,
      serverTimestamp,
      geoLat,
      geoLng,
      geoAccuracy,
      attachmentIds,
      previousEventHash,
      eventHash
    }).returning();
    
    return event;
  },

  async appendCorrection({
    originalEventId,
    correctedByUserId,
    correctionType,
    correctionPayload,
    reason
  }) {
    const validTypes = ['data_fix', 'clarification', 'void'];
    if (!validTypes.includes(correctionType)) {
      throw new Error(`Invalid correction type. Must be one of: ${validTypes.join(', ')}`);
    }
    
    const [original] = await db.select()
      .from(events)
      .where(eq(events.eventId, originalEventId))
      .limit(1);
    
    if (!original) {
      throw new Error('Original event not found');
    }
    
    const correctionId = generateULID();
    
    const [correction] = await db.insert(correctionEvents).values({
      correctionId,
      originalEventId,
      correctedByUserId,
      correctionType,
      correctionPayload,
      reason,
      serverTimestamp: new Date()
    }).returning();
    
    return correction;
  },

  async getEventById(eventId) {
    const [event] = await db.select()
      .from(events)
      .where(eq(events.eventId, eventId))
      .limit(1);
    
    if (!event) return null;
    
    const corrections = await db.select()
      .from(correctionEvents)
      .where(eq(correctionEvents.originalEventId, eventId));
    
    return {
      ...event,
      corrections
    };
  },

  async getEventsByWorkflowSession(workflowSessionId) {
    return db.select()
      .from(events)
      .where(eq(events.workflowSessionId, workflowSessionId))
      .orderBy(events.id);
  },

  async getEventsBySite(siteId, limit = 100) {
    return db.select()
      .from(events)
      .where(eq(events.siteId, siteId))
      .orderBy(desc(events.serverTimestamp))
      .limit(limit);
  },

  async getEventsByUser(userId, limit = 100) {
    return db.select()
      .from(events)
      .where(eq(events.actorUserId, userId))
      .orderBy(desc(events.serverTimestamp))
      .limit(limit);
  },

  async getRecentEvents(limit = 100) {
    return db.select()
      .from(events)
      .orderBy(desc(events.serverTimestamp))
      .limit(limit);
  },

  async verifyChainIntegrity(startEventId, endEventId) {
    const allEvents = await db.select()
      .from(events)
      .orderBy(events.id);
    
    let startIndex = 0;
    let endIndex = allEvents.length - 1;
    
    if (startEventId) {
      startIndex = allEvents.findIndex(e => e.eventId === startEventId);
      if (startIndex === -1) throw new Error('Start event not found');
    }
    
    if (endEventId) {
      endIndex = allEvents.findIndex(e => e.eventId === endEventId);
      if (endIndex === -1) throw new Error('End event not found');
    }
    
    const results = [];
    
    for (let i = startIndex; i <= endIndex; i++) {
      const event = allEvents[i];
      const expectedPreviousHash = i > 0 ? allEvents[i - 1].eventHash : null;
      
      const valid = event.previousEventHash === expectedPreviousHash;
      
      const recomputedHash = computeEventHash({
        eventId: event.eventId,
        eventType: event.eventType,
        actorUserId: event.actorUserId,
        siteId: event.siteId,
        machineId: event.machineId,
        workflowSessionId: event.workflowSessionId,
        payloadJson: event.payloadJson,
        clientTimestamp: event.clientTimestamp,
        serverTimestamp: event.serverTimestamp
      }, event.previousEventHash);
      
      const hashValid = event.eventHash === recomputedHash;
      
      results.push({
        eventId: event.eventId,
        chainValid: valid,
        hashValid,
        tampered: !valid || !hashValid
      });
    }
    
    const tamperedEvents = results.filter(r => r.tampered);
    
    return {
      totalChecked: results.length,
      valid: tamperedEvents.length === 0,
      tamperedCount: tamperedEvents.length,
      tamperedEvents
    };
  }
};

export const attachmentService = {
  async createAttachment({
    eventId,
    workflowSessionId,
    userId,
    siteId,
    fileHash,
    perceptualHash,
    objectPath,
    fileSizeBytes,
    mimeType,
    clientCapturedTimestamp,
    geoLat,
    geoLng,
    geoAccuracy,
    deviceInfo
  }) {
    const attachmentId = crypto.randomUUID();
    
    let isDuplicate = false;
    let duplicateOfId = null;
    
    if (fileHash) {
      const [existing] = await db.select()
        .from(attachments)
        .where(eq(attachments.fileHash, fileHash))
        .limit(1);
      
      if (existing) {
        isDuplicate = true;
        duplicateOfId = existing.attachmentId;
      }
    }
    
    const [attachment] = await db.insert(attachments).values({
      attachmentId,
      eventId,
      workflowSessionId,
      userId,
      siteId,
      fileHash,
      perceptualHash,
      objectPath,
      fileSizeBytes,
      mimeType,
      clientCapturedTimestamp: clientCapturedTimestamp ? new Date(clientCapturedTimestamp) : null,
      serverReceivedTimestamp: new Date(),
      geoLat,
      geoLng,
      geoAccuracy,
      deviceInfo,
      isDuplicate,
      duplicateOfId
    }).returning();
    
    return attachment;
  },

  async getAttachmentById(attachmentId) {
    const [attachment] = await db.select()
      .from(attachments)
      .where(eq(attachments.attachmentId, attachmentId))
      .limit(1);
    return attachment;
  },

  async getAttachmentsByEvent(eventId) {
    return db.select()
      .from(attachments)
      .where(eq(attachments.eventId, eventId));
  },

  async getAttachmentsByWorkflowSession(workflowSessionId) {
    return db.select()
      .from(attachments)
      .where(eq(attachments.workflowSessionId, workflowSessionId));
  },

  async checkDuplicate(fileHash) {
    if (!fileHash) return { isDuplicate: false };
    
    const [existing] = await db.select()
      .from(attachments)
      .where(eq(attachments.fileHash, fileHash))
      .limit(1);
    
    if (existing) {
      return {
        isDuplicate: true,
        originalAttachmentId: existing.attachmentId,
        originalEventId: existing.eventId
      };
    }
    
    return { isDuplicate: false };
  }
};
