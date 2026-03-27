import { db } from '../db.js';
import { visits, prizes, photoAudits, aiChatLogs } from '../schema.js';
import { eq, desc } from 'drizzle-orm';

export async function createVisit(visitData) {
  const { 
    technicianId, 
    machineId, 
    visitType, 
    completedQuestions, 
    photos, 
    problems, 
    optionSelections, 
    textInputs, 
    durationMinutes 
  } = visitData;
  
  try {
    const [visit] = await db.insert(visits).values({
      technicianId,
      machineId: machineId || 'DEFAULT-001',
      visitType,
      completedQuestions: completedQuestions || {},
      photos: photos || {},
      problems: problems || {},
      optionSelections: optionSelections || {},
      textInputs: textInputs || {},
      durationMinutes: durationMinutes || 0
    }).returning();
    
    return visit;
  } catch (error) {
    console.error('[VisitService] create error:', error.message);
    throw new Error(`Database error creating visit: ${error.message}`);
  }
}

export async function getVisitById(visitId) {
  try {
    const [visit] = await db.select()
      .from(visits)
      .where(eq(visits.id, parseInt(visitId)))
      .limit(1);
    return visit || null;
  } catch (error) {
    console.error('[VisitService] getById error:', error.message);
    throw new Error(`Database error fetching visit: ${error.message}`);
  }
}

export async function getRecentVisits(limit = 50) {
  try {
    return await db.select()
      .from(visits)
      .orderBy(desc(visits.completedAt))
      .limit(limit);
  } catch (error) {
    console.error('[VisitService] getRecent error:', error.message);
    throw new Error(`Database error fetching visits: ${error.message}`);
  }
}

export async function getVisitsByTechnician(technicianId, limit = 50) {
  try {
    return await db.select()
      .from(visits)
      .where(eq(visits.technicianId, technicianId))
      .orderBy(desc(visits.completedAt))
      .limit(limit);
  } catch (error) {
    console.error('[VisitService] getByTechnician error:', error.message);
    throw new Error(`Database error fetching technician visits: ${error.message}`);
  }
}

export async function markVisitSynced(visitId, syncedBy) {
  try {
    const [visit] = await db.update(visits)
      .set({
        syncedToMachineApp: true,
        syncedAt: new Date(),
        syncedBy: syncedBy || 'ops'
      })
      .where(eq(visits.id, parseInt(visitId)))
      .returning();
    
    return visit;
  } catch (error) {
    console.error('[VisitService] markSynced error:', error.message);
    throw new Error(`Database error syncing visit: ${error.message}`);
  }
}

export async function unmarkVisitSynced(visitId) {
  try {
    const [visit] = await db.update(visits)
      .set({
        syncedToMachineApp: false,
        syncedAt: null,
        syncedBy: null
      })
      .where(eq(visits.id, parseInt(visitId)))
      .returning();
    
    return visit;
  } catch (error) {
    console.error('[VisitService] unmarkSynced error:', error.message);
    throw new Error(`Database error unsyncing visit: ${error.message}`);
  }
}

export async function createPrize(prizeData) {
  const { technicianId, prizeType, prizeName, prizeValue, visitType, notifyOps } = prizeData;
  
  try {
    const [prize] = await db.insert(prizes).values({
      technicianId,
      prizeType,
      prizeName,
      prizeValue: prizeValue || 0,
      visitType,
      notifyOps: notifyOps || false
    }).returning();
    
    return prize;
  } catch (error) {
    console.error('[VisitService] createPrize error:', error.message);
    throw new Error(`Database error creating prize: ${error.message}`);
  }
}

export async function getAllPrizes() {
  try {
    return await db.select().from(prizes).orderBy(desc(prizes.wonAt));
  } catch (error) {
    console.error('[VisitService] getAllPrizes error:', error.message);
    throw new Error(`Database error fetching prizes: ${error.message}`);
  }
}

export async function getPrizesByTechnician(technicianId, limit = 50) {
  try {
    return await db.select()
      .from(prizes)
      .where(eq(prizes.technicianId, technicianId))
      .orderBy(desc(prizes.wonAt))
      .limit(limit);
  } catch (error) {
    console.error('[VisitService] getPrizesByTechnician error:', error.message);
    throw new Error(`Database error fetching prizes: ${error.message}`);
  }
}

export async function createPhotoAudit(photoData) {
  const { technicianId, machineId, visitId, questionId, photoData: photo } = photoData;
  
  try {
    const [audit] = await db.insert(photoAudits).values({
      technicianId,
      machineId,
      visitId,
      questionId,
      photoData: photo
    }).returning();
    
    return audit;
  } catch (error) {
    console.error('[VisitService] createPhotoAudit error:', error.message);
    throw new Error(`Database error creating photo audit: ${error.message}`);
  }
}

export async function getPendingPhotoAudits(limit = 20) {
  try {
    return await db.select()
      .from(photoAudits)
      .where(eq(photoAudits.approved, null))
      .orderBy(desc(photoAudits.createdAt))
      .limit(limit);
  } catch (error) {
    console.error('[VisitService] getPendingPhotos error:', error.message);
    throw new Error(`Database error fetching pending photos: ${error.message}`);
  }
}

export async function reviewPhotoAudit(photoId, approved, approvedBy) {
  try {
    await db.update(photoAudits)
      .set({
        approved,
        approvedBy,
        approvedAt: new Date()
      })
      .where(eq(photoAudits.id, parseInt(photoId)));
    
    return { photoId, approved };
  } catch (error) {
    console.error('[VisitService] reviewPhoto error:', error.message);
    throw new Error(`Database error reviewing photo: ${error.message}`);
  }
}

export async function getPhotoAuditById(photoId) {
  try {
    const [photo] = await db.select()
      .from(photoAudits)
      .where(eq(photoAudits.id, parseInt(photoId)))
      .limit(1);
    return photo || null;
  } catch (error) {
    console.error('[VisitService] getPhotoById error:', error.message);
    throw new Error(`Database error fetching photo: ${error.message}`);
  }
}

export async function reviewPhotoAuditAndAwardXP(photoId, approved, approvedBy, awardXPCallback) {
  try {
    await reviewPhotoAudit(photoId, approved, approvedBy);
    
    if (approved && awardXPCallback) {
      const photo = await getPhotoAuditById(photoId);
      if (photo && photo.technicianId) {
        await awardXPCallback(photo.technicianId, 50);
      }
    }
    
    return { success: true, photoId, approved };
  } catch (error) {
    console.error('[VisitService] reviewAndAward error:', error.message);
    throw new Error(`Database error reviewing photo: ${error.message}`);
  }
}

export async function getPhotosByVisit(visitId) {
  try {
    return await db.select()
      .from(photoAudits)
      .where(eq(photoAudits.visitId, parseInt(visitId)));
  } catch (error) {
    console.error('[VisitService] getPhotosByVisit error:', error.message);
    throw new Error(`Database error fetching photos: ${error.message}`);
  }
}

export async function createAiChatLog(chatData) {
  const { technicianId, machineId, question, response, hasImage } = chatData;
  
  try {
    const [chat] = await db.insert(aiChatLogs).values({
      technicianId,
      machineId,
      question,
      response,
      hasImage: hasImage || false
    }).returning();
    
    return chat;
  } catch (error) {
    console.error('[VisitService] createAiChat error:', error.message);
    throw new Error(`Database error logging AI chat: ${error.message}`);
  }
}

export async function getRecentAiChats(limit = 20) {
  try {
    return await db.select()
      .from(aiChatLogs)
      .orderBy(desc(aiChatLogs.createdAt))
      .limit(limit);
  } catch (error) {
    console.error('[VisitService] getRecentAiChats error:', error.message);
    throw new Error(`Database error fetching AI chats: ${error.message}`);
  }
}
