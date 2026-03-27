import { db } from '../db.js';
import { technicians } from '../schema.js';
import { eq } from 'drizzle-orm';

export async function findTechnicianByIdOrName(identifier) {
  if (!identifier) return null;
  
  const idString = String(identifier);
  
  try {
    let results = await db.select().from(technicians)
      .where(eq(technicians.technicianId, idString))
      .limit(1);
    
    if (results.length > 0) return results[0];
    
    if (isNaN(Number(idString))) {
      results = await db.select().from(technicians)
        .where(eq(technicians.name, idString))
        .limit(1);
      if (results.length > 0) return results[0];
    }
    
    return null;
  } catch (error) {
    console.error('[TechnicianService] findByIdOrName error:', error.message);
    throw new Error(`Database error finding technician: ${error.message}`);
  }
}

export async function createTechnician(technicianId, name) {
  const idString = String(technicianId);
  
  try {
    const [newTech] = await db.insert(technicians).values({
      technicianId: idString,
      name: name || idString,
      xp: 0,
      streak: 0,
      onTimeRate: 100,
      badges: [],
      totalVisits: 0,
      weeklyVisits: 0,
      monthlyVisits: 0,
      loginCount: 1
    }).returning();
    
    return newTech;
  } catch (error) {
    console.error('[TechnicianService] create error:', error.message);
    throw new Error(`Database error creating technician: ${error.message}`);
  }
}

export async function getOrCreateTechnician(technicianId, name) {
  const existing = await findTechnicianByIdOrName(technicianId);
  if (existing) {
    return { technician: existing, isNew: false };
  }
  const newTech = await createTechnician(technicianId, name);
  return { technician: newTech, isNew: true };
}

export async function updateTechnicianStats(technicianId, updates) {
  try {
    const tech = await findTechnicianByIdOrName(technicianId);
    if (!tech) {
      throw new Error('Technician not found');
    }
    
    const [updated] = await db.update(technicians)
      .set({
        ...updates,
        updatedAt: new Date()
      })
      .where(eq(technicians.technicianId, tech.technicianId))
      .returning();
    
    return updated;
  } catch (error) {
    console.error('[TechnicianService] updateStats error:', error.message);
    throw new Error(`Database error updating technician: ${error.message}`);
  }
}

export async function awardXP(technicianId, xpAmount) {
  const tech = await findTechnicianByIdOrName(technicianId);
  if (!tech) return null;
  
  return updateTechnicianStats(technicianId, {
    xp: tech.xp + xpAmount
  });
}

export async function recordVisit(technicianId, visitType) {
  const tech = await findTechnicianByIdOrName(technicianId);
  if (!tech) {
    await createTechnician(technicianId, String(technicianId));
    return recordVisit(technicianId, visitType);
  }
  
  const xpGain = visitType === 'weekly' ? 100 : 250;
  
  return updateTechnicianStats(technicianId, {
    xp: tech.xp + xpGain,
    totalVisits: tech.totalVisits + 1,
    weeklyVisits: visitType === 'weekly' ? tech.weeklyVisits + 1 : tech.weeklyVisits,
    monthlyVisits: visitType === 'monthly' ? tech.monthlyVisits + 1 : tech.monthlyVisits
  });
}

export async function getAllTechnicians() {
  try {
    return await db.select().from(technicians).orderBy(technicians.xp);
  } catch (error) {
    console.error('[TechnicianService] getAll error:', error.message);
    throw new Error(`Database error fetching technicians: ${error.message}`);
  }
}
