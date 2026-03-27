import { db } from '../db.js';
import { machines } from '../schema.js';
import { eq } from 'drizzle-orm';

export function formatTimestamp(timestamp) {
  if (!timestamp) return 'Never';
  const now = new Date();
  const date = new Date(timestamp);
  const diffMs = now - date;
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return '1 day ago';
  if (diffDays < 7) return `${diffDays} days ago`;
  if (diffDays < 14) return '1 week ago';
  return `${Math.floor(diffDays / 7)} weeks ago`;
}

export async function getAllMachines() {
  try {
    return await db.select().from(machines).orderBy(machines.machineId);
  } catch (error) {
    console.error('[MachineService] getAll error:', error.message);
    throw new Error(`Database error fetching machines: ${error.message}`);
  }
}

export async function getMachineById(machineId) {
  try {
    const [machine] = await db.select()
      .from(machines)
      .where(eq(machines.machineId, machineId))
      .limit(1);
    return machine || null;
  } catch (error) {
    console.error('[MachineService] getById error:', error.message);
    throw new Error(`Database error fetching machine: ${error.message}`);
  }
}

export async function getFleetOverview() {
  try {
    const allMachines = await getAllMachines();
    
    const normalizedMachines = allMachines.map(m => ({
      id: m.machineId,
      nickname: m.nickname,
      location: m.location,
      status: m.status,
      notes: m.notes || '',
      lastVisit: formatTimestamp(m.lastVisitDate),
      nextWeeklyDue: m.nextWeeklyDue,
      cupsToday: m.cupsServedToday || 0,
      technician: m.lastVisitTechId || 'Unassigned',
      errors: Array.isArray(m.activeErrors) ? m.activeErrors : [],
      inventory: m.inventory || { beans: 100, oat: 100, vanilla: 100, mocha: 100, cups: 500 }
    }));
    
    const totalFleet = normalizedMachines.length;
    const criticalIssues = normalizedMachines.filter(m => m.status === 'repair' || m.status === 'offline').length;
    const serviceDue = normalizedMachines.filter(m => m.nextWeeklyDue && new Date(m.nextWeeklyDue) < new Date()).length;
    const totalCupsToday = normalizedMachines.reduce((sum, m) => sum + (m.cupsToday || 0), 0);
    const estimatedRevenue = Math.round(totalCupsToday * 3.5 * 7);
    
    return {
      totalFleet,
      criticalIssues,
      serviceDue,
      estimatedRevenue,
      machines: normalizedMachines
    };
  } catch (error) {
    console.error('[MachineService] getFleetOverview error:', error.message);
    throw new Error(`Database error fetching fleet: ${error.message}`);
  }
}

export async function createMachine(machineData) {
  const { machineId, nickname, location, status, inventory } = machineData;
  
  try {
    const existing = await getMachineById(machineId);
    if (existing) {
      throw new Error('Machine with this ID already exists');
    }
    
    const [machine] = await db.insert(machines).values({
      machineId,
      nickname,
      location,
      status: status || 'active',
      notes: '',
      inventory: inventory || { beans: 100, oat: 100, vanilla: 100, mocha: 100, cups: 500 }
    }).returning();
    
    return machine;
  } catch (error) {
    console.error('[MachineService] create error:', error.message);
    throw error;
  }
}

export async function updateMachine(machineId, updates) {
  try {
    const updateData = { ...updates, updatedAt: new Date() };
    
    const [machine] = await db.update(machines)
      .set(updateData)
      .where(eq(machines.machineId, machineId))
      .returning();
    
    return machine;
  } catch (error) {
    console.error('[MachineService] update error:', error.message);
    throw new Error(`Database error updating machine: ${error.message}`);
  }
}

export async function deleteMachine(machineId) {
  try {
    const deleted = await db.delete(machines)
      .where(eq(machines.machineId, machineId))
      .returning();
    
    return deleted.length > 0;
  } catch (error) {
    console.error('[MachineService] delete error:', error.message);
    throw new Error(`Database error deleting machine: ${error.message}`);
  }
}

export async function recordMachineVisit(machineId, technicianId) {
  try {
    const machine = await getMachineById(machineId);
    if (!machine) return null;
    
    return updateMachine(machineId, {
      lastVisitDate: new Date(),
      lastVisitTechId: technicianId,
      nextWeeklyDue: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });
  } catch (error) {
    console.error('[MachineService] recordVisit error:', error.message);
    throw new Error(`Database error recording visit: ${error.message}`);
  }
}
