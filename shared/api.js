import express from 'express';
import { checkDatabaseHealth } from './db.js';
import * as TechnicianService from './services/technicians.js';
import * as VideoService from './services/videos.js';
import * as MachineService from './services/machines.js';
import * as VisitService from './services/visits.js';

const router = express.Router();

const requireOpsAuth = (req, res, next) => {
  const authToken = req.headers['x-ops-token'] || req.query.opsToken;
  const validToken = process.env.OPS_AUTH_TOKEN;
  
  if (!validToken) {
    return res.status(500).json({ error: 'Server configuration error' });
  }
  
  if (authToken === validToken) {
    next();
  } else {
    res.status(403).json({ error: 'Unauthorized' });
  }
};

const rateLimitMap = new Map();
const rateLimit = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 100;
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    next();
  } else {
    const record = rateLimitMap.get(ip);
    if (now > record.resetTime) {
      rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
      next();
    } else if (record.count < maxRequests) {
      record.count++;
      next();
    } else {
      res.status(429).json({ error: 'Too many requests' });
    }
  }
};

router.get('/health', async (req, res) => {
  try {
    const dbHealth = await checkDatabaseHealth();
    const serverUtcNow = new Date().toISOString();
    res.json({
      status: dbHealth.healthy ? 'ok' : 'error',
      database: dbHealth,
      timestamp: serverUtcNow,
      server_utc_now: serverUtcNow
    });
  } catch (error) {
    const serverUtcNow = new Date().toISOString();
    res.status(500).json({
      status: 'error',
      database: { healthy: false, message: error.message },
      timestamp: serverUtcNow,
      server_utc_now: serverUtcNow
    });
  }
});

router.post('/visits', async (req, res) => {
  try {
    const { technicianId, machineId, visitType, completedQuestions, photos, problems, optionSelections, textInputs, durationMinutes } = req.body;
    
    if (!technicianId || !visitType) {
      return res.status(400).json({ error: 'technicianId and visitType are required' });
    }
    if (!['weekly', 'monthly'].includes(visitType)) {
      return res.status(400).json({ error: 'visitType must be "weekly" or "monthly"' });
    }
    
    const visit = await VisitService.createVisit({
      technicianId,
      machineId,
      visitType,
      completedQuestions,
      photos,
      problems,
      optionSelections,
      textInputs,
      durationMinutes
    });
    
    await TechnicianService.recordVisit(technicianId, visitType);
    
    if (machineId) {
      await MachineService.recordMachineVisit(machineId, technicianId);
    }
    
    res.json({ success: true, visit });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/prizes', async (req, res) => {
  try {
    const { technicianId, prizeType, prizeName, prizeValue, visitType, notifyOps } = req.body;
    
    if (!technicianId || !prizeType || !prizeName || !visitType) {
      return res.status(400).json({ error: 'technicianId, prizeType, prizeName, and visitType are required' });
    }
    if (!['collectible', 'money'].includes(prizeType)) {
      return res.status(400).json({ error: 'prizeType must be "collectible" or "money"' });
    }
    if (!['weekly', 'monthly'].includes(visitType)) {
      return res.status(400).json({ error: 'visitType must be "weekly" or "monthly"' });
    }
    
    const prize = await VisitService.createPrize({ technicianId, prizeType, prizeName, prizeValue, visitType, notifyOps });
    res.json({ success: true, prize });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/photos', async (req, res) => {
  try {
    const { technicianId, machineId, visitId, questionId, photoData } = req.body;
    
    if (!technicianId || !machineId || !questionId || !photoData) {
      return res.status(400).json({ error: 'technicianId, machineId, questionId, and photoData are required' });
    }
    
    const photo = await VisitService.createPhotoAudit({ technicianId, machineId, visitId, questionId, photoData });
    res.json({ success: true, photo });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/ai-chats', async (req, res) => {
  try {
    const { technicianId, machineId, question, response, hasImage } = req.body;
    
    if (!technicianId || !question || !response) {
      return res.status(400).json({ error: 'technicianId, question, and response are required' });
    }
    
    const chat = await VisitService.createAiChatLog({ technicianId, machineId, question, response, hasImage });
    res.json({ success: true, chat });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/fleet', requireOpsAuth, async (req, res) => {
  try {
    const fleet = await MachineService.getFleetOverview();
    res.json(fleet);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/technicians', requireOpsAuth, async (req, res) => {
  try {
    const techs = await TechnicianService.getAllTechnicians();
    res.json({ technicians: techs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/visits', requireOpsAuth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const recentVisits = await VisitService.getRecentVisits(limit);
    res.json({ visits: recentVisits });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/visits/:id', requireOpsAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const visit = await VisitService.getVisitById(id);
    
    if (!visit) {
      return res.status(404).json({ error: 'Visit not found' });
    }
    
    const visitPhotos = await VisitService.getPhotosByVisit(id);
    const machine = await MachineService.getMachineById(visit.machineId);
    const technician = await TechnicianService.findTechnicianByIdOrName(visit.technicianId);
    
    res.json({
      success: true,
      visit,
      photos: visitPhotos,
      machine,
      technician
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/ops/visits/:id/sync', requireOpsAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { syncedBy } = req.body;
    
    const visit = await VisitService.markVisitSynced(id, syncedBy);
    if (!visit) {
      return res.status(404).json({ error: 'Visit not found' });
    }
    
    res.json({ success: true, visit });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/ops/visits/:id/sync', requireOpsAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const visit = await VisitService.unmarkVisitSynced(id);
    
    if (!visit) {
      return res.status(404).json({ error: 'Visit not found' });
    }
    
    res.json({ success: true, visit });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/prizes', requireOpsAuth, async (req, res) => {
  try {
    const allPrizes = await VisitService.getAllPrizes();
    
    const totalPrizes = allPrizes.length;
    const giftCardPrizes = allPrizes.filter(p => p.notifyOps);
    const totalGiftCardValue = giftCardPrizes.reduce((sum, p) => sum + (p.prizeValue || 0), 0);
    
    res.json({
      totalPrizes,
      giftCardCount: giftCardPrizes.length,
      totalGiftCardValue,
      prizes: allPrizes
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/photos/pending', requireOpsAuth, async (req, res) => {
  try {
    const pendingPhotos = await VisitService.getPendingPhotoAudits(20);
    res.json({ photos: pendingPhotos });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/ops/photos/:id/review', requireOpsAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { approved, approvedBy } = req.body;
    
    await VisitService.reviewPhotoAuditAndAwardXP(id, approved, approvedBy, TechnicianService.awardXP);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/ai-insights', requireOpsAuth, async (req, res) => {
  try {
    const limitVal = parseInt(req.query.limit, 10);
    const limit = !isNaN(limitVal) && limitVal > 0 ? limitVal : 20;
    const recentChats = await VisitService.getRecentAiChats(limit);
    res.json({ chats: recentChats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/ops/machines', requireOpsAuth, async (req, res) => {
  try {
    const { machineId, nickname, location, status, inventory } = req.body;
    
    if (!machineId || !nickname || !location) {
      return res.status(400).json({ error: 'machineId, nickname, and location are required' });
    }
    
    const machine = await MachineService.createMachine({ machineId, nickname, location, status, inventory });
    res.json({ success: true, machine });
  } catch (error) {
    if (error.message.includes('already exists')) {
      return res.status(409).json({ error: error.message });
    }
    res.status(500).json({ error: error.message });
  }
});

router.put('/ops/machines/:id', requireOpsAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { nickname, location, status, inventory, notes } = req.body;
    
    const updateData = {};
    if (nickname !== undefined) updateData.nickname = nickname;
    if (location !== undefined) updateData.location = location;
    if (status !== undefined) updateData.status = status;
    if (inventory !== undefined) updateData.inventory = inventory;
    if (notes !== undefined) updateData.notes = notes;
    
    const machine = await MachineService.updateMachine(id, updateData);
    
    if (!machine) {
      return res.status(404).json({ error: 'Machine not found' });
    }
    
    res.json({ success: true, machine });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/ops/machines/:id', requireOpsAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await MachineService.deleteMachine(id);
    
    if (!deleted) {
      return res.status(404).json({ error: 'Machine not found' });
    }
    
    res.json({ success: true, message: 'Machine deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/ops/machines/seed', requireOpsAuth, async (req, res) => {
  try {
    const { machines: machineList } = req.body;
    
    for (const machine of machineList) {
      const existing = await MachineService.getMachineById(machine.machineId);
      if (!existing) {
        await MachineService.createMachine(machine);
      }
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/ops/export/:type', requireOpsAuth, async (req, res) => {
  try {
    const { type } = req.params;
    let data;
    
    switch (type) {
      case 'visits':
        data = await VisitService.getRecentVisits(1000);
        break;
      case 'prizes':
        data = await VisitService.getAllPrizes();
        break;
      case 'technicians':
        data = await TechnicianService.getAllTechnicians();
        break;
      case 'machines':
        data = await MachineService.getAllMachines();
        break;
      default:
        return res.status(400).json({ error: 'Invalid export type' });
    }
    
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/ai/chat', async (req, res) => {
  try {
    const { message, image, systemPrompt } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ error: 'AI service not configured', text: 'API key missing' });
    }
    
    const parts = [{ text: message || "What do you see in this image?" }];
    if (image) {
      parts.push({
        inlineData: {
          mimeType: image.mimeType,
          data: image.data
        }
      });
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: parts }],
          systemInstruction: { parts: [{ text: systemPrompt || 'You are a helpful assistant.' }] }
        }),
        signal: controller.signal
      }
    );
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      return res.status(response.status).json({ error: `Gemini API returned ${response.status}`, text: 'Try again in a moment' });
    }
    
    const data = await response.json();
    const aiText = data.candidates?.[0]?.content?.parts?.[0]?.text || 'Unable to generate response';
    
    res.json({ success: true, text: aiText });
  } catch (error) {
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'Request timeout', text: 'API took too long to respond. Try again.' });
    }
    res.status(500).json({ error: 'Connection failed', text: 'Please try again in a moment.' });
  }
});

router.post('/auth/ops', async (req, res) => {
  try {
    const { code } = req.body;
    const validToken = process.env.OPS_AUTH_TOKEN;
    
    if (!validToken) {
      return res.status(500).json({ error: 'Server configuration error', authorized: false });
    }
    
    if (code === validToken) {
      res.json({ success: true, authorized: true });
    } else {
      res.status(401).json({ error: 'Invalid ops manager code', authorized: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message, authorized: false });
  }
});

router.post('/technicians', async (req, res) => {
  try {
    const { technicianId, name } = req.body;
    
    if (!technicianId) {
      return res.status(400).json({ error: 'technicianId is required' });
    }
    
    const { technician, isNew } = await TechnicianService.getOrCreateTechnician(technicianId, name);
    res.json({ success: true, technician, isNew });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/technicians/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const tech = await TechnicianService.findTechnicianByIdOrName(id);
    
    if (!tech) {
      return res.status(404).json({ error: 'Technician not found' });
    }
    
    res.json({ success: true, technician: tech });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/technicians/:id/visits', async (req, res) => {
  try {
    const { id } = req.params;
    const limitVal = parseInt(req.query.limit, 10);
    const limit = !isNaN(limitVal) && limitVal > 0 ? limitVal : 50;
    
    const techVisits = await VisitService.getVisitsByTechnician(id, limit);
    res.json({ success: true, visits: techVisits });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/technicians/:id/prizes', async (req, res) => {
  try {
    const { id } = req.params;
    const limitVal = parseInt(req.query.limit, 10);
    const limit = !isNaN(limitVal) && limitVal > 0 ? limitVal : 50;
    
    const techPrizes = await VisitService.getPrizesByTechnician(id, limit);
    res.json({ success: true, prizes: techPrizes });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/notifications/preferences/:technicianId', async (req, res) => {
  res.json({ preferences: { enabledNotifications: true, visitReminders: true, prizeAlerts: true, machineAlerts: true, maintenanceReminders: true } });
});

router.post('/notifications/preferences/:technicianId', async (req, res) => {
  res.json({ success: true, preferences: { enabledNotifications: true } });
});

router.get('/notifications/:technicianId', async (req, res) => {
  res.json({ notifications: [] });
});

router.post('/notifications', async (req, res) => {
  res.json({ success: true, notification: { id: Date.now() } });
});

router.post('/notifications/:id/read', async (req, res) => {
  res.json({ success: true, notification: {} });
});

router.delete('/notifications/:id', async (req, res) => {
  res.json({ success: true });
});

router.get('/videos', requireOpsAuth, async (req, res) => {
  try {
    const result = await VideoService.getAllVideoStepsWithStatus();
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/videos/:stepId', async (req, res) => {
  try {
    const { stepId } = req.params;
    const video = await VideoService.getVideoByStepId(stepId);
    
    if (!video || !video.videoUrl) {
      return res.status(404).json({ 
        error: 'Video not found',
        stepId,
        message: 'No video has been uploaded for this step yet.'
      });
    }
    
    res.json({ success: true, video });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/videos/:stepId', requireOpsAuth, async (req, res) => {
  try {
    const { stepId } = req.params;
    const { videoUrl, objectPath, fileSize, durationSeconds, uploadedBy } = req.body;
    
    const stepDef = VideoService.getStepDefinition(stepId);
    if (!stepDef) {
      return res.status(400).json({ error: 'Invalid step ID' });
    }
    
    const result = await VideoService.saveVideoMetadata(stepId, { videoUrl, objectPath, fileSize, durationSeconds, uploadedBy });
    res.json({ success: true, video: result.video, action: result.action });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/videos/:stepId', requireOpsAuth, async (req, res) => {
  try {
    const { stepId } = req.params;
    const updated = await VideoService.deleteVideo(stepId);
    
    if (!updated) {
      return res.status(404).json({ error: 'Video record not found' });
    }
    
    res.json({ success: true, message: 'Video removed' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Sites endpoint for Label Station
router.get('/sites', async (req, res) => {
  try {
    const { db } = await import('./db.js');
    const { opsSites } = await import('./schema.js');
    const sites = await db.select({
      site_id: opsSites.siteId,
      venue_name: opsSites.venueName,
      address: opsSites.address,
      primary_contact: opsSites.primaryContactName,
      status: opsSites.status
    }).from(opsSites);
    res.json({ sites: sites || [] });
  } catch (error) {
    console.error('Error fetching sites:', error);
    res.json({ sites: [] });
  }
});

export default router;
