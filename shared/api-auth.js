import express from 'express';
import { authService } from './services/auth.js';
import { qrCodeService, workflowSessionService } from './services/workflowSession.js';
import { eventLogService } from './services/eventLog.js';
import { 
  requireAuth, 
  requireAdmin, 
  loginRateLimit,
  extractToken
} from './middleware/rbac.js';

const router = express.Router();

router.post('/check-user', loginRateLimit, async (req, res) => {
  try {
    const { employeeCode } = req.body;
    
    if (!employeeCode) {
      return res.status(400).json({ error: 'Employee code required' });
    }
    
    const result = await authService.checkFirstTimeUser(employeeCode);
    res.json(result);
  } catch (error) {
    console.error('Check user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/set-password', loginRateLimit, async (req, res) => {
  try {
    const { employeeCode, password, confirmPassword } = req.body;
    
    if (!employeeCode || !password) {
      return res.status(400).json({ error: 'Employee code and password required' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const user = await authService.setPassword(employeeCode, password);
    res.json({ success: true, message: 'Password set successfully' });
  } catch (error) {
    console.error('Set password error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.post('/login', loginRateLimit, async (req, res) => {
  try {
    const { employeeCode, password } = req.body;
    
    if (!employeeCode || !password) {
      return res.status(400).json({ error: 'Employee code and password required' });
    }
    
    const deviceInfo = {
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip || req.connection?.remoteAddress,
      fingerprint: req.body.fingerprint
    };
    
    const session = await authService.login(employeeCode, password, deviceInfo);
    
    res.json({
      success: true,
      token: session.token,
      sessionId: session.sessionId,
      expiresAt: session.expiresAt,
      user: session.user,
      siteAssignments: session.siteAssignments
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: error.message });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const token = extractToken(req);
    if (token) {
      await authService.logout(token);
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

router.get('/me', requireAuth, async (req, res) => {
  try {
    res.json({
      user: req.user,
      siteAssignments: req.siteAssignments
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { employeeCode, name, email } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const user = await authService.createUser({
      employeeCode,
      name,
      email,
      invitedByUserId: req.user.id
    });
    
    await eventLogService.appendEvent({
      eventType: 'USER_CREATED',
      actorUserId: req.user.id,
      payload: {
        createdUserId: user.id,
        employeeCode: user.employeeCode,
        name: user.name
      }
    });
    
    res.status(201).json({
      success: true,
      user: {
        id: user.id,
        employeeCode: user.employeeCode,
        name: user.name,
        email: user.email,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await authService.getAllUsers();
    res.json({ users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/users/:userId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await authService.getUserById(parseInt(userId));
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users/:userId/assign-site', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { siteId, role } = req.body;
    
    if (!siteId || !role) {
      return res.status(400).json({ error: 'Site ID and role are required' });
    }
    
    const assignment = await authService.assignUserToSite(
      parseInt(userId),
      siteId,
      role,
      req.user.id
    );
    
    await eventLogService.appendEvent({
      eventType: 'USER_SITE_ASSIGNED',
      actorUserId: req.user.id,
      siteId,
      payload: {
        assignedUserId: parseInt(userId),
        role
      }
    });
    
    res.json({ success: true, assignment });
  } catch (error) {
    console.error('Assign site error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.post('/admin/users/:userId/revoke-site', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { siteId } = req.body;
    
    if (!siteId) {
      return res.status(400).json({ error: 'Site ID is required' });
    }
    
    const assignment = await authService.revokeUserFromSite(
      parseInt(userId),
      siteId,
      req.user.id
    );
    
    await eventLogService.appendEvent({
      eventType: 'USER_SITE_REVOKED',
      actorUserId: req.user.id,
      siteId,
      payload: {
        revokedUserId: parseInt(userId)
      }
    });
    
    res.json({ success: true, assignment });
  } catch (error) {
    console.error('Revoke site error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.post('/admin/users/:employeeCode/revoke', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { employeeCode } = req.params;
    const { reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({ error: 'Revocation reason is required' });
    }
    
    const user = await authService.revokeUser(employeeCode, req.user.id, reason);
    
    await eventLogService.appendEvent({
      eventType: 'USER_REVOKED',
      actorUserId: req.user.id,
      payload: {
        revokedUserId: user.id,
        employeeCode: user.employeeCode,
        reason
      }
    });
    
    res.json({ success: true, user });
  } catch (error) {
    console.error('Revoke user error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.post('/admin/users/:employeeCode/force-password-reset', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { employeeCode } = req.params;
    
    const result = await authService.forcePasswordReset(employeeCode, req.user.id);
    
    await eventLogService.appendEvent({
      eventType: 'USER_PASSWORD_RESET_FORCED',
      actorUserId: req.user.id,
      payload: { employeeCode }
    });
    
    res.json(result);
  } catch (error) {
    console.error('Force password reset error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.post('/admin/users/:employeeCode/unlock', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { employeeCode } = req.params;
    
    const user = await authService.unlockUser(employeeCode);
    
    await eventLogService.appendEvent({
      eventType: 'USER_UNLOCKED',
      actorUserId: req.user.id,
      payload: { 
        unlockedUserId: user.id,
        employeeCode 
      }
    });
    
    res.json({ success: true, user });
  } catch (error) {
    console.error('Unlock user error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.post('/admin/users/:employeeCode/reactivate', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { employeeCode } = req.params;
    
    const user = await authService.reactivateUser(employeeCode, req.user.id);
    
    await eventLogService.appendEvent({
      eventType: 'USER_REACTIVATED',
      actorUserId: req.user.id,
      payload: { 
        reactivatedUserId: user.id,
        employeeCode 
      }
    });
    
    res.json({ success: true, user });
  } catch (error) {
    console.error('Reactivate user error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.get('/admin/users/:userId/sessions', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const sessions = await authService.getActiveSessions(parseInt(userId));
    res.json({ sessions });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/users/:userId/invalidate-sessions', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const result = await authService.invalidateAllUserSessions(parseInt(userId));
    
    await eventLogService.appendEvent({
      eventType: 'USER_SESSIONS_INVALIDATED',
      actorUserId: req.user.id,
      payload: { targetUserId: parseInt(userId) }
    });
    
    res.json(result);
  } catch (error) {
    console.error('Invalidate sessions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/sessions/:sessionId/invalidate', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const result = await authService.invalidateSession(sessionId);
    
    await eventLogService.appendEvent({
      eventType: 'SESSION_INVALIDATED',
      actorUserId: req.user.id,
      payload: { sessionId }
    });
    
    res.json(result);
  } catch (error) {
    console.error('Invalidate session error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/sites/:siteId/qr-code', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { siteId } = req.params;
    const { qrType, machineId } = req.body;
    
    const qrCode = await qrCodeService.generateSiteQrCode(
      siteId,
      req.user.id,
      qrType || 'site_presence',
      machineId
    );
    
    await eventLogService.appendEvent({
      eventType: 'QR_CODE_GENERATED',
      actorUserId: req.user.id,
      siteId,
      payload: {
        qrId: qrCode.qrId,
        qrType: qrCode.qrType
      }
    });
    
    res.json({ success: true, qrCode });
  } catch (error) {
    console.error('Generate QR code error:', error);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

router.get('/admin/sites/:siteId/qr-codes', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { siteId } = req.params;
    const qrCodes = await qrCodeService.getSiteQrCodes(siteId);
    res.json({ qrCodes });
  } catch (error) {
    console.error('Get QR codes error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/qr-codes/:qrId/revoke', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { qrId } = req.params;
    const qrCode = await qrCodeService.revokeQrCode(qrId);
    
    if (!qrCode) {
      return res.status(404).json({ error: 'QR code not found' });
    }
    
    await eventLogService.appendEvent({
      eventType: 'QR_CODE_REVOKED',
      actorUserId: req.user.id,
      siteId: qrCode.siteId,
      payload: { qrId }
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Revoke QR code error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/workflow/verify-qr', requireAuth, async (req, res) => {
  try {
    const { qrToken } = req.body;
    
    if (!qrToken) {
      return res.status(400).json({ error: 'QR token required' });
    }
    
    const verification = await qrCodeService.verifyQrCode(qrToken);
    res.json(verification);
  } catch (error) {
    console.error('Verify QR error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

router.post('/workflow/start', requireAuth, async (req, res) => {
  try {
    const { siteId, machineId, workflowType, qrToken, geoLat, geoLng, geoAccuracy } = req.body;
    
    if (!siteId || !workflowType || !qrToken) {
      return res.status(400).json({ error: 'Site ID, workflow type, and QR token are required' });
    }
    
    const session = await workflowSessionService.startSession({
      userId: req.user.id,
      siteId,
      machineId,
      workflowType,
      qrToken,
      geoLat,
      geoLng,
      geoAccuracy
    });
    
    await eventLogService.appendEvent({
      eventType: 'WORKFLOW_STARTED',
      actorUserId: req.user.id,
      siteId,
      machineId,
      workflowSessionId: session.sessionId,
      geoLat,
      geoLng,
      geoAccuracy,
      payload: {
        workflowType,
        userRole: session.userRole
      }
    });
    
    res.json({ success: true, session });
  } catch (error) {
    console.error('Start workflow error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.post('/workflow/complete', requireAuth, async (req, res) => {
  try {
    const { sessionId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID required' });
    }
    
    const validation = await workflowSessionService.validateSessionActive(sessionId);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }
    
    if (validation.session.userId !== req.user.id) {
      return res.status(403).json({ error: 'Not your session' });
    }
    
    const session = await workflowSessionService.completeSession(sessionId);
    
    await eventLogService.appendEvent({
      eventType: 'WORKFLOW_COMPLETED',
      actorUserId: req.user.id,
      siteId: session.siteId,
      machineId: session.machineId,
      workflowSessionId: sessionId,
      payload: {
        eventCount: session.eventCount,
        durationMinutes: Math.round((new Date(session.completedAt) - new Date(session.startedAt)) / 60000)
      }
    });
    
    res.json({ success: true, session });
  } catch (error) {
    console.error('Complete workflow error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/workflow/active', requireAuth, async (req, res) => {
  try {
    const session = await workflowSessionService.getActiveSessionForUser(req.user.id);
    res.json({ session });
  } catch (error) {
    console.error('Get active workflow error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/events', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { siteId, userId, limit } = req.query;
    
    let events;
    if (siteId) {
      events = await eventLogService.getEventsBySite(siteId, parseInt(limit) || 100);
    } else if (userId) {
      events = await eventLogService.getEventsByUser(parseInt(userId), parseInt(limit) || 100);
    } else {
      events = await eventLogService.getRecentEvents(parseInt(limit) || 100);
    }
    
    res.json({ events });
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/admin/events/:eventId', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { eventId } = req.params;
    const event = await eventLogService.getEventById(eventId);
    
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }
    
    res.json({ event });
  } catch (error) {
    console.error('Get event error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/admin/events/:eventId/correction', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { eventId } = req.params;
    const { correctionType, correctionPayload, reason } = req.body;
    
    if (!correctionType || !correctionPayload || !reason) {
      return res.status(400).json({ error: 'Correction type, payload, and reason are required' });
    }
    
    const correction = await eventLogService.appendCorrection({
      originalEventId: eventId,
      correctedByUserId: req.user.id,
      correctionType,
      correctionPayload,
      reason
    });
    
    res.json({ success: true, correction });
  } catch (error) {
    console.error('Create correction error:', error);
    res.status(400).json({ error: error.message });
  }
});

router.get('/admin/chain-integrity', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { startEventId, endEventId } = req.query;
    const result = await eventLogService.verifyChainIntegrity(startEventId, endEventId);
    res.json(result);
  } catch (error) {
    console.error('Chain integrity check error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;
