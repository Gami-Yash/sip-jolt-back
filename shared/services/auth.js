import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { db } from '../db.js';
import { joltUsers, authSessions, userSiteAssignments } from '../schema.js';
import { eq, and, gt, isNull } from 'drizzle-orm';

const SALT_ROUNDS = 12;
const SESSION_EXPIRY_HOURS = 24;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 30;

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateEmployeeCode() {
  const prefix = 'JT';
  const number = Math.floor(10000 + Math.random() * 90000);
  return `${prefix}${number}`;
}

export const authService = {
  async createUser({ employeeCode, name, email, invitedByUserId }) {
    const code = employeeCode || generateEmployeeCode();
    
    const existing = await db.select().from(joltUsers).where(eq(joltUsers.employeeCode, code)).limit(1);
    if (existing.length > 0) {
      throw new Error('Employee code already exists');
    }
    
    const [user] = await db.insert(joltUsers).values({
      employeeCode: code,
      name,
      email,
      status: 'pending_password',
      invitedBy: invitedByUserId?.toString(),
      invitedAt: new Date()
    }).returning();
    
    return user;
  },

  async setPassword(employeeCode, password) {
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }
    
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    
    const [user] = await db.update(joltUsers)
      .set({
        passwordHash,
        passwordSetAt: new Date(),
        status: 'active',
        failedLoginAttempts: 0,
        lockedUntil: null,
        updatedAt: new Date()
      })
      .where(eq(joltUsers.employeeCode, employeeCode))
      .returning();
    
    if (!user) {
      throw new Error('User not found');
    }
    
    return user;
  },

  async login(employeeCode, password, deviceInfo = {}) {
    const [user] = await db.select().from(joltUsers).where(eq(joltUsers.employeeCode, employeeCode)).limit(1);
    
    if (!user) {
      throw new Error('Invalid credentials');
    }
    
    if (user.status === 'revoked') {
      throw new Error('Account has been revoked');
    }
    
    if (user.status === 'pending_password') {
      throw new Error('Password not set. Please complete first-time setup.');
    }
    
    if (user.status === 'locked' && user.lockedUntil && new Date() < new Date(user.lockedUntil)) {
      const remainingMinutes = Math.ceil((new Date(user.lockedUntil) - new Date()) / 60000);
      throw new Error(`Account locked. Try again in ${remainingMinutes} minutes.`);
    }
    
    const validPassword = await bcrypt.compare(password, user.passwordHash);
    
    if (!validPassword) {
      const newAttempts = (user.failedLoginAttempts || 0) + 1;
      const updates = { 
        failedLoginAttempts: newAttempts,
        updatedAt: new Date()
      };
      
      if (newAttempts >= MAX_FAILED_ATTEMPTS) {
        updates.status = 'locked';
        updates.lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
      }
      
      await db.update(joltUsers).set(updates).where(eq(joltUsers.id, user.id));
      
      const remaining = MAX_FAILED_ATTEMPTS - newAttempts;
      if (remaining > 0) {
        throw new Error(`Invalid credentials. ${remaining} attempts remaining.`);
      } else {
        throw new Error(`Account locked for ${LOCKOUT_MINUTES} minutes due to too many failed attempts.`);
      }
    }
    
    await db.update(joltUsers).set({
      failedLoginAttempts: 0,
      status: 'active',
      lockedUntil: null,
      lastLoginAt: new Date(),
      updatedAt: new Date()
    }).where(eq(joltUsers.id, user.id));
    
    const token = generateSessionToken();
    const tokenHash = hashToken(token);
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + SESSION_EXPIRY_HOURS * 60 * 60 * 1000);
    
    await db.insert(authSessions).values({
      sessionId,
      userId: user.id,
      tokenHash,
      deviceFingerprint: deviceInfo.fingerprint,
      userAgent: deviceInfo.userAgent,
      ipAddress: deviceInfo.ipAddress,
      expiresAt,
      lastActivityAt: new Date()
    });
    
    const assignments = await db.select()
      .from(userSiteAssignments)
      .where(and(
        eq(userSiteAssignments.userId, user.id),
        isNull(userSiteAssignments.revokedAt)
      ));
    
    return {
      token,
      sessionId,
      expiresAt,
      user: {
        id: user.id,
        employeeCode: user.employeeCode,
        name: user.name,
        email: user.email,
        status: user.status
      },
      siteAssignments: assignments.map(a => ({
        siteId: a.siteId,
        role: a.role
      }))
    };
  },

  async validateSession(token) {
    const tokenHash = hashToken(token);
    
    const [session] = await db.select()
      .from(authSessions)
      .where(and(
        eq(authSessions.tokenHash, tokenHash),
        gt(authSessions.expiresAt, new Date())
      ))
      .limit(1);
    
    if (!session) {
      return null;
    }
    
    const [user] = await db.select()
      .from(joltUsers)
      .where(eq(joltUsers.id, session.userId))
      .limit(1);
    
    if (!user || user.status !== 'active') {
      return null;
    }
    
    await db.update(authSessions)
      .set({ lastActivityAt: new Date() })
      .where(eq(authSessions.id, session.id));
    
    const assignments = await db.select()
      .from(userSiteAssignments)
      .where(and(
        eq(userSiteAssignments.userId, user.id),
        isNull(userSiteAssignments.revokedAt)
      ));
    
    return {
      user: {
        id: user.id,
        employeeCode: user.employeeCode,
        name: user.name,
        email: user.email,
        status: user.status
      },
      sessionId: session.sessionId,
      siteAssignments: assignments.map(a => ({
        siteId: a.siteId,
        role: a.role
      }))
    };
  },

  async logout(token) {
    const tokenHash = hashToken(token);
    await db.delete(authSessions).where(eq(authSessions.tokenHash, tokenHash));
  },

  async revokeUser(employeeCode, revokedByUserId, reason) {
    const [user] = await db.update(joltUsers)
      .set({
        status: 'revoked',
        revokedBy: revokedByUserId?.toString(),
        revokedAt: new Date(),
        revokeReason: reason,
        updatedAt: new Date()
      })
      .where(eq(joltUsers.employeeCode, employeeCode))
      .returning();
    
    if (!user) {
      throw new Error('User not found');
    }
    
    await db.delete(authSessions).where(eq(authSessions.userId, user.id));
    
    return user;
  },

  async assignUserToSite(userId, siteId, role, assignedByUserId) {
    const validRoles = ['technician', 'partner', 'driver', 'ops_admin', 'building_manager'];
    if (!validRoles.includes(role)) {
      throw new Error(`Invalid role. Must be one of: ${validRoles.join(', ')}`);
    }
    
    const existing = await db.select()
      .from(userSiteAssignments)
      .where(and(
        eq(userSiteAssignments.userId, userId),
        eq(userSiteAssignments.siteId, siteId),
        isNull(userSiteAssignments.revokedAt)
      ))
      .limit(1);
    
    if (existing.length > 0) {
      const [updated] = await db.update(userSiteAssignments)
        .set({ role, assignedBy: assignedByUserId, assignedAt: new Date() })
        .where(eq(userSiteAssignments.id, existing[0].id))
        .returning();
      return updated;
    }
    
    const [assignment] = await db.insert(userSiteAssignments).values({
      userId,
      siteId,
      role,
      assignedBy: assignedByUserId,
      assignedAt: new Date()
    }).returning();
    
    return assignment;
  },

  async revokeUserFromSite(userId, siteId, revokedByUserId) {
    const [assignment] = await db.update(userSiteAssignments)
      .set({
        revokedAt: new Date(),
        revokedBy: revokedByUserId
      })
      .where(and(
        eq(userSiteAssignments.userId, userId),
        eq(userSiteAssignments.siteId, siteId),
        isNull(userSiteAssignments.revokedAt)
      ))
      .returning();
    
    return assignment;
  },

  async getUserById(userId) {
    const [user] = await db.select()
      .from(joltUsers)
      .where(eq(joltUsers.id, userId))
      .limit(1);
    
    if (!user) return null;
    
    const assignments = await db.select()
      .from(userSiteAssignments)
      .where(and(
        eq(userSiteAssignments.userId, userId),
        isNull(userSiteAssignments.revokedAt)
      ));
    
    return {
      ...user,
      siteAssignments: assignments
    };
  },

  async getAllUsers() {
    const allUsers = await db.select().from(joltUsers).orderBy(joltUsers.name);
    return allUsers;
  },

  async getUsersBySite(siteId) {
    const assignments = await db.select()
      .from(userSiteAssignments)
      .where(and(
        eq(userSiteAssignments.siteId, siteId),
        isNull(userSiteAssignments.revokedAt)
      ));
    
    const userIds = assignments.map(a => a.userId);
    if (userIds.length === 0) return [];
    
    const siteUsers = await db.select()
      .from(joltUsers)
      .where(eq(joltUsers.status, 'active'));
    
    return siteUsers
      .filter(u => userIds.includes(u.id))
      .map(u => ({
        ...u,
        role: assignments.find(a => a.userId === u.id)?.role
      }));
  },

  async checkFirstTimeUser(employeeCode) {
    const [user] = await db.select()
      .from(joltUsers)
      .where(eq(joltUsers.employeeCode, employeeCode))
      .limit(1);
    
    if (!user) {
      return { exists: false };
    }
    
    return {
      exists: true,
      needsPassword: user.status === 'pending_password',
      name: user.name
    };
  },

  async forcePasswordReset(employeeCode, adminUserId) {
    const [user] = await db.update(joltUsers)
      .set({
        status: 'pending_password',
        passwordHash: null,
        passwordSetAt: null,
        updatedAt: new Date()
      })
      .where(eq(joltUsers.employeeCode, employeeCode))
      .returning();
    
    if (!user) {
      throw new Error('User not found');
    }
    
    await db.delete(authSessions).where(eq(authSessions.userId, user.id));
    
    return { success: true, message: 'Password reset required. All sessions invalidated.' };
  },

  async invalidateAllUserSessions(userId) {
    const result = await db.delete(authSessions).where(eq(authSessions.userId, userId));
    return { success: true, message: 'All sessions invalidated' };
  },

  async invalidateSession(sessionId) {
    await db.delete(authSessions).where(eq(authSessions.sessionId, sessionId));
    return { success: true };
  },

  async getActiveSessions(userId) {
    const sessions = await db.select({
      sessionId: authSessions.sessionId,
      deviceFingerprint: authSessions.deviceFingerprint,
      userAgent: authSessions.userAgent,
      ipAddress: authSessions.ipAddress,
      lastActivityAt: authSessions.lastActivityAt,
      createdAt: authSessions.createdAt,
      expiresAt: authSessions.expiresAt
    })
      .from(authSessions)
      .where(and(
        eq(authSessions.userId, userId),
        gt(authSessions.expiresAt, new Date())
      ));
    
    return sessions;
  },

  async reactivateUser(employeeCode, adminUserId) {
    const [user] = await db.update(joltUsers)
      .set({
        status: 'pending_password',
        revokedAt: null,
        revokedBy: null,
        revokeReason: null,
        failedLoginAttempts: 0,
        lockedUntil: null,
        updatedAt: new Date()
      })
      .where(eq(joltUsers.employeeCode, employeeCode))
      .returning();
    
    if (!user) {
      throw new Error('User not found');
    }
    
    return user;
  },

  async unlockUser(employeeCode) {
    const [user] = await db.update(joltUsers)
      .set({
        status: 'active',
        failedLoginAttempts: 0,
        lockedUntil: null,
        updatedAt: new Date()
      })
      .where(eq(joltUsers.employeeCode, employeeCode))
      .returning();
    
    if (!user) {
      throw new Error('User not found');
    }
    
    return user;
  }
};
