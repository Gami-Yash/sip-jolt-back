/**
 * SIPJOLT OS - Sovereign Command Queue
 * Production-ready for Replit (Single-Site Deployment)
 * 
 * COPY TO: /server/services/yile/sovereignQueue.js
 */

import { pool } from '../../../shared/db.js';
import yileApi from './yileApiService.js';
import crypto from 'crypto';

class SovereignCommandQueue {
  constructor() {
    this.SPAM_WINDOW_SECONDS = 30; // Q7: 30-second dedupe
    console.log('[Sovereign] Queue initialized');
  }

  async executeCommand({ deviceId, type, userId, userRole, payload }) {
    try {
      const payloadHash = this.hashPayload(payload);
      const idempotencyKey = `${deviceId}:${type}:${payloadHash}:${userId}`;

      // Check duplicate
      const existingCommand = await this.checkDuplicate(idempotencyKey);
      if (existingCommand) {
        console.log(`[Sovereign] Dedupe: ${existingCommand.command_id}`);
        return {
          commandId: existingCommand.command_id,
          status: existingCommand.status,
          deduplicated: true,
        };
      }

      // Check soft lock
      const lockCheck = await this.checkSoftLock(deviceId, type, userRole);
      if (lockCheck.blocked) {
        return await this.createBlockedCommand({
          deviceId, type, userId, userRole, payload,
          idempotencyKey, blockReason: lockCheck.reason,
        });
      }

      // Check in-flight
      const inFlightCheck = await this.checkInFlight(deviceId);
      if (inFlightCheck.hasInFlight) {
        return {
          commandId: inFlightCheck.commandId,
          status: 'RUNNING',
          message: `Device busy: ${inFlightCheck.type} in progress`,
          blocked: true,
        };
      }

      // Create command
      const commandId = await this.createCommand({
        deviceId, type, userId, userRole, payload, idempotencyKey, payloadHash,
      });

      // Execute
      const result = await this.dispatchCommand(commandId, deviceId, type, payload, userId);

      return {
        commandId,
        status: result.status,
        result: result.data,
      };
    } catch (error) {
      console.error('[Sovereign] Error:', error);
      throw error;
    }
  }

  hashPayload(payload) {
    const serialized = JSON.stringify(payload, Object.keys(payload).sort());
    return crypto.createHash('sha256').update(serialized).digest('hex').substring(0, 16);
  }

  async checkDuplicate(idempotencyKey) {
    const result = await pool.query(`
      SELECT command_id, status
      FROM yile_commands
      WHERE idempotency_key = $1
      AND created_at > NOW() - INTERVAL '30 seconds'
      ORDER BY created_at DESC
      LIMIT 1
    `, [idempotencyKey]);

    return result.rows[0] || null;
  }

  async checkSoftLock(deviceId, commandType, userRole) {
    const result = await pool.query(`
      SELECT soft_lock_state, soft_lock_reason
      FROM yile_devices
      WHERE yile_device_id = $1
    `, [deviceId]);

    if (result.rows.length === 0) {
      return { blocked: true, reason: 'Device not found in system' };
    }

    const device = result.rows[0];

    if (device.soft_lock_state === 'OFFLINE') {
      if (commandType === 'RESTART' || commandType === 'BRING_ONLINE') {
        return { blocked: false };
      }

      // Q6: Test brew offline = OPS OVERRIDE
      if (commandType === 'BREW_TEST') {
        if (userRole === 'OPS_MANAGER') {
          return { blocked: false };
        }
        return { 
          blocked: true, 
          reason: `Device offline: ${device.soft_lock_reason}. Ops override required.` 
        };
      }

      return { 
        blocked: true, 
        reason: `Device offline: ${device.soft_lock_reason}` 
      };
    }

    return { blocked: false };
  }

  async checkInFlight(deviceId) {
    const result = await pool.query(`
      SELECT command_id, type
      FROM yile_commands
      WHERE device_id = $1
      AND status IN ('QUEUED', 'RUNNING')
      ORDER BY created_at DESC
      LIMIT 1
    `, [deviceId]);

    if (result.rows.length > 0) {
      return {
        hasInFlight: true,
        commandId: result.rows[0].command_id,
        type: result.rows[0].type,
      };
    }

    return { hasInFlight: false };
  }

  async createBlockedCommand({ deviceId, type, userId, userRole, payload, idempotencyKey, blockReason }) {
    const result = await pool.query(`
      INSERT INTO yile_commands (
        device_id, type, requested_by_user_id, requested_by_role,
        payload_json, idempotency_key, status, error_message, created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, 'BLOCKED', $7, NOW())
      RETURNING command_id
    `, [deviceId, type, userId, userRole, JSON.stringify(payload), idempotencyKey, blockReason]);

    return {
      commandId: result.rows[0].command_id,
      status: 'BLOCKED',
      message: blockReason,
      blocked: true,
    };
  }

  async createCommand({ deviceId, type, userId, userRole, payload, idempotencyKey, payloadHash }) {
    const result = await pool.query(`
      INSERT INTO yile_commands (
        device_id, type, requested_by_user_id, requested_by_role,
        payload_json, payload_hash, idempotency_key, status, created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'QUEUED', NOW())
      RETURNING command_id
    `, [deviceId, type, userId, userRole, JSON.stringify(payload), payloadHash, idempotencyKey]);

    return result.rows[0].command_id;
  }

  async dispatchCommand(commandId, deviceId, type, payload, userId) {
    try {
      await pool.query(`
        UPDATE yile_commands SET status = 'RUNNING', started_at = NOW()
        WHERE command_id = $1
      `, [commandId]);

      let result;

      switch (type) {
        case 'BREW_TEST':
          result = await this.handleBrewTest(commandId, deviceId, payload);
          break;
        case 'RESTART':
          result = await this.handleRestart(commandId, deviceId);
          break;
        case 'TAKE_OFFLINE':
          result = await this.handleTakeOffline(commandId, deviceId, payload);
          break;
        case 'BRING_ONLINE':
          result = await this.handleBringOnline(commandId, deviceId);
          break;
        default:
          throw new Error(`Unknown command type: ${type}`);
      }

      await pool.query(`
        UPDATE yile_commands 
        SET status = $1, error_message = $2, ended_at = NOW()
        WHERE command_id = $3
      `, [result.status, result.message, commandId]);

      await pool.query(`
        INSERT INTO yile_audit_events (event_type, actor, device_id, metadata_json, created_at)
        VALUES ($1, $2, $3, $4, NOW())
      `, [
        `COMMAND_${result.status}`,
        userId,
        deviceId,
        JSON.stringify({ commandId, type, result }),
      ]);

      return result;
    } catch (error) {
      await pool.query(`
        UPDATE yile_commands 
        SET status = 'FAIL', error_message = $1, ended_at = NOW()
        WHERE command_id = $2
      `, [error.message, commandId]);

      throw error;
    }
  }

  async handleBrewTest(commandId, deviceId, payload) {
    const { recipeName } = payload;

    try {
      const pushId = await yileApi.pushRemoteDrinking(deviceId, recipeName);

      await pool.query(`
        UPDATE yile_commands SET vendor_push_id = $1 WHERE command_id = $2
      `, [pushId, commandId]);

      // Poll for result (2s × 15 = 30s max)
      for (let attempt = 1; attempt <= 15; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 2000));

        const result = await yileApi.queryPushResult(pushId);

        if (result.completed) {
          if (result.success) {
            return {
              status: 'SUCCESS',
              message: 'Brew completed',
              data: { pushId, makeResult: '1' },
            };
          } else {
            return {
              status: 'FAIL',
              message: result.message || 'Brew failed',
              data: { pushId, makeResult: '0' },
            };
          }
        }
      }

      return {
        status: 'NEEDS_REVIEW',
        message: 'Brew timeout - check machine',
        data: { pushId, timeout: true },
      };
    } catch (error) {
      return {
        status: 'FAIL',
        message: error.message,
        data: { error: error.message },
      };
    }
  }

  async handleRestart(commandId, deviceId) {
    try {
      // Q4: Block when busy
      const status = await yileApi.getCachedStatus(deviceId);
      
      if (status && status.work_status !== 0) {
        return {
          status: 'BLOCKED',
          message: 'Cannot restart: Machine is busy',
          data: { workStatus: status.work_status },
        };
      }

      await yileApi.pushRestartMachine(deviceId);

      return {
        status: 'SUCCESS',
        message: 'Restart initiated',
        data: {},
      };
    } catch (error) {
      return {
        status: 'FAIL',
        message: error.message,
        data: { error: error.message },
      };
    }
  }

  async handleTakeOffline(commandId, deviceId, payload) {
    const { reason } = payload;

    try {
      await pool.query(`
        UPDATE yile_devices 
        SET soft_lock_state = 'OFFLINE', 
            soft_lock_reason = $1,
            soft_lock_at = NOW()
        WHERE yile_device_id = $2
      `, [reason, deviceId]);

      return {
        status: 'SUCCESS',
        message: `Device offline: ${reason}`,
        data: { softLockState: 'OFFLINE', reason },
      };
    } catch (error) {
      return {
        status: 'FAIL',
        message: error.message,
        data: { error: error.message },
      };
    }
  }

  async handleBringOnline(commandId, deviceId) {
    try {
      await pool.query(`
        UPDATE yile_devices 
        SET soft_lock_state = 'ACTIVE', 
            soft_lock_reason = NULL,
            soft_lock_at = NULL
        WHERE yile_device_id = $1
      `, [deviceId]);

      return {
        status: 'SUCCESS',
        message: 'Device online',
        data: { softLockState: 'ACTIVE' },
      };
    } catch (error) {
      return {
        status: 'FAIL',
        message: error.message,
        data: { error: error.message },
      };
    }
  }

  async getCommandStatus(commandId) {
    const result = await pool.query(`
      SELECT * FROM yile_commands WHERE command_id = $1
    `, [commandId]);

    return result.rows[0] || null;
  }

  async getRecentCommands(deviceId, limit = 10) {
    const result = await pool.query(`
      SELECT * FROM yile_commands
      WHERE device_id = $1
      ORDER BY created_at DESC
      LIMIT $2
    `, [deviceId, limit]);

    return result.rows;
  }
}

export default new SovereignCommandQueue();
