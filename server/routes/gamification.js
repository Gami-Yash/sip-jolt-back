/**
 * SIPJOLT v1.01 GATE5 OS GAMIFICATION API
 * Routes: Lucky Spin, Leaderboard, Vacation Jackpot, Free Coffee
 */

import express from 'express';
import { pool } from '../../shared/db.js';
import { requireHeaderAuth, requireSelfOrRole } from '../middleware/headerAuth.js';

const router = express.Router();

const requireGamificationUser = requireHeaderAuth([
  'technician',
  'partner',
  'ops_manager',
  'ops_admin'
]);
const requireOpsRole = requireHeaderAuth(['ops_manager', 'ops_admin']);

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

// ============================================
// LUCKY SPIN ENDPOINTS
// ============================================

router.get(
  '/lucky-spin/available/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Auto-create user with 3 welcome spins if they don't exist
    await query(`
      INSERT INTO lucky_spins (partner_id, balance, points_balance, total_points_earned, lifetime_earned, last_spin_at)
      VALUES ($1, 3, 0, 0, 3, NULL)
      ON CONFLICT (partner_id) DO NOTHING
    `, [userId]);
    
    const result = await query(`
      SELECT 
        COALESCE(balance, 0) AS spins_available,
        COALESCE(lifetime_earned, 0) AS lucky_spins_earned,
        0 AS lucky_spins_used,
        COALESCE(total_points_earned, 0) AS points_lifetime
      FROM lucky_spins
      WHERE partner_id = $1
    `, [userId]);
    
    if (result.rows.length === 0) {
      return res.json({ spins_available: 3, lucky_spins_earned: 3, lucky_spins_used: 0, points_lifetime: 0 });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error checking spin availability:', error);
    res.json({ spins_available: 0, lucky_spins_earned: 0, lucky_spins_used: 0, points_lifetime: 0 });
  }
  }
);

router.post(
  '/lucky-spin/spin',
  requireGamificationUser,
  requireSelfOrRole((req) => req.body?.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { userId } = req.body;
    const resolvedUserId = userId || req.user?.id;

    if (!resolvedUserId) {
      return res.status(400).json({ error: 'User ID required' });
    }
    
    await client.query('BEGIN');
    
    // Auto-create user record with welcome spins if they don't exist
    const spinCheck = await client.query(`
      INSERT INTO lucky_spins (partner_id, balance, points_balance, total_points_earned, last_spin_at)
      VALUES ($1, 3, 0, 0, NULL)
      ON CONFLICT (partner_id) DO NOTHING
    `, [resolvedUserId]);
    
    // Now fetch the user's spin balance
    const userSpins = await client.query(`
      SELECT balance AS spins_available
      FROM lucky_spins
      WHERE partner_id = $1
      FOR UPDATE
    `, [resolvedUserId]);
    
    if (userSpins.rows.length === 0 || userSpins.rows[0].spins_available <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No spins available' });
    }
    
    // v1.01 PRIZE STRUCTURE - Authoritative server model
    // Wheel has 18 segments. "Try Again" appears at indices: 0, 3, 5, 7, 10, 13, 15
    // Weights: ~51.7% Try Again, ~45% Points, ~3% Cash, ~0.3% Gold
    const TRY_AGAIN_SEGMENTS = [0, 3, 5, 7, 10, 13, 15];
    
    const prizes = [
      { tier: 'COMMON', name: 'Better Luck', description: 'Spin again tomorrow!', icon: null, value: 0, weight: 517, type: 'VIRTUAL', getSegment: () => TRY_AGAIN_SEGMENTS[Math.floor(Math.random() * TRY_AGAIN_SEGMENTS.length)] },
      { tier: 'COMMON', name: '+25 Points', description: 'Small point boost', icon: '⭐', value: 0, weight: 225, type: 'VIRTUAL', getSegment: () => 1 },
      { tier: 'COMMON', name: '+50 Points', description: 'Point boost', icon: '⭐', value: 0, weight: 150, type: 'VIRTUAL', getSegment: () => 8 },
      { tier: 'COMMON', name: '+100 Points', description: 'Big point boost', icon: '🌟', value: 0, weight: 75, type: 'VIRTUAL', getSegment: () => 16 },
      { tier: 'RARE', name: '$5 Cash', description: 'Cash bonus on next paycheck', icon: '💵', value: 5, weight: 12, type: 'CASH', getSegment: () => 4 },
      { tier: 'RARE', name: '$10 Cash', description: 'Cash bonus on next paycheck', icon: '💵', value: 10, weight: 8, type: 'CASH', getSegment: () => 11 },
      { tier: 'EPIC', name: '$25 Cash', description: 'Cash bonus on next paycheck', icon: '💸', value: 25, weight: 5, type: 'CASH', getSegment: () => 6 },
      { tier: 'EPIC', name: '$50 Cash', description: 'Cash bonus on next paycheck', icon: '💰', value: 50, weight: 5, type: 'CASH', getSegment: () => 12 },
      { tier: 'LEGENDARY', name: 'Bluetooth Speaker', description: 'Portable wireless speaker ($80)', icon: '🔊', value: 80, weight: 0.75, type: 'ELECTRONICS', getSegment: () => 2 },
      { tier: 'LEGENDARY', name: 'Kindle', description: 'Kindle Paperwhite ($100)', icon: '📖', value: 100, weight: 0.75, type: 'ELECTRONICS', getSegment: () => 9 },
      { tier: 'LEGENDARY', name: 'AirPods', description: 'Apple AirPods 3rd Gen ($120)', icon: '🎧', value: 120, weight: 0.75, type: 'ELECTRONICS', getSegment: () => 14 },
      { tier: 'LEGENDARY', name: '55" Smart TV', description: '55-inch Smart TV ($200)', icon: '📺', value: 200, weight: 0.75, type: 'ELECTRONICS', getSegment: () => 17 },
    ];
    
    const totalWeight = prizes.reduce((sum, p) => sum + p.weight, 0);
    let randomValue = Math.random() * totalWeight;
    let selectedPrize = null;
    
    for (const prize of prizes) {
      randomValue -= prize.weight;
      if (randomValue <= 0) {
        selectedPrize = prize;
        break;
      }
    }
    
    if (!selectedPrize) {
      selectedPrize = prizes[0];
    }
    
    // Get the wheel segment index for animation
    const wheelSegmentIndex = selectedPrize.getSegment();
    
    await client.query(`
      UPDATE lucky_spins
      SET balance = balance - 1,
          last_spin_at = NOW()
      WHERE partner_id = $1
    `, [resolvedUserId]);

    let message = 'Spin successful!';
    
    // Award prize
    if (selectedPrize.type === 'VIRTUAL' && selectedPrize.name.includes('Points')) {
      const pointsMatch = selectedPrize.name.match(/\d+/);
      const points = pointsMatch ? parseInt(pointsMatch[0]) : 0;
      
      const pointUpdate = await client.query(`
        UPDATE lucky_spins 
        SET points_balance = COALESCE(points_balance, 0) + $2,
            total_points_earned = COALESCE(total_points_earned, 0) + $2
        WHERE partner_id = $1
        RETURNING points_balance
      `, [resolvedUserId, points]);

      const newPointsBalance = pointUpdate.rows[0].points_balance;
      if (newPointsBalance >= 500) {
        const spinsToGrant = Math.floor(newPointsBalance / 500);
        const pointsToDeduct = spinsToGrant * 500;
        
        await client.query(`
          UPDATE lucky_spins
          SET points_balance = points_balance - $2,
              balance = balance + $3,
              lifetime_earned = lifetime_earned + $3
          WHERE partner_id = $1
        `, [resolvedUserId, pointsToDeduct, spinsToGrant]);
        
        message = `🌟 Conversion! ${pointsToDeduct} pts -> +${spinsToGrant} Bonus Spin!`;
      }
    } else if (selectedPrize.type === 'CASH' || selectedPrize.type === 'ELECTRONICS') {
      // Logic for logging physical prizes could go here
    }
    
    try {
      await client.query(`
        INSERT INTO v1.00_spin_history (partner_id, prize_tier, prize_name, prize_value, trigger_event)
        VALUES ($1, $2, $3, $4, 'MANUAL_SPIN')
      `, [resolvedUserId, selectedPrize.tier, selectedPrize.name, selectedPrize.value]);
    } catch (e) {
      console.log('Spin history table may not exist yet');
    }
    
    await client.query('COMMIT');
    
    res.json({
      success: true,
      message,
      prizeIndex: wheelSegmentIndex,
      totalSegments: 18,
      prize: {
        tier: selectedPrize.tier,
        name: selectedPrize.name,
        description: selectedPrize.description,
        icon: selectedPrize.icon,
        value: selectedPrize.value,
        type: selectedPrize.type
      }
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error executing spin:', error);
    res.status(500).json({ error: 'Failed to execute spin' });
  } finally {
    client.release();
  }
  }
);

router.get(
  '/lucky-spin/history/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 20;
    
    try {
      const result = await query(`
        SELECT 
          id,
          prize_tier,
          prize_name,
          created_at as spin_timestamp,
          false as prize_redeemed
        FROM v1.00_spin_history
        WHERE partner_id = $1
        ORDER BY created_at DESC
        LIMIT $2
      `, [userId, limit]);
      
      res.json(result.rows);
    } catch (e) {
      res.json([]);
    }
  } catch (error) {
    console.error('Error fetching spin history:', error);
    res.json([]);
  }
  }
);

// ============================================
// SPIN GRANT ENDPOINT (for weekly/monthly completions)
// ============================================

router.post('/lucky-spin/grant', requireOpsRole, async (req, res) => {
  const client = await pool.connect();
  try {
    const { partnerId, reason, spins } = req.body;
    
    if (!partnerId || !spins || spins < 1) {
      return res.status(400).json({ error: 'Invalid parameters' });
    }
    
    await client.query('BEGIN');
    
    // Upsert into lucky_spins table
    await client.query(`
      INSERT INTO lucky_spins (partner_id, balance, lifetime_earned, created_at, updated_at)
      VALUES ($1, $2, $2, NOW(), NOW())
      ON CONFLICT (partner_id) 
      DO UPDATE SET 
        balance = lucky_spins.balance + $2,
        lifetime_earned = lucky_spins.lifetime_earned + $2,
        updated_at = NOW()
    `, [partnerId, spins]);
    
    // Log the grant
    try {
      await client.query(`
        INSERT INTO v1.00_spin_history (partner_id, prize_tier, prize_name, prize_value, trigger_event)
        VALUES ($1, 'GRANT', $2, 0, $2)
      `, [partnerId, reason]);
    } catch (e) {
      console.log('Spin history logging skipped');
    }
    
    await client.query('COMMIT');
    
    res.json({ 
      success: true, 
      message: `Granted ${spins} spin(s) for ${reason}`,
      spinsGranted: spins
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error granting spins:', error);
    res.status(500).json({ error: 'Failed to grant spins' });
  } finally {
    client.release();
  }
});

// ============================================
// FREE COFFEE ENDPOINTS
// ============================================

router.get(
  '/free-coffee/available/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    
    const result = await query(`
      SELECT 
        CASE WHEN EXISTS (
          SELECT 1 FROM ops_delivery_records d
          JOIN ops_sites s ON d.site_id = s.site_id
          WHERE s.partner_id = $1
            AND d.status = 'pending'
            AND d.delivered_at < NOW() - INTERVAL '24 hours'
        ) THEN 0 ELSE 1 END as available_coffees
    `, [userId]);
    
    res.json({ available_coffees: parseInt(result.rows[0]?.available_coffees || 0) });
  } catch (error) {
    console.error('Error checking coffee balance:', error);
    res.json({ available_coffees: 0 });
  }
  }
);

router.post(
  '/free-coffee/claim',
  requireGamificationUser,
  requireSelfOrRole((req) => req.body?.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId, siteId } = req.body;
    const resolvedUserId = userId || req.user?.id;

    if (!resolvedUserId) {
      return res.status(400).json({ error: 'User ID required' });
    }
    
    res.json({ 
      success: true, 
      message: 'Coffee claimed successfully',
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });
    
  } catch (error) {
    console.error('Error claiming coffee:', error);
    res.status(500).json({ error: 'Failed to claim coffee' });
  }
  }
);

// ============================================
// LEADERBOARD ENDPOINTS
// ============================================

router.get(
  '/leaderboard/:period',
  requireGamificationUser,
  requireSelfOrRole((req) => req.query.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { period } = req.params;
    const userId = req.query.userId;
    const limit = parseInt(req.query.limit) || 20;
    
    const result = await query(`
      SELECT 
        u.id,
        CONCAT(COALESCE(u.first_name, ''), ' ', COALESCE(u.last_name, '')) as name,
        u.email,
        COALESCE(ls.lifetime_earned, 0) * 50 as total_points,
        COALESCE(ls.lifetime_earned, 0) * 50 as points_earned_today,
        COALESCE(ls.lifetime_earned, 0) * 50 as points_week,
        COALESCE(ls.balance, 0) as acceptances_under_2h,
        0 as speed_acceptances,
        0 as total_speed_acceptances,
        0 as current_streak_days,
        0 as best_streak,
        ROW_NUMBER() OVER (ORDER BY COALESCE(ls.lifetime_earned, 0) DESC) as rank
      FROM users u
      LEFT JOIN lucky_spins ls ON u.id::text = ls.partner_id
      WHERE u.role = 'PARTNER_TECHNICIAN'
      ORDER BY COALESCE(ls.lifetime_earned, 0) DESC
      LIMIT $1
    `, [limit]);
    
    let userRank = null;
    if (userId) {
      const userResult = await query(`
        SELECT 
          u.id,
          CONCAT(COALESCE(u.first_name, ''), ' ', COALESCE(u.last_name, '')) as name,
          u.email,
          COALESCE(ls.lifetime_earned, 0) * 50 as total_points,
          COALESCE(ls.lifetime_earned, 0) * 50 as points_earned_today,
          COALESCE(ls.lifetime_earned, 0) * 50 as points_week,
          COALESCE(ls.balance, 0) as acceptances_under_2h,
          (SELECT COUNT(*) + 1 FROM lucky_spins ls2 WHERE ls2.lifetime_earned > COALESCE(ls.lifetime_earned, 0)) as rank
        FROM users u
        LEFT JOIN lucky_spins ls ON u.id::text = ls.partner_id
        WHERE u.id::text = $1
      `, [userId]);
      
      if (userResult.rows.length > 0) {
        userRank = userResult.rows[0];
      }
    }
    
    res.json({
      period,
      top_performers: result.rows,
      user_rank: userRank
    });
    
  } catch (error) {
    console.error('Error fetching leaderboard:', error);
    res.json({ period: req.params.period, top_performers: [], user_rank: null });
  }
  }
);

// ============================================
// VACATION JACKPOT ENDPOINTS
// ============================================

router.get('/jackpot/current', requireGamificationUser, async (req, res) => {
  try {
    const totalEntries = await query(`SELECT COALESCE(SUM(lifetime_earned), 0) as total FROM lucky_spins`);
    const participants = await query(`SELECT COUNT(*) as count FROM lucky_spins WHERE lifetime_earned > 0`);
    
    const topContenders = await query(`
      SELECT 
        ls.partner_id as id,
        COALESCE(CONCAT(COALESCE(u.first_name, ''), ' ', COALESCE(u.last_name, '')), 'Technician') as name,
        COALESCE(ls.lifetime_earned, 0) * 2 as vacation_score,
        COALESCE(ls.lifetime_earned, 0) as jackpot_entries,
        ROUND((COALESCE(ls.lifetime_earned, 0)::DECIMAL / NULLIF($1::DECIMAL, 0)) * 100, 2) AS win_probability
      FROM lucky_spins ls
      LEFT JOIN users u ON ls.partner_id = u.id::text
      WHERE ls.lifetime_earned > 0
      ORDER BY ls.lifetime_earned DESC
      LIMIT 10
    `, [totalEntries.rows[0]?.total || 1]);
    
    res.json({
      contest: {
        id: 'current',
        contest_month: new Date().toISOString().slice(0, 7),
        prize_name: 'All-Expenses Paid Vacation',
        prize_value_usd: 2500,
        prize_description: 'Round-trip airfare for 2, 5-night hotel, $500 spending money, 3 paid days off',
        total_entries: parseInt(totalEntries.rows[0]?.total || 0),
        unique_participants: parseInt(participants.rows[0]?.count || 0)
      },
      top_contenders: topContenders.rows
    });
    
  } catch (error) {
    console.error('Error fetching jackpot info:', error);
    res.json({ contest: null, top_contenders: [] });
  }
});

router.get(
  '/jackpot/entries/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    
    const result = await query(`
      SELECT 
        COALESCE(lifetime_earned, 0) as user_entries,
        COALESCE(lifetime_earned, 0) * 2 as vacation_score
      FROM lucky_spins
      WHERE partner_id = $1
    `, [userId]);
    
    const totalEntries = await query(`SELECT COALESCE(SUM(lifetime_earned), 0) as total FROM lucky_spins`);
    
    const userEntries = result.rows[0]?.user_entries || 0;
    const total = parseInt(totalEntries.rows[0]?.total || 1);
    const winProbability = total > 0 ? (userEntries / total) * 100 : 0;
    
    res.json({
      user_entries: userEntries,
      vacation_score: result.rows[0]?.vacation_score || 0,
      win_probability: winProbability
    });
    
  } catch (error) {
    console.error('Error fetching jackpot entries:', error);
    res.json({ user_entries: 0, vacation_score: 0, win_probability: 0 });
  }
  }
);

// ============================================
// METRICS ENDPOINTS
// ============================================

router.get(
  '/metrics/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    
    const spins = await query(`
      SELECT balance, lifetime_earned FROM lucky_spins WHERE partner_id = $1
    `, [userId]);
    
    res.json({
      spins_available: spins.rows[0]?.balance || 0,
      total_spins_earned: spins.rows[0]?.lifetime_earned || 0,
      points_lifetime: (spins.rows[0]?.lifetime_earned || 0) * 50,
      vacation_score: (spins.rows[0]?.lifetime_earned || 0) * 2
    });
    
  } catch (error) {
    console.error('Error fetching metrics:', error);
    res.json({ spins_available: 0, total_spins_earned: 0, points_lifetime: 0 });
  }
  }
);

router.get(
  '/metrics/grade/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    
    const spins = await query(`
      SELECT lifetime_earned FROM lucky_spins WHERE partner_id = $1
    `, [userId]);
    
    const points = (spins.rows[0]?.lifetime_earned || 0) * 50;
    
    let grade = 'D';
    if (points >= 200) grade = 'S';
    else if (points >= 150) grade = 'A';
    else if (points >= 100) grade = 'B';
    else if (points >= 50) grade = 'C';
    
    res.json({ grade, points });
    
  } catch (error) {
    console.error('Error fetching grade:', error);
    res.json({ grade: 'D', points: 0 });
  }
  }
);

// ============================================
// v1.00 SYSTEM METRICS (Ops Manager Dashboard)
// ============================================

router.get('/system/metrics', requireOpsRole, async (req, res) => {
  try {
    // Overall system gamification metrics
    const totalSpins = await query(`SELECT COALESCE(SUM(lifetime_earned), 0) as total FROM lucky_spins`);
    const activeUsers = await query(`SELECT COUNT(*) as count FROM lucky_spins WHERE balance > 0 OR lifetime_earned > 0`);
    
    // Prize payout tracking (from spin history)
    let prizePayouts = { cash: 0, electronics: 0, total_value: 0, spin_count: 0 };
    try {
      const payoutResult = await query(`
        SELECT 
          COUNT(*) as spin_count,
          COALESCE(SUM(CASE WHEN prize_tier IN ('RARE', 'EPIC') THEN prize_value ELSE 0 END), 0) as cash_payout,
          COALESCE(SUM(CASE WHEN prize_tier = 'LEGENDARY' THEN prize_value ELSE 0 END), 0) as electronics_value,
          COALESCE(SUM(prize_value), 0) as total_value
        FROM v1.00_spin_history
        WHERE created_at >= DATE_TRUNC('year', CURRENT_DATE)
      `);
      if (payoutResult.rows[0]) {
        prizePayouts = {
          cash: parseFloat(payoutResult.rows[0].cash_payout) || 0,
          electronics: parseFloat(payoutResult.rows[0].electronics_value) || 0,
          total_value: parseFloat(payoutResult.rows[0].total_value) || 0,
          spin_count: parseInt(payoutResult.rows[0].spin_count) || 0
        };
      }
    } catch (e) {
      console.log('Spin history not available for metrics');
    }
    
    // Calculate average cost per spin
    const avgCostPerSpin = prizePayouts.spin_count > 0 
      ? (prizePayouts.total_value / prizePayouts.spin_count).toFixed(2) 
      : '0.00';
    
    res.json({
      summary: {
        total_spins_all_time: parseInt(totalSpins.rows[0]?.total || 0),
        active_users: parseInt(activeUsers.rows[0]?.count || 0),
        ytd_spins: prizePayouts.spin_count,
        avg_cost_per_spin: parseFloat(avgCostPerSpin)
      },
      payouts_ytd: {
        cash_prizes: prizePayouts.cash,
        electronics_value: prizePayouts.electronics,
        total_prize_value: prizePayouts.total_value
      },
      prize_structure: {
        version: 'v1.00',
        virtual_rate: 0.965,
        cash_rate: 0.03,
        electronics_rate: 0.005,
        target_cost_per_spin: 0.50,
        annual_budget_estimate: 250
      }
    });
    
  } catch (error) {
    console.error('Error fetching system metrics:', error);
    res.status(500).json({ error: 'Failed to fetch system metrics' });
  }
});

// Prize distribution audit endpoint
router.get('/system/prize-audit', requireOpsRole, async (req, res) => {
  try {
    let distribution = [];
    try {
      distribution = (await query(`
        SELECT 
          prize_tier,
          prize_name,
          COUNT(*) as count,
          COALESCE(SUM(prize_value), 0) as total_value,
          ROUND(COUNT(*)::decimal / NULLIF((SELECT COUNT(*) FROM v1.00_spin_history WHERE created_at >= DATE_TRUNC('year', CURRENT_DATE)), 0) * 100, 2) as percentage
        FROM v1.00_spin_history
        WHERE created_at >= DATE_TRUNC('year', CURRENT_DATE)
        GROUP BY prize_tier, prize_name
        ORDER BY count DESC
      `)).rows;
    } catch (e) {
      console.log('Spin history table not available');
    }
    
    res.json({
      year: new Date().getFullYear(),
      distribution,
      expected_rates: {
        'Better Luck Next Time': 40.0,
        '+25 Points': 30.5,
        '+50 Points': 15.0,
        '+100 Points': 11.0,
        '$5 Cash': 1.2,
        '$10 Cash': 0.8,
        '$25 Cash': 0.5,
        '$50 Cash': 0.5,
        'Bluetooth Speaker': 0.2,
        'Kindle': 0.15,
        'AirPods': 0.1,
        '55" Smart TV': 0.05
      }
    });
    
  } catch (error) {
    console.error('Error fetching prize audit:', error);
    res.status(500).json({ error: 'Failed to fetch prize audit' });
  }
});

// ============================================
// PERFECTION STATUS ENDPOINTS (OPS + Technician)
// ============================================

router.get(
  '/perfection/status/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    const currentMonth = new Date();
    currentMonth.setDate(1);
    
    const startOfMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth(), 1);
    const endOfMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth() + 1, 0);
    
    const deliveries = await query(`
      SELECT 
        COUNT(*) FILTER (WHERE d.status = 'accepted') as total_deliveries,
        COUNT(*) FILTER (WHERE d.status = 'accepted' AND d.accepted_at - d.delivered_at < INTERVAL '6 hours') as speed_deliveries
      FROM ops_delivery_records d
      JOIN ops_sites s ON d.site_id = s.site_id
      WHERE s.owner_user_id::text = $1
        AND d.delivered_at >= $2
        AND d.delivered_at < $3
    `, [userId, startOfMonth, endOfMonth]);
    
    const totalDeliveries = parseInt(deliveries.rows[0]?.total_deliveries || 0);
    const speedDeliveries = parseInt(deliveries.rows[0]?.speed_deliveries || 0);
    const speedRate = totalDeliveries > 0 ? (speedDeliveries / totalDeliveries * 100) : 0;
    
    const overdueTasks = await query(`
      SELECT COUNT(*) as count
      FROM ops_delivery_records d
      JOIN ops_sites s ON d.site_id = s.site_id
      WHERE s.owner_user_id::text = $1
        AND d.delivered_at >= $2
        AND d.delivered_at < $3
        AND d.status = 'pending'
        AND d.delivered_at < NOW() - INTERVAL '24 hours'
    `, [userId, startOfMonth, endOfMonth]);
    
    const overdueCount = parseInt(overdueTasks.rows[0]?.count || 0);
    
    const perfectionAchieved = totalDeliveries >= 20 
      && speedRate >= 80.0 
      && overdueCount === 0;
    
    res.json({
      month: currentMonth.toISOString().substring(0, 7),
      perfection_achieved: perfectionAchieved,
      criteria: {
        volume: {
          required: 20,
          actual: totalDeliveries,
          passed: totalDeliveries >= 20
        },
        speed: {
          required: 80.0,
          actual: parseFloat(speedRate.toFixed(1)),
          passed: speedRate >= 80.0
        },
        consistency: {
          required: 0,
          actual: overdueCount,
          passed: overdueCount === 0
        }
      },
      spins_if_achieved: 3
    });
  } catch (error) {
    console.error('Error fetching perfection status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
  }
);

router.get(
  '/perfection/history/:userId',
  requireGamificationUser,
  requireSelfOrRole((req) => req.params.userId, ['ops_manager', 'ops_admin']),
  async (req, res) => {
  try {
    const { userId } = req.params;
    
    res.json({
      history: [],
      total_perfection_months: 0,
      total_spins_from_perfection: 0
    });
  } catch (error) {
    console.error('Error fetching perfection history:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
  }
);

router.get('/ops/perfection-leaderboard', requireOpsRole, async (req, res) => {
  try {
    const currentMonth = new Date();
    currentMonth.setDate(1);
    const startOfMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth(), 1);
    const endOfMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth() + 1, 0);
    
    const technicians = await query(`
      SELECT id, CONCAT(COALESCE(first_name, ''), ' ', COALESCE(last_name, '')) as employee_name
      FROM users
      WHERE role = 'PARTNER_TECHNICIAN'
    `);
    
    const leaderboard = [];
    
    for (const tech of technicians.rows) {
      const deliveries = await query(`
        SELECT 
          COUNT(*) FILTER (WHERE d.status = 'accepted') as total_deliveries,
          COUNT(*) FILTER (WHERE d.status = 'accepted' AND d.accepted_at - d.delivered_at < INTERVAL '6 hours') as speed_deliveries
        FROM ops_delivery_records d
        JOIN ops_sites s ON d.site_id = s.site_id
        WHERE s.owner_user_id::text = $1
          AND d.delivered_at >= $2
          AND d.delivered_at < $3
      `, [tech.id.toString(), startOfMonth, endOfMonth]);
      
      const totalDeliveries = parseInt(deliveries.rows[0]?.total_deliveries || 0);
      const speedDeliveries = parseInt(deliveries.rows[0]?.speed_deliveries || 0);
      const speedRate = totalDeliveries > 0 ? (speedDeliveries / totalDeliveries * 100) : 0;
      
      const perfectionAchieved = totalDeliveries >= 20 && speedRate >= 80.0;
      
      leaderboard.push({
        user_id: tech.id,
        employee_name: tech.employee_name,
        total_deliveries: totalDeliveries,
        speed_rate: speedRate.toFixed(1),
        qc_issues: 0,
        late_refills: 0,
        overdue_24h: 0,
        perfection_achieved: perfectionAchieved
      });
    }
    
    leaderboard.sort((a, b) => {
      if (a.perfection_achieved !== b.perfection_achieved) {
        return b.perfection_achieved - a.perfection_achieved;
      }
      return b.total_deliveries - a.total_deliveries;
    });
    
    const perfectionCount = leaderboard.filter(t => t.perfection_achieved).length;
    const totalTechs = leaderboard.length;
    
    res.json({
      month: currentMonth.toISOString().substring(0, 7),
      leaderboard,
      summary: {
        total_technicians: totalTechs,
        perfection_achieved_count: perfectionCount,
        perfection_rate: totalTechs > 0 ? Math.round(perfectionCount / totalTechs * 100) : 0
      }
    });
  } catch (error) {
    console.error('Error fetching perfection leaderboard:', error);
    res.json({
      month: new Date().toISOString().substring(0, 7),
      leaderboard: [],
      summary: {
        total_technicians: 0,
        perfection_achieved_count: 0,
        perfection_rate: 0
      }
    });
  }
});

export default router;
