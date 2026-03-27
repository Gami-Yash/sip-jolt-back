import { getPool } from './db.js';
import { consequenceEngineService, CONSEQUENCE_EVENT_TYPES } from './consequence-engine.js';

const generateId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

export const A50_TEST_STEPS = [
  {
    id: 'prepare',
    title: 'Prepare the Machine',
    instruction: 'Ensure the machine is powered on and in standby mode. Remove any cups from the dispenser area.',
    duration_sec: 15,
    requires_photo: false
  },
  {
    id: 'squeeze_test',
    title: 'Perform Squeeze Test',
    instruction: 'Firmly squeeze the A50 component for 3 seconds, then release. Observe if it returns to original position within 2 seconds.',
    duration_sec: 30,
    requires_photo: true,
    photo_label: 'Photo: A50 Component During Test'
  },
  {
    id: 'visual_check',
    title: 'Visual Inspection',
    instruction: 'Check for any visible cracks, discoloration, or deformation on the A50 component.',
    duration_sec: 20,
    requires_photo: true,
    photo_label: 'Photo: A50 Component Close-up'
  },
  {
    id: 'result',
    title: 'Record Result',
    instruction: 'Based on your observations, did the A50 component pass all checks?',
    duration_sec: 10,
    requires_decision: true,
    decision_options: ['PASS', 'FAIL']
  }
];

export const a50SqueezeGateService = {
  TEST_TIMER_SECONDS: 60,
  
  async startTest(machineId, testerId) {
    const pool = getPool();
    const sessionId = generateId('A50S');
    
    await pool.query(`
      INSERT INTO a50_test_sessions (
        session_id, machine_id, tester_id, status, started_at,
        current_step, steps_completed
      ) VALUES ($1, $2, $3, $4, NOW(), $5, $6)
    `, [sessionId, machineId, testerId, 'in_progress', 0, JSON.stringify([])]);

    return {
      sessionId,
      machineId,
      testerId,
      steps: A50_TEST_STEPS,
      totalSteps: A50_TEST_STEPS.length,
      timerSeconds: this.TEST_TIMER_SECONDS
    };
  },

  async recordStepCompletion(sessionId, stepId, data) {
    const pool = getPool();
    
    const session = await pool.query(
      `SELECT * FROM a50_test_sessions WHERE session_id = $1`,
      [sessionId]
    );
    
    if (!session.rows[0]) {
      throw new Error('Test session not found');
    }
    
    if (session.rows[0].status !== 'in_progress') {
      throw new Error('Test session is not in progress');
    }

    const stepsCompleted = session.rows[0].steps_completed || [];
    const stepIndex = A50_TEST_STEPS.findIndex(s => s.id === stepId);
    
    if (stepIndex === -1) {
      throw new Error('Invalid step ID');
    }

    stepsCompleted.push({
      step_id: stepId,
      completed_at: new Date().toISOString(),
      photo_url: data.photo_url || null,
      decision: data.decision || null,
      notes: data.notes || null
    });

    const isComplete = stepsCompleted.length >= A50_TEST_STEPS.length;
    const newCurrentStep = Math.min(stepIndex + 1, A50_TEST_STEPS.length - 1);

    await pool.query(`
      UPDATE a50_test_sessions SET
        current_step = $2,
        steps_completed = $3,
        status = $4,
        completed_at = $5
      WHERE session_id = $1
    `, [
      sessionId,
      newCurrentStep,
      JSON.stringify(stepsCompleted),
      isComplete ? 'completed' : 'in_progress',
      isComplete ? new Date() : null
    ]);

    return {
      sessionId,
      stepId,
      isComplete,
      stepsCompleted: stepsCompleted.length,
      totalSteps: A50_TEST_STEPS.length
    };
  },

  async submitTestResult(sessionId, passed, proofUrls) {
    const pool = getPool();
    
    const session = await pool.query(
      `SELECT * FROM a50_test_sessions WHERE session_id = $1`,
      [sessionId]
    );
    
    if (!session.rows[0]) {
      throw new Error('Test session not found');
    }

    const { machine_id, tester_id, steps_completed } = session.rows[0];

    if (!Array.isArray(steps_completed) || steps_completed.length < A50_TEST_STEPS.filter(s => s.requires_photo || s.requires_decision).length) {
      throw new Error('All required steps must be completed before submission');
    }

    await pool.query(`
      UPDATE a50_test_sessions SET
        status = 'submitted',
        final_result = $2,
        proof_urls = $3,
        submitted_at = NOW()
      WHERE session_id = $1
    `, [sessionId, passed ? 'PASS' : 'FAIL', JSON.stringify(proofUrls)]);

    const testId = await consequenceEngineService.recordA50Test(
      machine_id,
      tester_id,
      passed,
      proofUrls[0] || null,
      {
        session_id: sessionId,
        timer_duration: this.TEST_TIMER_SECONDS,
        steps_completed: steps_completed.length,
        all_proof_urls: proofUrls
      }
    );

    return {
      testId,
      sessionId,
      machineId: machine_id,
      result: passed ? 'PASS' : 'FAIL',
      safeModeTriggered: !passed ? await consequenceEngineService.isMachineInSafeMode(machine_id) : false
    };
  },

  async getTestHistory(machineId, limit = 10) {
    const pool = getPool();
    
    const result = await pool.query(`
      SELECT 
        s.session_id, s.tester_id, s.status, s.final_result,
        s.started_at, s.completed_at, s.submitted_at,
        r.passed, r.proof_url
      FROM a50_test_sessions s
      LEFT JOIN a50_test_results r ON r.test_id = (
        SELECT test_id FROM a50_test_results 
        WHERE machine_id = s.machine_id 
        ORDER BY tested_at DESC LIMIT 1
      )
      WHERE s.machine_id = $1
      ORDER BY s.started_at DESC
      LIMIT $2
    `, [machineId, limit]);

    return result.rows;
  },

  async getMachineTestStatus(machineId) {
    const pool = getPool();
    
    const machine = await pool.query(`
      SELECT 
        machine_id, safe_mode, safe_mode_entered_at, safe_mode_exit_date
      FROM machines WHERE machine_id = $1
    `, [machineId]);

    if (!machine.rows[0]) {
      return null;
    }

    const lastTest = await pool.query(`
      SELECT * FROM a50_test_results
      WHERE machine_id = $1
      ORDER BY tested_at DESC
      LIMIT 1
    `, [machineId]);

    const recentTests = await pool.query(`
      SELECT passed FROM a50_test_results
      WHERE machine_id = $1
      ORDER BY tested_at DESC
      LIMIT 5
    `, [machineId]);

    const passRate = recentTests.rows.length > 0
      ? Math.round(recentTests.rows.filter(r => r.passed).length / recentTests.rows.length * 100)
      : null;

    return {
      machineId,
      safeMode: machine.rows[0].safe_mode || false,
      safeModeEnteredAt: machine.rows[0].safe_mode_entered_at,
      safeModeExitDate: machine.rows[0].safe_mode_exit_date,
      lastTest: lastTest.rows[0] || null,
      recentPassRate: passRate,
      consecutiveFails: this.countConsecutiveFails(recentTests.rows)
    };
  },

  countConsecutiveFails(tests) {
    let count = 0;
    for (const test of tests) {
      if (!test.passed) count++;
      else break;
    }
    return count;
  }
};

export default a50SqueezeGateService;
