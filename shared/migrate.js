import { getPool } from './db.js';

const runMigration = async () => {
  console.log('🚀 Starting database migration...');

  let client = null;
  try {
    const pool = getPool();
    client = await pool.connect();
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS machines (
        id SERIAL PRIMARY KEY,
        machine_id TEXT UNIQUE NOT NULL,
        nickname TEXT NOT NULL,
        location TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        last_visit_date TIMESTAMP,
        last_visit_tech_id TEXT,
        next_weekly_due TIMESTAMP,
        cups_served_today INTEGER DEFAULT 0,
        active_errors JSONB DEFAULT '[]',
        inventory JSONB DEFAULT '{"beans": 100, "oat": 100, "vanilla": 100, "mocha": 100, "cups": 500}',
        notes JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS technicians (
        id SERIAL PRIMARY KEY,
        technician_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        xp INTEGER DEFAULT 0,
        streak INTEGER DEFAULT 0,
        on_time_rate INTEGER DEFAULT 100,
        badges JSONB DEFAULT '[]',
        total_visits INTEGER DEFAULT 0,
        weekly_visits INTEGER DEFAULT 0,
        monthly_visits INTEGER DEFAULT 0,
        login_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS visits (
        id SERIAL PRIMARY KEY,
        technician_id TEXT NOT NULL,
        machine_id TEXT NOT NULL,
        visit_type TEXT NOT NULL,
        completed_questions JSONB DEFAULT '{}',
        photos JSONB DEFAULT '{}',
        problems JSONB DEFAULT '{}',
        option_selections JSONB DEFAULT '{}',
        text_inputs JSONB DEFAULT '{}',
        duration_minutes INTEGER,
        synced_to_machine_app BOOLEAN DEFAULT FALSE,
        synced_at TIMESTAMP,
        synced_by TEXT,
        completed_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS prizes (
        id SERIAL PRIMARY KEY,
        technician_id TEXT NOT NULL,
        prize_type TEXT NOT NULL,
        prize_name TEXT NOT NULL,
        prize_value INTEGER,
        visit_type TEXT NOT NULL,
        notify_ops BOOLEAN DEFAULT FALSE,
        claimed BOOLEAN DEFAULT FALSE,
        claimed_at TIMESTAMP,
        won_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ai_chat_logs (
        id SERIAL PRIMARY KEY,
        technician_id TEXT NOT NULL,
        machine_id TEXT,
        question TEXT NOT NULL,
        response TEXT NOT NULL,
        has_image BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS photo_audits (
        id SERIAL PRIMARY KEY,
        technician_id TEXT NOT NULL,
        machine_id TEXT NOT NULL,
        visit_id INTEGER,
        question_id TEXT NOT NULL,
        photo_data TEXT NOT NULL,
        approved BOOLEAN,
        approved_by TEXT,
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS notification_preferences (
        id SERIAL PRIMARY KEY,
        technician_id TEXT UNIQUE NOT NULL,
        enabled_notifications BOOLEAN DEFAULT TRUE,
        visit_reminders BOOLEAN DEFAULT TRUE,
        prize_alerts BOOLEAN DEFAULT TRUE,
        machine_alerts BOOLEAN DEFAULT TRUE,
        maintenance_reminders BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        technician_id TEXT NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        icon TEXT,
        data JSONB DEFAULT '{}',
        read BOOLEAN DEFAULT FALSE,
        read_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS instructional_videos (
        id SERIAL PRIMARY KEY,
        step_id TEXT UNIQUE NOT NULL,
        wizard_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        video_url TEXT,
        object_path TEXT,
        file_size INTEGER,
        duration_seconds INTEGER,
        uploaded_by TEXT,
        uploaded_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // =====================================================
    // SUPPLY CLOSET OPS MODULE TABLES
    // =====================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_users (
        id SERIAL PRIMARY KEY,
        user_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        role TEXT NOT NULL DEFAULT 'partner',
        assigned_sites JSONB DEFAULT '[]',
        is_active BOOLEAN DEFAULT TRUE,
        last_login_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_sites (
        id SERIAL PRIMARY KEY,
        site_id TEXT UNIQUE NOT NULL,
        venue_name TEXT NOT NULL,
        address TEXT NOT NULL,
        primary_contact_name TEXT,
        primary_contact_phone TEXT,
        backup_contact_name TEXT,
        backup_contact_phone TEXT,
        closet_location TEXT,
        access_instructions TEXT,
        status TEXT NOT NULL DEFAULT 'pending_setup',
        day1_completed_at TIMESTAMP,
        day1_completed_by TEXT,
        golden_photos JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_site_configs (
        id SERIAL PRIMARY KEY,
        site_id TEXT UNIQUE NOT NULL,
        weekly_due_day TEXT NOT NULL DEFAULT 'tuesday',
        weekly_due_hour INTEGER DEFAULT 17,
        overdue_threshold_hours INTEGER DEFAULT 48,
        acceptance_window_hours INTEGER DEFAULT 24,
        skip_next_cups_drop BOOLEAN DEFAULT FALSE,
        skip_cups_reason TEXT,
        skip_cups_expires_at TIMESTAMP,
        cups_drop_hold_active BOOLEAN DEFAULT FALSE,
        cups_drop_hold_reason TEXT,
        a50_fallback_active BOOLEAN DEFAULT FALSE,
        a50_activated_at TIMESTAMP,
        consecutive_soft_reports INTEGER DEFAULT 0,
        consecutive_bricked_reports INTEGER DEFAULT 0,
        zones_labeled JSONB DEFAULT '{"A": false, "B1": false, "B2": false, "CD": false, "E": false}',
        thresholds JSONB DEFAULT '{"A": {"min": 1, "max": 4}, "B1": {"min": 1, "max": 2}, "B2": {"min": 1, "max": 2}, "CD": {"min": 1, "max": 2}, "E": {"min": 50, "max": 200}}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    try {
      await client.query(`ALTER TABLE ops_site_configs ADD COLUMN IF NOT EXISTS acceptance_window_hours INTEGER DEFAULT 24;`);
    } catch (e) { }

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_box_configs (
        id SERIAL PRIMARY KEY,
        site_id TEXT NOT NULL,
        box_id TEXT NOT NULL,
        descriptor TEXT NOT NULL,
        is_enabled BOOLEAN DEFAULT TRUE,
        is_split BOOLEAN DEFAULT FALSE,
        split_count INTEGER DEFAULT 1,
        contents JSONB DEFAULT '[]',
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_weekly_tasks (
        id SERIAL PRIMARY KEY,
        task_id TEXT UNIQUE NOT NULL,
        site_id TEXT NOT NULL,
        task_type TEXT DEFAULT 'weekly',
        title TEXT,
        week_start DATE,
        due_date TIMESTAMP NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        assigned_to TEXT,
        linked_incident_id TEXT,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        completed_by TEXT,
        alert_created_at TIMESTAMP,
        emergency_task_created_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    try {
      await client.query(`ALTER TABLE ops_weekly_tasks ADD COLUMN IF NOT EXISTS task_type TEXT DEFAULT 'weekly';`);
      await client.query(`ALTER TABLE ops_weekly_tasks ADD COLUMN IF NOT EXISTS title TEXT;`);
      await client.query(`ALTER TABLE ops_weekly_tasks ADD COLUMN IF NOT EXISTS week_start DATE;`);
      await client.query(`ALTER TABLE ops_weekly_tasks ADD COLUMN IF NOT EXISTS linked_incident_id TEXT;`);
    } catch (e) { console.log('ops_weekly_tasks columns note:', e.message); }

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_weekly_submissions (
        id SERIAL PRIMARY KEY,
        submission_id TEXT UNIQUE NOT NULL,
        task_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        submitted_by TEXT NOT NULL,
        before_photo TEXT NOT NULL,
        after_photo TEXT NOT NULL,
        close_up_photos JSONB DEFAULT '[]',
        checklist JSONB DEFAULT '{"refillCompleted": false, "cleaningCompleted": false, "noLeaksVisible": false}',
        matcha_condition TEXT NOT NULL,
        issue_flags JSONB DEFAULT '{"lowStock": false, "lowStockZones": [], "leakWetBox": false, "messyCloset": false, "accessIssue": false}',
        issue_notes TEXT,
        submitted_at TIMESTAMP DEFAULT NOW(),
        reviewed_by TEXT,
        reviewed_at TIMESTAMP,
        review_notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_shipments (
        id SERIAL PRIMARY KEY,
        shipment_id TEXT UNIQUE NOT NULL,
        site_id TEXT NOT NULL,
        shipment_type TEXT NOT NULL,
        carrier_type TEXT NOT NULL DEFAULT 'milk_run',
        tracking_number TEXT,
        status TEXT NOT NULL DEFAULT 'created',
        total_boxes INTEGER DEFAULT 0,
        expected_delivery_date TIMESTAMP,
        created_by TEXT NOT NULL,
        packed_at TIMESTAMP,
        packed_by TEXT,
        shipped_at TIMESTAMP,
        shipped_by TEXT,
        delivered_at TIMESTAMP,
        refused_at TIMESTAMP,
        refusal_reason TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_shipment_boxes (
        id SERIAL PRIMARY KEY,
        box_record_id TEXT UNIQUE NOT NULL,
        shipment_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        box_id TEXT NOT NULL,
        descriptor TEXT NOT NULL,
        box_number INTEGER NOT NULL,
        total_in_set INTEGER NOT NULL,
        batch_id TEXT,
        pack_date TIMESTAMP,
        weight DECIMAL(6, 2),
        is_heavy BOOLEAN DEFAULT FALSE,
        has_liquids BOOLEAN DEFAULT FALSE,
        has_inner_kits BOOLEAN DEFAULT FALSE,
        packing_log JSONB DEFAULT '{"shakeTestPass": false, "voidFillUsed": false, "zeroRattle": false, "packerInitials": "", "packerNotes": ""}',
        label_generated_at TIMESTAMP,
        label_type TEXT,
        qr_payload TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_delivery_records (
        id SERIAL PRIMARY KEY,
        delivery_id TEXT UNIQUE NOT NULL,
        shipment_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        driver_id TEXT NOT NULL,
        driver_name TEXT,
        route_id TEXT,
        carrier_type TEXT NOT NULL,
        tracking_number TEXT,
        placement_photos JSONB DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'pending',
        access_denied BOOLEAN DEFAULT FALSE,
        access_denied_photo TEXT,
        access_denied_notes TEXT,
        site_fail_flag BOOLEAN DEFAULT FALSE,
        site_fail_photo TEXT,
        site_fail_notes TEXT,
        delivered_at TIMESTAMP,
        partner_accepted_at TIMESTAMP,
        partner_accepted_by TEXT,
        partner_refused BOOLEAN DEFAULT FALSE,
        refusal_reason TEXT,
        refusal_photo TEXT,
        refusal_notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_incidents (
        id SERIAL PRIMARY KEY,
        incident_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT,
        site_id TEXT NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'medium',
        title TEXT NOT NULL,
        description TEXT,
        photos JSONB DEFAULT '[]',
        related_task_id TEXT,
        related_shipment_id TEXT,
        related_delivery_id TEXT,
        linked_entity_type TEXT,
        linked_entity_id TEXT,
        sla_due_at TIMESTAMP,
        status TEXT NOT NULL DEFAULT 'open',
        assigned_to TEXT,
        assigned_at TIMESTAMP,
        resolved_at TIMESTAMP,
        resolved_by TEXT,
        resolution_notes TEXT,
        escalated_at TIMESTAMP,
        escalation_level INTEGER DEFAULT 0,
        auto_created BOOLEAN DEFAULT FALSE,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    try {
      await client.query(`ALTER TABLE ops_incidents ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
      await client.query(`ALTER TABLE ops_incidents ADD COLUMN IF NOT EXISTS linked_entity_type TEXT;`);
      await client.query(`ALTER TABLE ops_incidents ADD COLUMN IF NOT EXISTS linked_entity_id TEXT;`);
      await client.query(`ALTER TABLE ops_incidents ADD COLUMN IF NOT EXISTS sla_due_at TIMESTAMP;`);
      await client.query(`UPDATE ops_incidents SET tenant_id = (SELECT tenant_id FROM ops_sites WHERE ops_sites.site_id = ops_incidents.site_id LIMIT 1) WHERE tenant_id IS NULL;`);
    } catch (e) { console.log('ops_incidents columns note:', e.message); }

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_audit_log (
        id SERIAL PRIMARY KEY,
        log_id TEXT UNIQUE NOT NULL,
        user_id TEXT NOT NULL,
        user_name TEXT,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        details JSONB DEFAULT '{}',
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_manager_overrides (
        id SERIAL PRIMARY KEY,
        override_id TEXT UNIQUE NOT NULL,
        manager_id TEXT NOT NULL,
        manager_name TEXT NOT NULL,
        override_type TEXT NOT NULL,
        site_id TEXT,
        entity_type TEXT,
        entity_id TEXT,
        reason TEXT NOT NULL,
        previous_value JSONB,
        new_value JSONB,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log('✅ Supply Closet Ops tables created/verified!');

    // =====================================================
    // MULTI-TENANT SUPPORT TABLES
    // =====================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS tenants (
        id SERIAL PRIMARY KEY,
        tenant_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        contact_email TEXT,
        contact_phone TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add tenant_id column to ops_sites if not exists
    try {
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS geo_lat TEXT;`);
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS geo_lng TEXT;`);
    } catch (e) { console.log('ops_sites columns note:', e.message); }

    console.log('✅ Multi-tenant tables created/verified!');

    // =====================================================
    // PRODUCTION SECURITY HARDENING TABLES
    // =====================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS jolt_users (
        id SERIAL PRIMARY KEY,
        employee_code TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        email TEXT,
        name TEXT NOT NULL,
        tenant_id TEXT,
        status TEXT NOT NULL DEFAULT 'pending_password',
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        password_set_at TIMESTAMP,
        last_login_at TIMESTAMP,
        invited_by TEXT,
        invited_at TIMESTAMP,
        revoked_by TEXT,
        revoked_at TIMESTAMP,
        revoke_reason TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add tenant_id to jolt_users if not exists
    try {
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
    } catch (e) { console.log('jolt_users tenant_id note:', e.message); }

    await client.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id SERIAL PRIMARY KEY,
        session_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        device_fingerprint TEXT,
        user_agent TEXT,
        ip_address TEXT,
        expires_at TIMESTAMP NOT NULL,
        last_activity_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS user_site_assignments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        site_id TEXT NOT NULL,
        tenant_id TEXT,
        role TEXT NOT NULL,
        assigned_by INTEGER,
        assigned_at TIMESTAMP DEFAULT NOW(),
        revoked_at TIMESTAMP,
        revoked_by INTEGER
      );
    `);

    // Add tenant_id to user_site_assignments if not exists
    try {
      await client.query(`ALTER TABLE user_site_assignments ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
    } catch (e) { console.log('user_site_assignments tenant_id note:', e.message); }

    await client.query(`
      CREATE TABLE IF NOT EXISTS site_qr_codes (
        id SERIAL PRIMARY KEY,
        qr_id TEXT UNIQUE NOT NULL,
        site_id TEXT NOT NULL,
        qr_token TEXT NOT NULL,
        qr_type TEXT NOT NULL DEFAULT 'site_presence',
        machine_id TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        generated_by INTEGER,
        generated_at TIMESTAMP DEFAULT NOW(),
        revoked_at TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS workflow_sessions (
        id SERIAL PRIMARY KEY,
        session_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        site_id TEXT NOT NULL,
        tenant_id TEXT,
        machine_id TEXT,
        workflow_type TEXT NOT NULL,
        qr_scan_timestamp TIMESTAMP NOT NULL,
        qr_scan_geo_lat TEXT,
        qr_scan_geo_lng TEXT,
        qr_scan_geo_accuracy TEXT,
        started_at TIMESTAMP DEFAULT NOW(),
        completed_at TIMESTAMP,
        abandoned_at TIMESTAMP,
        status TEXT NOT NULL DEFAULT 'in_progress',
        event_count INTEGER DEFAULT 0
      );
    `);

    // Add tenant_id to workflow_sessions if not exists
    try {
      await client.query(`ALTER TABLE workflow_sessions ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
    } catch (e) { console.log('workflow_sessions tenant_id note:', e.message); }

    await client.query(`
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        event_id TEXT UNIQUE NOT NULL,
        event_type TEXT NOT NULL,
        actor_user_id INTEGER NOT NULL,
        tenant_id TEXT,
        site_id TEXT,
        machine_id TEXT,
        workflow_session_id TEXT,
        payload_json JSONB NOT NULL,
        client_timestamp TIMESTAMP,
        server_timestamp TIMESTAMP DEFAULT NOW(),
        geo_lat TEXT,
        geo_lng TEXT,
        geo_accuracy TEXT,
        attachment_ids JSONB DEFAULT '[]',
        previous_event_hash TEXT,
        event_hash TEXT NOT NULL
      );
    `);

    // Add tenant_id to events if not exists
    try {
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
    } catch (e) { console.log('events tenant_id note:', e.message); }

    await client.query(`
      CREATE TABLE IF NOT EXISTS correction_events (
        id SERIAL PRIMARY KEY,
        correction_id TEXT UNIQUE NOT NULL,
        original_event_id TEXT NOT NULL,
        corrected_by_user_id INTEGER NOT NULL,
        correction_type TEXT NOT NULL,
        correction_payload JSONB NOT NULL,
        reason TEXT NOT NULL,
        server_timestamp TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS attachments (
        id SERIAL PRIMARY KEY,
        attachment_id TEXT UNIQUE NOT NULL,
        event_id TEXT,
        workflow_session_id TEXT,
        user_id INTEGER NOT NULL,
        tenant_id TEXT,
        site_id TEXT,
        file_hash TEXT NOT NULL,
        perceptual_hash TEXT,
        object_path TEXT NOT NULL,
        file_size_bytes INTEGER,
        mime_type TEXT,
        client_captured_timestamp TIMESTAMP,
        server_received_timestamp TIMESTAMP DEFAULT NOW(),
        geo_lat TEXT,
        geo_lng TEXT,
        geo_accuracy TEXT,
        device_info JSONB,
        is_duplicate BOOLEAN DEFAULT FALSE,
        duplicate_of_id TEXT
      );
    `);

    // Add tenant_id to attachments if not exists
    try {
      await client.query(`ALTER TABLE attachments ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
    } catch (e) { console.log('attachments tenant_id note:', e.message); }

    // Photos table for Phase 2 proof pipeline
    await client.query(`
      CREATE TABLE IF NOT EXISTS photos (
        id SERIAL PRIMARY KEY,
        photo_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        workflow_session_id TEXT,
        actor_user_id INTEGER NOT NULL,
        storage_key TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        mime_type TEXT,
        size_bytes INTEGER,
        width INTEGER,
        height INTEGER,
        client_captured_at TIMESTAMP NOT NULL,
        server_received_at TIMESTAMP DEFAULT NOW(),
        geo_lat TEXT NOT NULL,
        geo_lng TEXT NOT NULL,
        geo_accuracy_meters REAL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Photo status events table for immutable status tracking
    await client.query(`
      CREATE TABLE IF NOT EXISTS photo_status_events (
        id SERIAL PRIMARY KEY,
        event_id TEXT UNIQUE NOT NULL,
        photo_id TEXT NOT NULL,
        status TEXT NOT NULL,
        actor_user_id INTEGER NOT NULL,
        reason TEXT,
        server_timestamp TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS upload_queue (
        id SERIAL PRIMARY KEY,
        queue_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        workflow_session_id TEXT,
        idempotency_key TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        retry_count INTEGER DEFAULT 0,
        max_retries INTEGER DEFAULT 3,
        last_attempt_at TIMESTAMP,
        error_message TEXT,
        confirmed_at TIMESTAMP,
        attachment_id TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log('✅ Security hardening tables created/verified!');

    // Create indexes for performance (with try-catch to handle existing/partial tables)
    try {
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_site_id ON events(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_actor_user_id ON events(actor_user_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_workflow_session_id ON events(workflow_session_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_tenant_id ON events(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_tenant_server_ts ON events(tenant_id, server_timestamp);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_user_site_assignments_user_id ON user_site_assignments(user_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_user_site_assignments_site_id ON user_site_assignments(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_user_site_assignments_tenant_id ON user_site_assignments(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_attachments_file_hash ON attachments(file_hash);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_attachments_tenant_id ON attachments(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_photos_tenant_id ON photos(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_photos_site_id ON photos(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_photos_tenant_server_ts ON photos(tenant_id, server_received_at);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_photos_sha256 ON photos(sha256_hash);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_photo_status_events_photo_id ON photo_status_events(photo_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_ops_sites_tenant_id ON ops_sites(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_workflow_sessions_tenant_id ON workflow_sessions(tenant_id);`);
      console.log('✅ Database indexes created!');
    } catch (indexError) {
      console.log('⚠️ Some indexes could not be created:', indexError.message);
    }

    // =====================================================
    // PHASE 2.5 - MONITORING & OPERATIONAL CONTROLS TABLES
    // =====================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS system_metrics (
        id SERIAL PRIMARY KEY,
        tenant_id TEXT,
        metric_type TEXT NOT NULL,
        metric_value REAL NOT NULL,
        metric_count INTEGER DEFAULT 1,
        period_start TIMESTAMP NOT NULL,
        period_end TIMESTAMP NOT NULL,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS upload_failures (
        id SERIAL PRIMARY KEY,
        tenant_id TEXT,
        user_id INTEGER NOT NULL,
        site_id TEXT,
        workflow_session_id TEXT,
        failure_type TEXT NOT NULL,
        error_message TEXT,
        file_size_bytes INTEGER,
        mime_type TEXT,
        retry_count INTEGER DEFAULT 0,
        resolved BOOLEAN DEFAULT FALSE,
        resolved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS geo_denials (
        id SERIAL PRIMARY KEY,
        tenant_id TEXT,
        user_id INTEGER NOT NULL,
        site_id TEXT,
        workflow_session_id TEXT,
        denial_reason TEXT NOT NULL,
        expected_lat TEXT,
        expected_lng TEXT,
        actual_lat TEXT,
        actual_lng TEXT,
        distance_meters REAL,
        accuracy_meters REAL,
        device_info JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS session_metrics (
        id SERIAL PRIMARY KEY,
        tenant_id TEXT,
        workflow_session_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        site_id TEXT,
        workflow_type TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TIMESTAMP NOT NULL,
        completed_at TIMESTAMP,
        duration_seconds INTEGER,
        step_count INTEGER DEFAULT 0,
        photo_count INTEGER DEFAULT 0,
        issue_count INTEGER DEFAULT 0,
        receipt_hash TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS login_lockouts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        employee_code TEXT NOT NULL,
        lockout_reason TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        locked_at TIMESTAMP DEFAULT NOW(),
        locked_until TIMESTAMP,
        unlocked_at TIMESTAMP,
        unlocked_by INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        id SERIAL PRIMARY KEY,
        limit_key TEXT UNIQUE NOT NULL,
        limit_type TEXT NOT NULL,
        current_count INTEGER DEFAULT 0,
        max_count INTEGER NOT NULL,
        window_start TIMESTAMP NOT NULL,
        window_seconds INTEGER NOT NULL,
        last_request_at TIMESTAMP,
        blocked BOOLEAN DEFAULT FALSE,
        blocked_at TIMESTAMP,
        blocked_until TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS retention_tracking (
        id SERIAL PRIMARY KEY,
        table_name TEXT NOT NULL,
        record_id TEXT NOT NULL,
        tenant_id TEXT,
        retention_days INTEGER NOT NULL DEFAULT 365,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        marked_for_deletion BOOLEAN DEFAULT FALSE,
        deleted_at TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS visit_receipts (
        id SERIAL PRIMARY KEY,
        receipt_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT,
        workflow_session_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        site_id TEXT NOT NULL,
        workflow_type TEXT NOT NULL,
        receipt_hash TEXT NOT NULL,
        receipt_payload JSONB NOT NULL,
        event_count INTEGER DEFAULT 0,
        photo_count INTEGER DEFAULT 0,
        issue_count INTEGER DEFAULT 0,
        started_at TIMESTAMP NOT NULL,
        completed_at TIMESTAMP NOT NULL,
        duration_seconds INTEGER,
        geo_verified BOOLEAN DEFAULT FALSE,
        client_confirmed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_isolation_alerts (
        id SERIAL PRIMARY KEY,
        alert_type TEXT NOT NULL,
        table_name TEXT,
        record_ids JSONB,
        expected_tenant_id TEXT,
        actual_tenant_id TEXT,
        query_context TEXT,
        severity TEXT NOT NULL DEFAULT 'warning',
        resolved BOOLEAN DEFAULT FALSE,
        resolved_at TIMESTAMP,
        resolved_by INTEGER,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log('✅ Phase 2.5 monitoring tables created/verified!');

    // =====================================================
    // PHASE 3: SHIPPING HARDENING - Tenant Scoping + New Tables
    // =====================================================
    console.log('📦 Running Phase 3 shipping hardening migrations...');

    // Add tenant_id to ops_shipments if not exists
    try {
      await client.query(`ALTER TABLE ops_shipments ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
      await client.query(`ALTER TABLE ops_shipments ADD COLUMN IF NOT EXISTS expected_box_count INTEGER DEFAULT 0;`);
      await client.query(`ALTER TABLE ops_shipments ADD COLUMN IF NOT EXISTS target_delivery_window_hours INTEGER DEFAULT 24;`);
    } catch (e) { console.log('ops_shipments columns note:', e.message); }

    // Add tenant_id to ops_shipment_boxes if not exists
    try {
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS target_weight_lbs DECIMAL(6,2);`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS partner_accepted BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS partner_accepted_at TIMESTAMP;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS partner_accepted_by TEXT;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS partner_refused BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS refusal_reason TEXT;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS refusal_photo TEXT;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS refusal_notes TEXT;`);
      await client.query(`ALTER TABLE ops_shipment_boxes ADD COLUMN IF NOT EXISTS contents_locked_at TIMESTAMP;`);
    } catch (e) { console.log('ops_shipment_boxes columns note:', e.message); }

    // Add tenant_id to ops_delivery_records if not exists
    try {
      await client.query(`ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
      await client.query(`ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS acceptance_window_expires_at TIMESTAMP;`);
      await client.query(`ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS acceptance_escalated BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS escalation_incident_id TEXT;`);
    } catch (e) { console.log('ops_delivery_records columns note:', e.message); }

    // Add tenant_id to ops_packing_logs if not exists
    try {
      await client.query(`ALTER TABLE ops_packing_logs ADD COLUMN IF NOT EXISTS tenant_id TEXT;`);
      await client.query(`ALTER TABLE ops_packing_logs ADD COLUMN IF NOT EXISTS site_id TEXT;`);
      await client.query(`ALTER TABLE ops_packing_logs ADD COLUMN IF NOT EXISTS scale_zero_confirmed BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE ops_packing_logs ADD COLUMN IF NOT EXISTS freshness_lock_confirmed BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE ops_packing_logs ADD COLUMN IF NOT EXISTS label_verified BOOLEAN DEFAULT FALSE;`);
    } catch (e) { console.log('ops_packing_logs columns note:', e.message); }

    // Box Contents Snapshot - append-only, locked after label
    await client.query(`
      CREATE TABLE IF NOT EXISTS box_contents_snapshot (
        id SERIAL PRIMARY KEY,
        snapshot_id TEXT UNIQUE NOT NULL,
        box_id TEXT NOT NULL,
        box_record_id TEXT NOT NULL,
        shipment_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        sku TEXT NOT NULL,
        item_name TEXT,
        qty INTEGER NOT NULL,
        unit TEXT DEFAULT 'ea',
        lot_number TEXT,
        best_by DATE,
        created_at TIMESTAMP DEFAULT NOW(),
        created_by TEXT NOT NULL
      );
    `);

    // QC Gate Events - append-only per-box gate validation
    await client.query(`
      CREATE TABLE IF NOT EXISTS qc_gate_events (
        id SERIAL PRIMARY KEY,
        gate_event_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        shipment_id TEXT NOT NULL,
        box_id TEXT NOT NULL,
        box_record_id TEXT NOT NULL,
        gate_type TEXT NOT NULL,
        pass_fail TEXT NOT NULL,
        measured_value TEXT,
        notes TEXT,
        actor_user_id TEXT NOT NULL,
        actor_user_name TEXT,
        photo_id TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Box Scan Custody - driver per-box delivery scans
    await client.query(`
      CREATE TABLE IF NOT EXISTS box_scan_custody (
        id SERIAL PRIMARY KEY,
        scan_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        shipment_id TEXT NOT NULL,
        box_record_id TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        scanned_by_driver_id TEXT NOT NULL,
        scanned_by_driver_name TEXT,
        scan_type TEXT NOT NULL DEFAULT 'delivery',
        gps_latitude DECIMAL(10,8),
        gps_longitude DECIMAL(11,8),
        scanned_at TIMESTAMP DEFAULT NOW(),
        client_timestamp TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Zone PAR Targets - site inventory par levels
    await client.query(`
      CREATE TABLE IF NOT EXISTS zone_par_targets (
        id SERIAL PRIMARY KEY,
        par_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        zone TEXT NOT NULL,
        sku TEXT NOT NULL,
        item_name TEXT,
        unit TEXT DEFAULT 'ea',
        min_qty INTEGER NOT NULL,
        target_qty INTEGER NOT NULL,
        reorder_point INTEGER,
        is_active BOOLEAN DEFAULT TRUE,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Refill Counts - partner count submissions during refill
    await client.query(`
      CREATE TABLE IF NOT EXISTS refill_counts (
        id SERIAL PRIMARY KEY,
        count_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        submission_id TEXT,
        zone TEXT NOT NULL,
        sku TEXT NOT NULL,
        item_name TEXT,
        count_before INTEGER,
        count_after INTEGER NOT NULL,
        delta INTEGER,
        par_target_qty INTEGER,
        counted_by TEXT NOT NULL,
        counted_at TIMESTAMP DEFAULT NOW(),
        photo_proof TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Shipment Proposals - auto-generated from consumption
    await client.query(`
      CREATE TABLE IF NOT EXISTS shipment_proposals (
        id SERIAL PRIMARY KEY,
        proposal_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        proposed_boxes JSONB DEFAULT '[]',
        proposed_items JSONB DEFAULT '[]',
        consumption_basis JSONB,
        projected_depletion_date DATE,
        urgency TEXT DEFAULT 'normal',
        approved_by TEXT,
        approved_at TIMESTAMP,
        converted_to_shipment_id TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Playbook Tasks - auto-created from incidents
    await client.query(`
      CREATE TABLE IF NOT EXISTS playbook_tasks (
        id SERIAL PRIMARY KEY,
        task_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        playbook_type TEXT NOT NULL,
        task_title TEXT NOT NULL,
        task_description TEXT,
        due_at TIMESTAMP,
        status TEXT NOT NULL DEFAULT 'pending',
        assigned_to TEXT,
        assigned_at TIMESTAMP,
        completed_by TEXT,
        completed_at TIMESTAMP,
        completion_notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Evidence Packets - exported bundles
    await client.query(`
      CREATE TABLE IF NOT EXISTS evidence_packets (
        id SERIAL PRIMARY KEY,
        packet_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        packet_type TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        packet_hash TEXT NOT NULL,
        packet_payload JSONB NOT NULL,
        manifest_summary TEXT,
        qc_gate_count INTEGER DEFAULT 0,
        photo_count INTEGER DEFAULT 0,
        event_count INTEGER DEFAULT 0,
        generated_by TEXT NOT NULL,
        generated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Golden Photos - reference photos per site/zone
    await client.query(`
      CREATE TABLE IF NOT EXISTS golden_photos (
        id SERIAL PRIMARY KEY,
        golden_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        zone TEXT NOT NULL,
        photo_url TEXT NOT NULL,
        description TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        uploaded_by TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create indexes for new tables
    try {
      await client.query(`CREATE INDEX IF NOT EXISTS idx_box_contents_snapshot_box ON box_contents_snapshot(box_record_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_box_contents_snapshot_tenant ON box_contents_snapshot(tenant_id, site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_qc_gate_events_box ON qc_gate_events(box_record_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_qc_gate_events_tenant ON qc_gate_events(tenant_id, site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_box_scan_custody_delivery ON box_scan_custody(delivery_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_box_scan_custody_tenant ON box_scan_custody(tenant_id, site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_zone_par_targets_site ON zone_par_targets(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_zone_par_targets_tenant ON zone_par_targets(tenant_id, site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_refill_counts_site ON refill_counts(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_playbook_tasks_incident ON playbook_tasks(incident_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_shipment_proposals_site ON shipment_proposals(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_ops_shipments_tenant ON ops_shipments(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_ops_shipment_boxes_tenant ON ops_shipment_boxes(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_ops_delivery_records_tenant ON ops_delivery_records(tenant_id);`);
    } catch (e) { console.log('Phase 3 indexes note:', e.message); }

    // Backfill tenant_id for existing shipping records
    try {
      await client.query(`
        UPDATE ops_shipments s
        SET tenant_id = COALESCE(
          (SELECT tenant_id FROM ops_sites WHERE site_id = s.site_id LIMIT 1),
          'JOLT_INTERNAL'
        )
        WHERE s.tenant_id IS NULL;
      `);
      await client.query(`
        UPDATE ops_shipment_boxes b
        SET tenant_id = COALESCE(
          (SELECT tenant_id FROM ops_shipments WHERE shipment_id = b.shipment_id LIMIT 1),
          'JOLT_INTERNAL'
        )
        WHERE b.tenant_id IS NULL;
      `);
      await client.query(`
        UPDATE ops_delivery_records d
        SET tenant_id = COALESCE(
          (SELECT tenant_id FROM ops_shipments WHERE shipment_id = d.shipment_id LIMIT 1),
          'JOLT_INTERNAL'
        )
        WHERE d.tenant_id IS NULL;
      `);
      await client.query(`
        UPDATE ops_packing_logs p
        SET tenant_id = COALESCE(
          (SELECT tenant_id FROM ops_shipment_boxes WHERE box_record_id = p.shipment_box_id LIMIT 1),
          'JOLT_INTERNAL'
        )
        WHERE p.tenant_id IS NULL;
      `);
    } catch (e) { console.log('Tenant backfill note:', e.message); }

    console.log('✅ Phase 3 shipping hardening complete!');

    // =====================================================
    // DB-LEVEL PROTECTIONS FOR IMMUTABLE EVIDENCE TABLES
    // =====================================================
    console.log('🔒 Setting up database-level protections for evidence tables...');

    try {
      await client.query(`
        CREATE OR REPLACE FUNCTION prevent_update_delete() RETURNS TRIGGER AS $$
        BEGIN
          RAISE EXCEPTION 'Updates and deletes are blocked on immutable evidence tables. Use correction_events instead.';
        END;
        $$ LANGUAGE plpgsql;
      `);
      
      const immutableTables = ['qc_gate_events', 'box_contents_snapshot', 'box_scan_custody', 'events'];
      
      for (const table of immutableTables) {
        try {
          await client.query(`DROP TRIGGER IF EXISTS no_update_${table} ON ${table};`);
          await client.query(`DROP TRIGGER IF EXISTS no_delete_${table} ON ${table};`);
          
          await client.query(`
            CREATE TRIGGER no_update_${table}
            BEFORE UPDATE ON ${table}
            FOR EACH ROW EXECUTE FUNCTION prevent_update_delete();
          `);
          
          await client.query(`
            CREATE TRIGGER no_delete_${table}
            BEFORE DELETE ON ${table}
            FOR EACH ROW EXECUTE FUNCTION prevent_update_delete();
          `);
        } catch (e) { console.log(`  Trigger for ${table}:`, e.message); }
      }
      
      console.log('✅ Immutable evidence table protections applied!');
    } catch (e) { console.log('DB triggers note:', e.message); }

    // =====================================================
    // PHASE 4: PILOT READINESS + WEEKLY CADENCE + KPI
    // =====================================================
    console.log('📊 Running Phase 4 pilot readiness migrations...');

    // Go-Live Certificates - immutable onboarding completion records
    await client.query(`
      CREATE TABLE IF NOT EXISTS go_live_certificates (
        id SERIAL PRIMARY KEY,
        certificate_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        onboarding_steps JSONB DEFAULT '{}',
        dry_run_results JSONB DEFAULT '{}',
        zones_configured JSONB DEFAULT '[]',
        par_targets_count INTEGER DEFAULT 0,
        golden_photos_count INTEGER DEFAULT 0,
        users_invited JSONB DEFAULT '[]',
        all_checks_passed BOOLEAN DEFAULT FALSE,
        marked_live_at TIMESTAMP,
        marked_live_by TEXT,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Go-Live Dry Run Checks - individual check results
    await client.query(`
      CREATE TABLE IF NOT EXISTS go_live_dry_run_checks (
        id SERIAL PRIMARY KEY,
        check_id TEXT UNIQUE NOT NULL,
        certificate_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        check_type TEXT NOT NULL,
        check_name TEXT NOT NULL,
        passed BOOLEAN DEFAULT FALSE,
        result_data JSONB,
        tested_by TEXT NOT NULL,
        tested_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Weekly KPI Snapshots - aggregated metrics per site/week
    await client.query(`
      CREATE TABLE IF NOT EXISTS weekly_kpi_snapshots (
        id SERIAL PRIMARY KEY,
        snapshot_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        week_start DATE NOT NULL,
        week_end DATE NOT NULL,
        refill_scheduled INTEGER DEFAULT 0,
        refill_completed INTEGER DEFAULT 0,
        refill_completion_rate DECIMAL(5,2) DEFAULT 0,
        proof_submissions INTEGER DEFAULT 0,
        proof_first_pass INTEGER DEFAULT 0,
        proof_first_pass_rate DECIMAL(5,2) DEFAULT 0,
        deliveries_total INTEGER DEFAULT 0,
        deliveries_accepted INTEGER DEFAULT 0,
        avg_acceptance_latency_hours DECIMAL(6,2),
        missing_box_count INTEGER DEFAULT 0,
        incidents_total INTEGER DEFAULT 0,
        incidents_by_type JSONB DEFAULT '{}',
        median_refill_duration_mins INTEGER,
        median_pod_duration_mins INTEGER,
        median_visit_duration_mins INTEGER,
        training_flags JSONB DEFAULT '[]',
        computed_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(site_id, week_start)
      );
    `);

    // Weekly Cadence Plans - generated weekly work queue
    await client.query(`
      CREATE TABLE IF NOT EXISTS weekly_cadence_plans (
        id SERIAL PRIMARY KEY,
        plan_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        week_start DATE NOT NULL,
        week_end DATE NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        sites_included JSONB DEFAULT '[]',
        shipment_proposals_generated INTEGER DEFAULT 0,
        refill_tasks_generated INTEGER DEFAULT 0,
        delivery_tasks_generated INTEGER DEFAULT 0,
        exceptions_count INTEGER DEFAULT 0,
        generated_by TEXT,
        generated_at TIMESTAMP DEFAULT NOW(),
        approved_by TEXT,
        approved_at TIMESTAMP,
        closed_at TIMESTAMP
      );
    `);

    // Weekly Work Items - individual work items in a cadence plan
    await client.query(`
      CREATE TABLE IF NOT EXISTS weekly_work_items (
        id SERIAL PRIMARY KEY,
        work_item_id TEXT UNIQUE NOT NULL,
        plan_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        item_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        priority TEXT DEFAULT 'normal',
        assigned_to TEXT,
        due_date DATE,
        status TEXT NOT NULL DEFAULT 'pending',
        linked_entity_type TEXT,
        linked_entity_id TEXT,
        completed_by TEXT,
        completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Landlord Digests - weekly summaries for landlord portal
    await client.query(`
      CREATE TABLE IF NOT EXISTS landlord_digests (
        id SERIAL PRIMARY KEY,
        digest_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        week_start DATE NOT NULL,
        week_end DATE NOT NULL,
        refills_completed INTEGER DEFAULT 0,
        refills_overdue INTEGER DEFAULT 0,
        deliveries_accepted INTEGER DEFAULT 0,
        deliveries_pending INTEGER DEFAULT 0,
        open_incidents INTEGER DEFAULT 0,
        incident_severities JSONB DEFAULT '{}',
        compliance_streak INTEGER DEFAULT 0,
        overall_status TEXT DEFAULT 'good',
        digest_summary TEXT,
        generated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(site_id, week_start)
      );
    `);

    // Training Flags - automated training recommendations
    await client.query(`
      CREATE TABLE IF NOT EXISTS training_flags (
        id SERIAL PRIMARY KEY,
        flag_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        user_id TEXT,
        flag_type TEXT NOT NULL,
        flag_reason TEXT NOT NULL,
        threshold_value DECIMAL(6,2),
        actual_value DECIMAL(6,2),
        severity TEXT DEFAULT 'warning',
        acknowledged BOOLEAN DEFAULT FALSE,
        acknowledged_by TEXT,
        acknowledged_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add site status for live tracking
    try {
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS is_live BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS go_live_certificate_id TEXT;`);
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS acceptance_window_hours INTEGER DEFAULT 24;`);
    } catch (e) { console.log('ops_sites Phase 4 columns note:', e.message); }

    // Create indexes for Phase 4 tables
    try {
      await client.query(`CREATE INDEX IF NOT EXISTS idx_go_live_certificates_site ON go_live_certificates(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_go_live_certificates_tenant ON go_live_certificates(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_weekly_kpi_snapshots_site_week ON weekly_kpi_snapshots(site_id, week_start);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_weekly_kpi_snapshots_tenant ON weekly_kpi_snapshots(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_weekly_cadence_plans_week ON weekly_cadence_plans(week_start);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_weekly_work_items_plan ON weekly_work_items(plan_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_weekly_work_items_site ON weekly_work_items(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_landlord_digests_site_week ON landlord_digests(site_id, week_start);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_training_flags_site ON training_flags(site_id);`);
    } catch (e) { console.log('Phase 4 indexes note:', e.message); }

    console.log('✅ Phase 4 pilot readiness tables complete!');

    // =====================================================
    // PHASE 5: PRODUCTION HARDENING
    // =====================================================
    console.log('🔐 Running Phase 5 production hardening migrations...');

    // Security Deny Log - Audit all access denials
    await client.query(`
      CREATE TABLE IF NOT EXISTS security_deny_log (
        id SERIAL PRIMARY KEY,
        deny_id TEXT UNIQUE NOT NULL,
        deny_type TEXT NOT NULL,
        user_id TEXT,
        user_role TEXT,
        tenant_id TEXT,
        ip_address TEXT,
        path TEXT,
        method TEXT,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Security Events - General security audit trail with tenant context
    await client.query(`
      CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY,
        event_id TEXT UNIQUE NOT NULL,
        event_type TEXT NOT NULL,
        user_id TEXT,
        tenant_id TEXT,
        endpoint TEXT,
        action TEXT,
        target_table TEXT,
        success BOOLEAN DEFAULT TRUE,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Training Flags - Track users/sites needing training
    await client.query(`
      CREATE TABLE IF NOT EXISTS training_flags (
        id SERIAL PRIMARY KEY,
        flag_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT,
        site_id TEXT,
        user_id TEXT,
        flag_type TEXT NOT NULL,
        trigger_value DECIMAL(8,2),
        threshold_value DECIMAL(8,2),
        evaluation_period_days INTEGER DEFAULT 14,
        status TEXT DEFAULT 'open',
        recommended_action TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        resolved_at TIMESTAMP,
        resolved_by TEXT
      );
    `);

    // Ops Incident Assignments - Track assignment history
    await client.query(`
      CREATE TABLE IF NOT EXISTS ops_incident_assignments (
        id SERIAL PRIMARY KEY,
        assignment_id TEXT UNIQUE NOT NULL,
        incident_id TEXT NOT NULL,
        assigned_to TEXT NOT NULL,
        assigned_by TEXT NOT NULL,
        assigned_at TIMESTAMP DEFAULT NOW(),
        notes TEXT
      );
    `);

    // System Status - Deployment and health tracking
    await client.query(`
      CREATE TABLE IF NOT EXISTS system_status (
        id SERIAL PRIMARY KEY,
        status_id TEXT UNIQUE NOT NULL,
        deploy_version TEXT,
        deployed_at TIMESTAMP,
        deployed_by TEXT,
        health_status TEXT DEFAULT 'healthy',
        error_rate_1h DECIMAL(5,2) DEFAULT 0,
        queue_backlog INTEGER DEFAULT 0,
        storage_health TEXT DEFAULT 'ok',
        last_check_at TIMESTAMP DEFAULT NOW(),
        metadata JSONB DEFAULT '{}'
      );
    `);

    // Failure Log - Track failures for ops-admin debugging
    await client.query(`
      CREATE TABLE IF NOT EXISTS failure_log (
        id SERIAL PRIMARY KEY,
        failure_id TEXT UNIQUE NOT NULL,
        failure_type TEXT NOT NULL,
        tenant_id TEXT,
        site_id TEXT,
        user_id TEXT,
        error_message TEXT,
        stack_trace TEXT,
        request_path TEXT,
        request_method TEXT,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Evidence Completeness - Weekly KPI tracking
    await client.query(`
      CREATE TABLE IF NOT EXISTS evidence_completeness (
        id SERIAL PRIMARY KEY,
        completeness_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        week_start DATE NOT NULL,
        total_required INTEGER DEFAULT 0,
        total_submitted INTEGER DEFAULT 0,
        total_verified INTEGER DEFAULT 0,
        completeness_rate DECIMAL(5,2) DEFAULT 0,
        missing_items JSONB DEFAULT '[]',
        computed_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(site_id, week_start)
      );
    `);

    // Idempotency Keys - Prevent duplicate operations
    await client.query(`
      CREATE TABLE IF NOT EXISTS idempotency_keys (
        id SERIAL PRIMARY KEY,
        idempotency_key TEXT UNIQUE NOT NULL,
        operation_type TEXT NOT NULL,
        result JSONB,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '24 hours'
      );
    `);

    // Data Retention Policy - Track retention schedules
    await client.query(`
      CREATE TABLE IF NOT EXISTS data_retention_policy (
        id SERIAL PRIMARY KEY,
        policy_id TEXT UNIQUE NOT NULL,
        entity_type TEXT NOT NULL,
        retention_days INTEGER NOT NULL DEFAULT 365,
        last_cleanup_at TIMESTAMP,
        records_cleaned INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add columns for session revocation
    try {
      await client.query(`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;`);
      await client.query(`ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS revoked_by TEXT;`);
    } catch (e) { console.log('auth_sessions revocation columns note:', e.message); }

    // Create indexes for production hardening tables
    try {
      await client.query(`CREATE INDEX IF NOT EXISTS idx_security_deny_log_time ON security_deny_log(created_at);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_security_deny_log_type ON security_deny_log(deny_type);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_security_deny_log_tenant ON security_deny_log(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(created_at);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_failure_log_time ON failure_log(created_at);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_failure_log_tenant ON failure_log(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_failure_log_site ON failure_log(site_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_evidence_completeness_site_week ON evidence_completeness(site_id, week_start);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires ON idempotency_keys(expires_at);`);
    } catch (e) { console.log('Phase 5 indexes note:', e.message); }

    // Initialize default data retention policies
    try {
      await client.query(`
        INSERT INTO data_retention_policy (policy_id, entity_type, retention_days) VALUES
          ('RET-PHOTOS', 'proof_photos', 365),
          ('RET-EVENTS', 'events', 730),
          ('RET-SESSIONS', 'auth_sessions', 90),
          ('RET-DENY-LOG', 'security_deny_log', 180)
        ON CONFLICT (policy_id) DO NOTHING
      `);
    } catch (e) { console.log('Data retention policy seed note:', e.message); }

    console.log('✅ Phase 5 production hardening tables complete!');

    // =====================================================
    // PLAN 1: 1-100 MACHINE SCALING TABLES
    // A50 Squeeze Gate, Consequence Engine, Feature Flags
    // =====================================================
    console.log('🚀 Running Plan 1 scaling migrations...');

    // A50 Test Sessions
    await client.query(`
      CREATE TABLE IF NOT EXISTS a50_test_sessions (
        id SERIAL PRIMARY KEY,
        session_id TEXT UNIQUE NOT NULL,
        machine_id TEXT NOT NULL,
        tester_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'in_progress',
        current_step INTEGER DEFAULT 0,
        steps_completed JSONB DEFAULT '[]',
        final_result TEXT,
        proof_urls JSONB DEFAULT '[]',
        started_at TIMESTAMP DEFAULT NOW(),
        completed_at TIMESTAMP,
        submitted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // A50 Test Results
    await client.query(`
      CREATE TABLE IF NOT EXISTS a50_test_results (
        id SERIAL PRIMARY KEY,
        test_id TEXT UNIQUE NOT NULL,
        machine_id TEXT NOT NULL,
        tester_id TEXT NOT NULL,
        passed BOOLEAN NOT NULL,
        proof_url TEXT,
        timer_duration_sec INTEGER DEFAULT 60,
        test_instructions_followed BOOLEAN DEFAULT TRUE,
        metadata JSONB DEFAULT '{}',
        tested_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add safe mode columns to machines
    try {
      await client.query(`ALTER TABLE machines ADD COLUMN IF NOT EXISTS safe_mode BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE machines ADD COLUMN IF NOT EXISTS safe_mode_entered_at TIMESTAMP;`);
      await client.query(`ALTER TABLE machines ADD COLUMN IF NOT EXISTS safe_mode_exit_date TIMESTAMP;`);
      await client.query(`ALTER TABLE machines ADD COLUMN IF NOT EXISTS safe_mode_exited_at TIMESTAMP;`);
    } catch (e) { console.log('Safe mode columns note:', e.message); }

    // Add consequence engine columns to jolt_users
    try {
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS restricted_mode BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS restricted_mode_reason TEXT;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS restricted_mode_entered_at TIMESTAMP;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS restricted_mode_cleared_by TEXT;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS restricted_mode_cleared_at TIMESTAMP;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS recert_required BOOLEAN DEFAULT FALSE;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS recert_reason TEXT;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS recert_required_at TIMESTAMP;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS last_recert_at TIMESTAMP;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS last_recert_type TEXT;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS last_recert_by TEXT;`);
    } catch (e) { console.log('Consequence engine user columns note:', e.message); }

    // Feature Flags table
    await client.query(`
      CREATE TABLE IF NOT EXISTS feature_flags (
        id SERIAL PRIMARY KEY,
        flag_name TEXT NOT NULL,
        enabled BOOLEAN DEFAULT FALSE,
        tenant_id TEXT,
        site_id TEXT,
        updated_by TEXT,
        updated_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    // Create unique index for feature flags (handles NULL values)
    try {
      await client.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_feature_flags_unique 
        ON feature_flags (flag_name, COALESCE(tenant_id, ''), COALESCE(site_id, ''));
      `);
    } catch (e) { console.log('Feature flags unique index note:', e.message); }

    // Tenant Isolation Audits table
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_isolation_audits (
        id SERIAL PRIMARY KEY,
        audit_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT,
        tables_checked INTEGER DEFAULT 0,
        violations_found INTEGER DEFAULT 0,
        passed BOOLEAN DEFAULT TRUE,
        details JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add device_id and actor_role columns to events
    try {
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS device_id TEXT;`);
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS actor_role TEXT;`);
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS gps_lat NUMERIC;`);
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS gps_lng NUMERIC;`);
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS evidence_links JSONB DEFAULT '[]';`);
    } catch (e) { console.log('Events columns note:', e.message); }

    // Plan 1 indexes
    try {
      await client.query(`CREATE INDEX IF NOT EXISTS idx_a50_results_machine ON a50_test_results(machine_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_a50_results_tested_at ON a50_test_results(tested_at);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_a50_sessions_machine ON a50_test_sessions(machine_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_feature_flags_name ON feature_flags(flag_name);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_feature_flags_tenant ON feature_flags(tenant_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_machines_safe_mode ON machines(safe_mode);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_users_restricted ON jolt_users(restricted_mode);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_users_recert ON jolt_users(recert_required);`);
    } catch (e) { console.log('Plan 1 indexes note:', e.message); }

    console.log('✅ Plan 1 scaling tables complete!');

    // =====================================================
    // V93 SIPJOLT OS TABLES
    // Daily Tokens, Site Geofence, Enhanced Events
    // =====================================================
    console.log('🚀 Running v1.00 SIPJOLT OS migrations...');

    // Daily Tokens table for recovery validation
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_tokens (
        date DATE PRIMARY KEY,
        code TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Add geofence columns to ops_sites
    try {
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS lat NUMERIC;`);
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS lng NUMERIC;`);
      await client.query(`ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'ACTIVE';`);
    } catch (e) { console.log('Site geofence columns note:', e.message); }

    // Add video_url to events for squeeze gate videos
    try {
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS video_url TEXT;`);
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS is_synced BOOLEAN DEFAULT TRUE;`);
      await client.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS client_timestamp BIGINT;`);
    } catch (e) { console.log('Events video columns note:', e.message); }

    // Add site_id to ops_incidents if not exists
    try {
      await client.query(`ALTER TABLE ops_incidents ADD COLUMN IF NOT EXISTS site_id TEXT;`);
    } catch (e) { console.log('Incidents site_id note:', e.message); }

    // v1.00 indexes
    try {
      await client.query(`CREATE INDEX IF NOT EXISTS idx_daily_tokens_date ON daily_tokens(date);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_sites_status ON ops_sites(status);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_events_client_timestamp ON events(client_timestamp);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_incidents_site ON ops_incidents(site_id);`);
    } catch (e) { console.log('v1.00 indexes note:', e.message); }

    console.log('✅ v1.00 SIPJOLT OS tables complete!');

    // v1.00 User Management columns
    try {
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'TECHNICIAN';`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS reliability_score NUMERIC DEFAULT 100.0;`);
      await client.query(`ALTER TABLE jolt_users ADD COLUMN IF NOT EXISTS assigned_route TEXT;`);
      console.log('✅ v1.00 User Management columns added!');
    } catch (e) { console.log('User management columns note:', e.message); }

    // Seed default tenant if none exists
    const tenantCount = await client.query('SELECT COUNT(*) as count FROM tenants');
    if (tenantCount.rows[0].count === '0' || parseInt(tenantCount.rows[0].count) === 0) {
      console.log('🌱 Seeding default tenant (JOLT_INTERNAL)...');
      
      await client.query(`
        INSERT INTO tenants (tenant_id, name, contact_email, is_active, created_at)
        VALUES ('JOLT_INTERNAL', 'JOLT Internal Operations', 'ops@jolt.service', TRUE, NOW())
        ON CONFLICT (tenant_id) DO NOTHING
      `);
      
      console.log('✅ Default tenant created!');
      
      // Backfill existing sites to default tenant
      await client.query(`UPDATE ops_sites SET tenant_id = 'JOLT_INTERNAL' WHERE tenant_id IS NULL;`);
      await client.query(`UPDATE events SET tenant_id = 'JOLT_INTERNAL' WHERE tenant_id IS NULL;`);
      await client.query(`UPDATE workflow_sessions SET tenant_id = 'JOLT_INTERNAL' WHERE tenant_id IS NULL;`);
      await client.query(`UPDATE attachments SET tenant_id = 'JOLT_INTERNAL' WHERE tenant_id IS NULL;`);
      await client.query(`UPDATE user_site_assignments SET tenant_id = 'JOLT_INTERNAL' WHERE tenant_id IS NULL;`);
      
      console.log('✅ Existing data backfilled to default tenant!');
    }

    // Check and fix technician_id column type if needed
    try {
      const colCheck = await client.query(`
        SELECT data_type FROM information_schema.columns 
        WHERE table_name = 'technicians' AND column_name = 'technician_id'
      `);
      
      if (colCheck.rows.length > 0 && colCheck.rows[0].data_type === 'integer') {
        console.log('[DB] Found INTEGER technician_id, converting to TEXT...');
        await client.query(`ALTER TABLE technicians ALTER COLUMN technician_id TYPE TEXT USING technician_id::TEXT`);
        console.log('[DB] Changed technician_id to TEXT');
      } else {
        console.log('[DB] technician_id column is already TEXT');
      }
    } catch (e) { 
      console.log('[DB] technician_id type check note:', e.message);
    }

    console.log('✅ Database tables created/verified successfully!');
    
    // Seed initial machine data if empty
    const machineCount = await client.query('SELECT COUNT(*) as count FROM machines');
    if (machineCount.rows[0].count === '0' || parseInt(machineCount.rows[0].count) === 0) {
      console.log('🌱 Seeding initial machine data...');
      
      await client.query(`
        INSERT INTO machines (machine_id, nickname, location, status, cups_served_today, active_errors, next_weekly_due)
        VALUES 
          ('M-001', 'Lobby Latte', 'Main Lobby', 'active', 145, '[]', NOW() + INTERVAL '5 days'),
          ('M-002', 'Cafe Central', 'Cafeteria', 'repair', 0, '["Grinder Timeout", "Brew Pressure Low"]', NOW() - INTERVAL '1 day'),
          ('M-003', 'Building B Express', 'Building B', 'active', 203, '[]', NOW() + INTERVAL '6 days'),
          ('M-004', 'North Wing Wonder', 'North Wing', 'service_due', 67, '[]', NOW()),
          ('M-005', 'Rooftop Refresher', 'Rooftop Lounge', 'offline', 0, '["Power Loss", "Water Line Disconnected"]', NOW() - INTERVAL '3 days')
        ON CONFLICT (machine_id) DO NOTHING
      `);
      
      console.log('✅ Initial machines seeded!');
    }
    
    // Seed default admin user if no jolt_users exist
    const userCount = await client.query('SELECT COUNT(*) as count FROM jolt_users');
    if (userCount.rows[0].count === '0' || parseInt(userCount.rows[0].count) === 0) {
      console.log('🌱 Seeding default admin user...');
      
      // Create default admin user (password needs to be set on first login)
      await client.query(`
        INSERT INTO jolt_users (employee_code, name, email, status, invited_by, invited_at)
        VALUES ('ADMIN001', 'System Administrator', 'admin@jolt.service', 'pending_password', 'SYSTEM', NOW())
        ON CONFLICT (employee_code) DO NOTHING
      `);
      
      console.log('✅ Default admin user created!');
      console.log('   Employee Code: ADMIN001');
      console.log('   Status: pending_password (set password on first login)');
    }

    console.log('🎉 Migration completed successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    if (client) {
      client.release();
    }
  }
};

export const initDatabase = runMigration;

if (process.argv[1]?.includes('migrate')) {
  runMigration().then(() => process.exit(0)).catch(() => process.exit(1));
}
