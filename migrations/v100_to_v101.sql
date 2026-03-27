-- ============================================
-- SIPJOLT v100 → v101 DATABASE MIGRATION
-- Run Date: 2026-01-22
-- ============================================

-- STEP 1: Create sensor_readings table (Initiative #2)
CREATE TABLE IF NOT EXISTS sensor_readings (
  id BIGSERIAL PRIMARY KEY,
  device_id VARCHAR(50) NOT NULL,
  site_id TEXT NOT NULL,
  bin_id INT NOT NULL CHECK (bin_id BETWEEN 1 AND 11),
  ingredient VARCHAR(50) NOT NULL,
  weight_lbs DECIMAL(6,2) NOT NULL CHECK (weight_lbs >= 0),
  percent_full DECIMAL(5,2) NOT NULL CHECK (percent_full BETWEEN 0 AND 100),
  timestamp TIMESTAMP NOT NULL,
  battery_voltage DECIMAL(4,2),
  status VARCHAR(20) DEFAULT 'ok',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sensor_readings_site_bin ON sensor_readings(site_id, bin_id);
CREATE INDEX IF NOT EXISTS idx_sensor_readings_timestamp ON sensor_readings(timestamp);
CREATE INDEX IF NOT EXISTS idx_sensor_readings_device ON sensor_readings(device_id);

-- STEP 2: Create sensor_alerts table
CREATE TABLE IF NOT EXISTS sensor_alerts (
  id BIGSERIAL PRIMARY KEY,
  site_id TEXT NOT NULL,
  bin_id INT NOT NULL,
  ingredient VARCHAR(50) NOT NULL,
  alert_type VARCHAR(50) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  percent_full DECIMAL(5,2),
  estimated_days_remaining INT,
  triggered_at TIMESTAMP NOT NULL,
  resolved_at TIMESTAMP,
  resolution_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_sensor_alerts_site ON sensor_alerts(site_id, triggered_at);
CREATE INDEX IF NOT EXISTS idx_sensor_alerts_unresolved ON sensor_alerts(resolved_at);
CREATE INDEX IF NOT EXISTS idx_sensor_alerts_severity ON sensor_alerts(severity);

-- STEP 3: Add GPS fields to ops_delivery_records
ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS gps_lat DECIMAL(10, 7);
ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS gps_lng DECIMAL(10, 7);
ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS gps_accuracy DECIMAL(5, 2);
ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS pod_photo_hash VARCHAR(64);
ALTER TABLE ops_delivery_records ADD COLUMN IF NOT EXISTS geofence_validated BOOLEAN DEFAULT FALSE;

-- STEP 4: Create label_print_jobs table
CREATE TABLE IF NOT EXISTS label_print_jobs (
  id BIGSERIAL PRIMARY KEY,
  job_type VARCHAR(50) NOT NULL,
  site_id TEXT,
  delivery_id TEXT,
  label_data JSONB NOT NULL,
  printer_id VARCHAR(100),
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP,
  error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_label_print_jobs_status ON label_print_jobs(status);
CREATE INDEX IF NOT EXISTS idx_label_print_jobs_created ON label_print_jobs(created_at);

-- STEP 5: Update ops_sites table for 11-bin configuration
ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS bin_count INT DEFAULT 11;
ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS rack_type VARCHAR(50) DEFAULT 'HDX_4_SHELF';
ALTER TABLE ops_sites ADD COLUMN IF NOT EXISTS floor_space_sqft INT DEFAULT 16;

-- STEP 6: Add display_role column to users table if exists
DO $$
BEGIN
  IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users') THEN
    ALTER TABLE users ADD COLUMN IF NOT EXISTS display_role VARCHAR(100);
  END IF;
END $$;

-- STEP 7: Create notification_templates table
CREATE TABLE IF NOT EXISTS notification_templates (
  id SERIAL PRIMARY KEY,
  template_key VARCHAR(100) UNIQUE NOT NULL,
  template_body TEXT NOT NULL,
  variables JSONB,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO notification_templates (template_key, template_body, variables) VALUES
('DELIVERY_ACCEPTED', '{{baristaName}}, your SIPJOLT Barista Specialist, has accepted the delivery.', '["baristaName"]'),
('REFILL_COMPLETE', '{{baristaName}}, Barista Specialist, completed refill at {{siteName}}.', '["baristaName", "siteName"]'),
('COFFEE_PERK_EARNED', 'Great work, Barista Specialist! You''ve earned a free coffee.', '[]'),
('LOW_INVENTORY_ALERT', 'Alert: {{siteName}}, Bin {{binId}} ({{ingredient}}) is at {{percentFull}}%. Estimated stockout: {{daysRemaining}} days.', '["siteName", "binId", "ingredient", "percentFull", "daysRemaining"]')
ON CONFLICT (template_key) DO UPDATE SET template_body = EXCLUDED.template_body;

-- STEP 8: Create coffee_perks table
CREATE TABLE IF NOT EXISTS coffee_perks (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  site_id TEXT,
  claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  perk_type VARCHAR(50) DEFAULT 'daily_coffee'
);

CREATE INDEX IF NOT EXISTS idx_coffee_perks_user ON coffee_perks(user_id, claimed_at);

-- Migration complete marker
INSERT INTO migrations (version, applied_at, description) 
VALUES ('v1.01', NOW(), 'Barista Specialist rebrand, Bin Weight Sensors, GPS validation')
ON CONFLICT (version) DO NOTHING;

-- ============================================
-- END OF MIGRATION
-- ============================================
