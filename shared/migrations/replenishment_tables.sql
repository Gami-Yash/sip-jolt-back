-- Replenishment System v1.01 - Database Schema
-- Machine bin monitoring for automated stock alerts

-- 1. Replenishment Settings (Per-Ingredient Config)
CREATE TABLE IF NOT EXISTS replenishment_settings (
  id SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  ingredient_name TEXT NOT NULL,
  yile_store_type TEXT,
  
  warning_threshold INTEGER DEFAULT 30,
  critical_threshold INTEGER DEFAULT 15,
  target_level INTEGER DEFAULT 90,
  
  container_type TEXT DEFAULT 'bag',
  container_size_grams INTEGER,
  
  monitoring_enabled BOOLEAN DEFAULT TRUE,
  
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  UNIQUE(device_id, ingredient_name)
);

-- 2. Inventory Snapshots (Yile API Polling History)
CREATE TABLE IF NOT EXISTS inventory_snapshots (
  id SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  ingredient_name TEXT NOT NULL,
  
  current_grams INTEGER NOT NULL,
  max_capacity_grams INTEGER NOT NULL,
  percent_full DECIMAL(5,2) NOT NULL,
  
  grams_consumed_since_last INTEGER,
  hours_since_last DECIMAL(5,2),
  consumption_rate_per_day DECIMAL(8,2),
  
  snapshot_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_snapshots_device_ingredient ON inventory_snapshots (device_id, ingredient_name);
CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON inventory_snapshots (snapshot_timestamp);

-- 3. Refill Alerts
CREATE TABLE IF NOT EXISTS refill_alerts (
  id SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  ingredient_name TEXT NOT NULL,
  
  alert_level TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  
  percent_when_triggered INTEGER,
  grams_when_triggered INTEGER,
  estimated_days_remaining DECIMAL(5,2),
  
  flagged_for_visit_id INTEGER,
  urgent_task_created BOOLEAN DEFAULT FALSE,
  
  resolved_at TIMESTAMP,
  resolved_by_snapshot_id INTEGER,
  
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_active ON refill_alerts (device_id, status);

-- Insert default settings for known device
INSERT INTO replenishment_settings (device_id, ingredient_name, warning_threshold, critical_threshold, target_level, container_type, container_size_grams)
VALUES 
  ('00000020868', 'Coffee Beans', 30, 15, 90, 'bag', 1000),
  ('00000020868', 'Oat Milk', 30, 15, 90, 'jug', 2000),
  ('00000020868', 'Cups', 25, 10, 95, 'sleeve', 50)
ON CONFLICT (device_id, ingredient_name) DO NOTHING;
