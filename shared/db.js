import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import * as schema from './schema.js';
import ws from 'ws';

neonConfig.webSocketConstructor = ws;

let _pool = null;
let _db = null;

function getDatabaseUrl() {
  let databaseUrl = process.env.DATABASE_URL;
  
  if (!databaseUrl) {
    console.error('[DB] DATABASE_URL environment variable is not set');
    throw new Error('DATABASE_URL must be set. Did you forget to provision a database?');
  }
  
  return databaseUrl;
}

export function getPool() {
  if (!_pool) {
    const databaseUrl = getDatabaseUrl();
    _pool = new Pool({ 
      connectionString: databaseUrl,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 10000,
      max: 5
    });
    
    _pool.on('error', (err) => {
      console.error('[DB] Pool error:', err.message);
      _pool = null;
      _db = null;
    });
    
    console.log('[DB] Neon serverless pool created');
  }
  return _pool;
}

export function getDb() {
  if (!_db) {
    const pool = getPool();
    _db = drizzle(pool, { schema });
    console.log('[DB] Drizzle ORM initialized');
  }
  return _db;
}

export async function checkDatabaseHealth() {
  try {
    const pool = getPool();
    const client = await pool.connect();
    const result = await client.query('SELECT 1 as ok');
    client.release();
    return { healthy: true, message: 'Database connected successfully' };
  } catch (error) {
    console.error('[DB] Health check failed:', error.message);
    _pool = null;
    _db = null;
    return { healthy: false, message: error.message };
  }
}

export const db = new Proxy({}, {
  get(target, prop) {
    const realDb = getDb();
    const value = realDb[prop];
    if (typeof value === 'function') {
      return value.bind(realDb);
    }
    return value;
  }
});

export const pool = new Proxy({}, {
  get(target, prop) {
    return getPool()[prop];
  }
});
