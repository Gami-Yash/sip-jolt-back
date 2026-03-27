import 'dotenv/config';
import express from "express";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import apiRouter from "./shared/api.js";
import opsApiRouter from "./shared/api-ops.js";
import authApiRouter from "./shared/api-auth.js";
import metricsApiRouter from "./shared/api-metrics.js";
import adminApiRouter from "./shared/api-admin.js";
import landlordApiRouter from "./shared/api-landlord.js";
import exceptionQueueRouter from "./shared/api-exception-queue.js";
import kpiDashboardRouter from "./shared/api-kpi-dashboard.js";
import consequenceApiRouter from "./shared/api-consequence.js";
import v1_00ApiRouter from "./shared/api-v1.00.js";
import neuralCoreRouter from "./server/api-neural-core.js";
import boxesRouter from "./server/routes/boxes.js";
import ghostDeliveryRouter from "./server/routes/ghostDelivery.js";
import labelGeneratorRouter from "./server/routes/labelGenerator.js";
import gamificationRouter from "./server/routes/gamification.js";
import sensorRouter from "./server/routes/sensors.js";
import yileTechnicianRouter from "./server/routes/yileTechnician.js";
import yileAdminRouter from "./server/routes/yileAdmin.js";
import yileRouter from "./server/routes/yile.js";
import recipeTemplatesRouter from "./server/routes/recipes/templates.js";
import fleetRouter from "./server/routes/fleetRoutes.js";
import replenishmentRouter from "./server/routes/replenishmentRoutes.js";
import remoteRouter from "./server/routes/remoteRoutes.js";
import { startWatchdogInterval } from "./shared/watchdog.js";
import { initDatabase } from "./shared/migrate.js";
import { registerObjectStorageRoutes } from "./server/replit_integrations/object_storage/index.js";
import {
  securityHeaders,
  removeDevBypasses,
} from "./shared/production-hardening.js";
import { setupRLSPolicies } from "./shared/rls-middleware.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
// Use PORT from env when provided so we can run the API
// alongside the Vite dev server without port conflicts.
const PORT = process.env.PORT ? Number(process.env.PORT) : 5001;

// Basic request logging to help diagnose API issues in development
app.use((req, res, next) => {
  console.log(`[HTTP] ${req.method} ${req.url}`);
  next();
});

// Initialize database tables on startup
initDatabase()
  .then(() => {
    setupRLSPolicies().catch((err) => {
      console.warn("RLS setup note:", err.message);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database:", err);
  });

// Parse JSON bodies
app.use(express.json({ limit: "50mb" }));

// Production security middleware
app.use(securityHeaders);
app.use(removeDevBypasses);

// Security headers for production
app.use((req, res, next) => {
  const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  const requestOrigin = req.headers.origin;

  if (allowedOrigins.length === 0) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS",
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-User-Id, X-User-Name, X-User-Role, X-Tenant-Id, X-Session-Token",
  );

  // Proper MIME types
  if (req.path.endsWith(".js")) {
    res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  } else if (req.path.endsWith(".css")) {
    res.setHeader("Content-Type", "text/css; charset=utf-8");
  } else if (req.path.endsWith(".html")) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
  }

  // Cache control for static assets
  if (req.path.includes("/assets/")) {
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  } else {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  }

  next();
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    server_utc_now: new Date().toISOString(),
    version: "v1.00",
  });
});

// v1.01 Recipe Builder Templates API (Specific route FIRST)
app.use("/api/v1.01/recipes/templates", recipeTemplatesRouter);

// API routes
app.use("/api", apiRouter);

// Auth API routes (new secure authentication)
app.use("/api/auth", authApiRouter);

// Supply Closet Ops API routes
app.use("/api/ops", opsApiRouter);

// Metrics and monitoring API routes (Phase 2.5)
app.use("/api/metrics", metricsApiRouter);

// Admin API routes (Phase 5 - Production Hardening)
app.use("/api/admin", adminApiRouter);

// Landlord viewer portal (read-only, tenant-scoped)
app.use("/api/landlord", landlordApiRouter);

// Ops Exception Queue
app.use("/api/exceptions", exceptionQueueRouter);

// KPI Dashboard + Training Flags
app.use("/api/kpi", kpiDashboardRouter);

// Consequence Engine + A50 Squeeze Gate + Feature Flags (Plan 1)
app.use("/api/consequence", consequenceApiRouter);

// v1.00 SIPJOLT OS routes (machine config, recovery, reliability)
app.use("/api/v1.00", v1_00ApiRouter);

// Neural Core AI routes (v1.00)
app.use("/api/ai", neuralCoreRouter);

// v1.00 5-Gate QC Packing System and Ghost Delivery
app.use("/api/v1.00/boxes", boxesRouter);
app.use("/api/v1.00/ghost", ghostDeliveryRouter);

// Label Generator (Puppeteer-based 4x6 label generation)
app.use("/api/label-generator", labelGeneratorRouter);

// v1.00 Premium Gamification (Lucky Spin, Leaderboard, Vacation Jackpot)
app.use("/api/v1.00/gamification", gamificationRouter);

// v1.01 Sensor API (Bin Weight Sensors)
app.use("/api/v1.01/sensors", sensorRouter);

// v1.01 Yile Coffee Machine Technician API
app.use("/api/v1.01/yile-tech", yileTechnicianRouter);

// v1.01 Yile Admin/Diagnostic API
app.use("/api/v1.01/yile-admin", yileAdminRouter);

// v1.01 Yile Unified API (Official V5.3 endpoints)
app.use("/api/v1.01/yile", yileRouter);

// v1.01 Fleet Dashboard API (Yile-powered device monitoring)
app.use("/api/v1.01/fleet", fleetRouter);

// v1.01 Replenishment System (Machine bin monitoring)
app.use("/api/v1.01/replenishment", replenishmentRouter);

// v1.01 Remote Operations API
app.use("/api/v1.01/remote", remoteRouter);

console.log("Recipe Builder routes mounted");
console.log("Fleet Dashboard routes mounted");
console.log("Replenishment System routes mounted");

// Start watchdog cron job (hourly for pilot)
startWatchdogInterval(60);

// Object storage routes for file uploads
registerObjectStorageRoutes(app);

// Serve static files from public folder (for assets not in dist)
app.use(express.static(join(__dirname, "../frontend/public")));

// Serve static files from dist folder with proper MIME types
app.use(
  express.static(join(__dirname, "../dist"), {
    setHeaders: (res, path) => {
      if (path.endsWith(".js")) {
        res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      }
    },
  }),
);

// Global error handler to surface uncaught errors in logs instead of silent 500s
app.use((err, req, res, next) => {
  console.error("[Express Error]", err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: "Internal server error", details: err?.message });
});

// Fallback to index.html for SPA routing
app.use((req, res) => {
  res.sendFile(join(__dirname, "../dist", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  console.log(`API endpoints available at http://0.0.0.0:${PORT}/api`);
});


