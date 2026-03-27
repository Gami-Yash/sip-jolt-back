const store = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, record] of store.entries()) {
    if (record.resetAt < now) {
      store.delete(key);
    }
  }
}, 5 * 60 * 1000);

function checkRateLimit(key, config) {
  const now = Date.now();
  const record = store.get(key);

  if (!record || record.resetAt < now) {
    const resetAt = now + config.windowMs;
    store.set(key, { count: 1, resetAt });
    return {
      allowed: true,
      remaining: config.maxRequests - 1,
      resetAt,
      retryAfterSeconds: 0,
    };
  }

  if (record.count < config.maxRequests) {
    record.count++;
    return {
      allowed: true,
      remaining: config.maxRequests - record.count,
      resetAt: record.resetAt,
      retryAfterSeconds: 0,
    };
  }

  const retryAfterSeconds = Math.ceil((record.resetAt - now) / 1000);
  return {
    allowed: false,
    remaining: 0,
    resetAt: record.resetAt,
    retryAfterSeconds,
  };
}

function defaultKeyGenerator(req) {
  const userId = req.user?.id || req.session?.userId;
  if (userId) return `user:${userId}`;
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.connection?.remoteAddress || 'unknown';
  return `ip:${ip}`;
}

function ipOnlyKeyGenerator(req) {
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.connection?.remoteAddress || 'unknown';
  return `ip:${ip}`;
}

function userIdKeyGenerator(req) {
  const userId = req.user?.id || req.session?.userId || req.body?.userId || 'anonymous';
  return `user:${userId}`;
}

export function createRateLimiter(config = {}) {
  const finalConfig = {
    windowMs: 60 * 1000,
    maxRequests: 100,
    keyGenerator: defaultKeyGenerator,
    message: 'Too many requests. Please try again later.',
    statusCode: 429,
    headers: true,
    ...config,
  };

  return function rateLimitMiddleware(req, res, next) {
    const key = finalConfig.keyGenerator(req);
    const result = checkRateLimit(key, finalConfig);

    if (finalConfig.headers) {
      res.setHeader('X-RateLimit-Limit', finalConfig.maxRequests);
      res.setHeader('X-RateLimit-Remaining', result.remaining);
      res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetAt / 1000));
    }

    if (!result.allowed) {
      res.setHeader('Retry-After', result.retryAfterSeconds);
      console.warn(`[RATE_LIMIT] Exceeded for key: ${key}`);
      return res.status(finalConfig.statusCode).json({
        success: false,
        error: finalConfig.message,
        retryAfter: result.retryAfterSeconds,
      });
    }

    next();
  };
}

export const loginLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 5,
  keyGenerator: ipOnlyKeyGenerator,
  message: 'Too many login attempts. Please wait 1 minute.',
});

export const uploadLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 20,
  keyGenerator: userIdKeyGenerator,
  message: 'Upload limit reached. Please wait before uploading more.',
});

export const exportLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000,
  maxRequests: 10,
  keyGenerator: userIdKeyGenerator,
  message: 'Export limit reached. Please wait before exporting more.',
});

export const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 100,
  keyGenerator: defaultKeyGenerator,
  message: 'API rate limit exceeded. Please slow down.',
});

export const aiChatLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 20,
  keyGenerator: userIdKeyGenerator,
  message: 'AI chat limit reached. Please wait before sending more messages.',
});

export const strictLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 3,
  keyGenerator: userIdKeyGenerator,
  message: 'Operation limit reached. Please wait.',
});

export function checkLimit(key, windowMs, maxRequests) {
  return checkRateLimit(key, { windowMs, maxRequests });
}

export function resetLimit(key) {
  store.delete(key);
}
