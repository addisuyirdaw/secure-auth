import { Request, Response, NextFunction } from 'express';
import { redis } from '../config/redis';
import { prisma } from '../config/database';

const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;

export const bruteForceLimiter = async (req: Request, res: Response, next: NextFunction) => {
  const rawIp = (req.headers['x-client-ip'] as string) || req.ip || 'unknown';
  const ip = rawIp.startsWith('::ffff:') ? rawIp.substring(7) : rawIp;
  const email = req.body.email?.toLowerCase() || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const ipKey = `bf:ip:${ip}`;
  const emailKey = `bf:email:${email}`;

  // Check if already locked out
  const [ipCount, emailCount] = await Promise.all([
    redis.get(ipKey),
    redis.get(emailKey),
  ]);

  const attempts = Math.max(parseInt(ipCount || '0', 10), parseInt(emailCount || '0', 10));

  if (attempts >= MAX_ATTEMPTS) {
    const ttl = await redis.ttl(ipKey);

    // Log the locked attempt
    await Promise.all([
      prisma.loginAttempt.create({
        data: { email, ipAddress: ip, userAgent, success: false }
      }),
      prisma.securityEvent.create({
        data: {
          type: 'BRUTE_FORCE_LOCKOUT',
          ipAddress: ip,
          userAgent,
          location: (req.headers['x-client-location'] as string) || 'Unknown',
          details: JSON.stringify({
            message: `Rate limit hit. Login attempt blocked for email: ${email}`,
            attempts,
            windowMs: WINDOW_MS,
          }),
        }
      })
    ]);

    return res.status(429).json({
      error: 'Too many login attempts. Account temporarily locked.',
      retryAfter: ttl,
    });
  }

  // Attach increment helper to response for use after authentication
  (req as any).__incrementBruteForce = async (success: boolean) => {
    // Log attempt in database
    await prisma.loginAttempt.create({
      data: { email, ipAddress: ip, userAgent, success }
    });

    if (success) {
      await redis.del(ipKey);
      await redis.del(emailKey);
    } else {
      const pipeline = redis.pipeline();
      pipeline.incr(ipKey);
      pipeline.expire(ipKey, WINDOW_MS / 1000);
      pipeline.incr(emailKey);
      pipeline.expire(emailKey, WINDOW_MS / 1000);
      const results = await pipeline.exec();

      const newAttempts = Math.max(
        parseInt(results[0]?.[1] || '0', 10),
        parseInt(results[2]?.[1] || '0', 10)
      );

      // If they just hit the lockout threshold
      if (newAttempts >= MAX_ATTEMPTS) {
        await prisma.securityEvent.create({
          data: {
            type: 'BRUTE_FORCE_LOCKOUT',
            ipAddress: ip,
            userAgent,
            location: (req.headers['x-client-location'] as string) || 'Unknown',
            details: JSON.stringify({
              message: `Lockout triggered for email: ${email}`,
              attempts: newAttempts,
            }),
          }
        });
      }
    }
  };

  next();
};

// General API rate limiter
export const apiRateLimiter = async (req: Request, res: Response, next: NextFunction) => {
  const rawIp = (req.headers['x-client-ip'] as string) || req.ip || 'unknown';
  const ip = rawIp.startsWith('::ffff:') ? rawIp.substring(7) : rawIp;
  const key = `ratelimit:api:${ip}`;
  const limit = 100; // requests per window
  const window = 60; // seconds

  const current = await redis.incr(key);
  if (current === 1) await redis.expire(key, window);

  if (current > limit) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }
  next();
};