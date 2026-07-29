import { prisma } from '../config/database';

interface LoginContext {
  userId: string;
  ip: string;
  userAgent: string;
  fingerprint: string;
  location: string; // "City, Country"
  timestamp: Date;
}

export type SecurityEventType = 'NEW_DEVICE' | 'NEW_LOCATION' | 'IMPOSSIBLE_TRAVEL' | 'VELOCITY' | 'LOGIN' | 'BRUTE_FORCE_LOCKOUT' | 'SUSPICIOUS_TOKEN_REUSE';

export class RiskEngine {
  static async assessRisk(ctx: LoginContext): Promise<{
    riskScore: number; // 0-100
    triggers: SecurityEventType[];
    action: 'allow' | 'challenge' | 'block';
  }> {
    let score = 0;
    const triggers: SecurityEventType[] = [];

    // 1. New device fingerprint?
    const knownDevice = await prisma.deviceFingerprint.findFirst({
      where: { userId: ctx.userId, fingerprint: ctx.fingerprint },
    });

    if (!knownDevice) {
      score += 25;
      triggers.push('NEW_DEVICE');
    }

    // 2. New location / IP?
    const recentSessions = await prisma.refreshToken.findMany({
      where: {
        userId: ctx.userId,
        revokedAt: null,
      },
      orderBy: { lastUsedAt: 'desc' },
      take: 5,
    });

    const knownIps = new Set(recentSessions.map(s => s.ipAddress));
    if (!knownIps.has(ctx.ip)) {
      score += 20;
      triggers.push('NEW_LOCATION');
    }

    // 3. Impossible travel (simplified: different country within < 2 hours)
    if (recentSessions.length > 0) {
      const lastSession = recentSessions[0];
      const hoursSinceLastLogin = (ctx.timestamp.getTime() - lastSession.lastUsedAt.getTime()) / 36e5;

      if (lastSession.location && lastSession.location !== ctx.location && hoursSinceLastLogin < 2) {
        // Basic check: if locations differ significantly in short time
        score += 40;
        triggers.push('IMPOSSIBLE_TRAVEL');
      }
    }

    // 4. Velocity check: many recent security events
    const recentEvents = await prisma.securityEvent.count({
      where: {
        userId: ctx.userId,
        createdAt: { gte: new Date(Date.now() - 60 * 60 * 1000) }, // last hour
      },
    });
    if (recentEvents > 3) {
      score += 15;
      triggers.push('VELOCITY');
    }

    // Determine action
    let action: 'allow' | 'challenge' | 'block' = 'allow';
    if (score >= 70) action = 'block';
    else if (score >= 30) action = 'challenge';

    // Log the event
    await prisma.securityEvent.create({
      data: {
        userId: ctx.userId,
        type: triggers[0] || 'LOGIN',
        ipAddress: ctx.ip,
        userAgent: ctx.userAgent,
        location: ctx.location,
        details: JSON.stringify({ riskScore: score, triggers }),
      },
    });

    return { riskScore: score, triggers, action };
  }

  static async registerDevice(userId: string, fingerprint: string, name: string) {
    await prisma.deviceFingerprint.upsert({
      where: { fingerprint },
      update: { lastSeenAt: new Date(), name },
      create: { userId, fingerprint, name, trusted: false },
    });
  }
}