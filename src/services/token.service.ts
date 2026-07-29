import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { prisma } from '../config/database';
import { env } from '../config/env';

export interface TokenPayload {
  userId: string;
  email: string;
  type: 'access' | 'refresh';
}

export class TokenService {
  static generateAccessToken(userId: string, email: string): string {
    return jwt.sign({ userId, email, type: 'access' }, env.JWT_ACCESS_SECRET as jwt.Secret, {
      expiresIn: env.JWT_ACCESS_EXPIRY as any,
      issuer: 'identity-system',
      audience: 'identity-system',
    });
  }

  static generateRefreshToken(): string {
    return crypto.randomBytes(64).toString('hex');
  }

  static async createRefreshTokenSession(
    userId: string,
    rawToken: string,
    meta: { ip: string; userAgent: string; fingerprint?: string; deviceName?: string; location?: string }
  ) {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + parseInt(env.REFRESH_TOKEN_EXPIRY_DAYS));

    return prisma.refreshToken.create({
      data: {
        userId,
        tokenHash,
        ipAddress: meta.ip,
        deviceName: meta.deviceName,
        fingerprint: meta.fingerprint,
        location: meta.location,
        expiresAt,
      },
    });
  }

  static async verifyRefreshToken(rawToken: string) {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const session = await prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!session) {
      return null;
    }

    if (session.revokedAt) {
      console.warn(`⚠️ Token reuse detected for user ${session.userId}! Revoking all sessions.`);
      await Promise.all([
        this.revokeAllUserTokens(session.userId),
        prisma.securityEvent.create({
          data: {
            userId: session.userId,
            type: 'SUSPICIOUS_TOKEN_REUSE',
            ipAddress: session.ipAddress,
            userAgent: 'system',
            location: session.location || 'Unknown',
            details: JSON.stringify({
              message: 'A previously revoked refresh token was reused. Potential token theft.',
              revokedTokenHash: tokenHash,
              revokedAt: session.revokedAt,
            }),
          },
        }),
      ]);
      return null;
    }

    if (session.expiresAt < new Date()) {
      return null;
    }

    // Rotate: update last used, but we issue a new token on refresh
    await prisma.refreshToken.update({
      where: { id: session.id },
      data: { lastUsedAt: new Date() },
    });

    return session;
  }

  static async revokeToken(tokenHash: string) {
    await prisma.refreshToken.updateMany({
      where: { tokenHash },
      data: { revokedAt: new Date() },
    });
  }

  static async revokeAllUserTokens(userId: string, exceptId?: string) {
    await prisma.refreshToken.updateMany({
      where: {
        userId,
        revokedAt: null,
        ...(exceptId ? { NOT: { id: exceptId } } : {}),
      },
      data: { revokedAt: new Date() },
    });
  }
}