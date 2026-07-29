import { prisma } from '../config/database';

export class SessionService {
  static async getActiveSessions(userId: string) {
    const sessions = await prisma.refreshToken.findMany({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { lastUsedAt: 'desc' },
      select: {
        id: true,
        deviceName: true,
        ipAddress: true,
        location: true,
        createdAt: true,
        lastUsedAt: true,
      },
    });
    return sessions;
  }

  static async revokeSession(sessionId: string, userId: string) {
    const session = await prisma.refreshToken.findFirst({
      where: { id: sessionId, userId },
    });
    if (!session) {
      const err: any = new Error('Session not found');
      err.status = 404;
      throw err;
    }

    await prisma.refreshToken.update({
      where: { id: sessionId },
      data: { revokedAt: new Date() },
    });
  }

  static async revokeOtherSessions(userId: string, currentSessionId: string) {
    await prisma.refreshToken.updateMany({
      where: {
        userId,
        revokedAt: null,
        NOT: { id: currentSessionId },
      },
      data: { revokedAt: new Date() },
    });
  }
}