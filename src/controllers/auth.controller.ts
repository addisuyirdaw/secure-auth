import { Request, Response } from 'express';
import { prisma } from '../config/database';
import { PasswordService } from '../services/password.service';
import { TokenService } from '../services/token.service';
import { RiskEngine } from '../services/riskEngine.service';
import { SessionService } from '../services/session.service';
import { EmailService } from '../services/email.service';
import { env } from '../config/env';
import { GeoService } from '../utils/geo';
import { z } from 'zod';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

function getClientMeta(req: Request) {
  const ip = (req.headers['x-client-ip'] as string) || req.ip || 'unknown';
  const cleanIp = ip.startsWith('::ffff:') ? ip.substring(7) : ip;
  return {
    ip: cleanIp,
    userAgent: req.headers['user-agent'] || 'unknown',
    fingerprint: req.headers['x-device-fingerprint'] as string || 'unknown',
    location: (req.headers['x-client-location'] as string) || GeoService.lookupIp(cleanIp),
  };
}

export class AuthController {
  // POST /auth/register
  static async register(req: Request, res: Response) {
    const { email, password } = registerSchema.parse(req.body);
    
    const strength = PasswordService.validateStrength(password);
    if (!strength.valid) {
      return res.status(400).json({
        error: 'Weak password',
        feedback: strength.feedback,
      });
    }

    const existing = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const passwordHash = await PasswordService.hash(password);
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        passwordHash,
      },
    });

    // Auto-login after registration
    const accessToken = TokenService.generateAccessToken(user.id, user.email);
    const rawRefresh = TokenService.generateRefreshToken();
    const meta = getClientMeta(req);
    const session = await TokenService.createRefreshTokenSession(user.id, rawRefresh, {
      ...meta,
      deviceName: meta.userAgent,
    });

    res.cookie('refreshToken', rawRefresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
      user: { id: user.id, email: user.email },
      accessToken,
      sessionId: session.id,
    });
  }

  // POST /auth/login
  static async login(req: Request, res: Response) {
    const { email, password } = loginSchema.parse(req.body);
    const incrementBF = (req as any).__incrementBruteForce;

    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user || !user.passwordHash) {
      await incrementBF(false);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await PasswordService.verify(password, user.passwordHash);
    if (!valid) {
      await incrementBF(false);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await incrementBF(true); // Reset brute force counter on success

    const meta = getClientMeta(req);

    // Risk assessment
    const risk = await RiskEngine.assessRisk({
      userId: user.id,
      ip: meta.ip,
      userAgent: meta.userAgent,
      fingerprint: meta.fingerprint,
      location: meta.location,
      timestamp: new Date(),
    });

    if (risk.action === 'block') {
      await EmailService.sendSecurityAlert(user.email, 'Blocked suspicious login', {
        ip: meta.ip,
        location: meta.location,
      });
      return res.status(403).json({ error: 'Login blocked due to suspicious activity. Check your email.' });
    }

    if (risk.action === 'challenge') {
      // In production: send email verification code or push MFA
      // For this implementation, we allow but notify
      await EmailService.sendSecurityAlert(user.email, 'Suspicious login detected', {
        ip: meta.ip,
        location: meta.location,
        triggers: risk.triggers,
      });
    }

    // Register/update device
    await RiskEngine.registerDevice(user.id, meta.fingerprint, meta.userAgent);

    const accessToken = TokenService.generateAccessToken(user.id, user.email);
    const rawRefresh = TokenService.generateRefreshToken();
    const session = await TokenService.createRefreshTokenSession(user.id, rawRefresh, {
      ...meta,
      deviceName: meta.userAgent,
    });

    res.cookie('refreshToken', rawRefresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      user: { id: user.id, email: user.email },
      accessToken,
      sessionId: session.id,
      risk: risk.action !== 'allow' ? { level: risk.action, triggers: risk.triggers } : undefined,
    });
  }

  // POST /auth/refresh
  static async refresh(req: Request, res: Response) {
    const rawToken = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!rawToken) return res.status(401).json({ error: 'No refresh token' });

    const session = await TokenService.verifyRefreshToken(rawToken);
    if (!session) return res.status(401).json({ error: 'Invalid or expired session' });

    // Rotate refresh token
    await TokenService.revokeToken(
      require('crypto').createHash('sha256').update(rawToken).digest('hex')
    );

    const newAccess = TokenService.generateAccessToken(session.userId, session.user.email);
    const newRefresh = TokenService.generateRefreshToken();
    const meta = getClientMeta(req);
    const newSession = await TokenService.createRefreshTokenSession(session.userId, newRefresh, {
      ...meta,
      deviceName: meta.userAgent,
    });

    res.cookie('refreshToken', newRefresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.json({ accessToken: newAccess, sessionId: newSession.id });
  }

  // POST /auth/logout
  static async logout(req: Request, res: Response) {
    const rawToken = req.cookies?.refreshToken;
    if (rawToken) {
      const hash = require('crypto').createHash('sha256').update(rawToken).digest('hex');
      await TokenService.revokeToken(hash);
    }
    res.clearCookie('refreshToken');
    return res.json({ message: 'Logged out' });
  }

  // GET /auth/sessions
  static async listSessions(req: Request, res: Response) {
    const userId = (req as any).user.userId;
    const sessions = await SessionService.getActiveSessions(userId);
    return res.json({ sessions });
  }

  // DELETE /auth/sessions/:id
  static async revokeSession(req: Request, res: Response) {
    const userId = (req as any).user.userId;
    const { id } = req.params;
    await SessionService.revokeSession(id, userId);
    return res.json({ message: 'Session revoked' });
  }

  // DELETE /auth/sessions/others
  static async revokeOtherSessions(req: Request, res: Response) {
    const userId = (req as any).user.userId;
    const currentSessionId = req.headers['x-session-id'] as string;
    await SessionService.revokeOtherSessions(userId, currentSessionId);
    return res.json({ message: 'Other sessions revoked' });
  }

  // GET /auth/google
  static googleAuth(req: Request, res: Response) {
    const scope = encodeURIComponent('openid email profile');
    const redirectUri = encodeURIComponent(env.GOOGLE_CALLBACK_URL);
    const clientId = encodeURIComponent(env.GOOGLE_CLIENT_ID);
    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}&access_type=offline&prompt=consent`;
    
    return res.redirect(googleAuthUrl);
  }

  // GET /auth/google/callback
  static async googleCallback(req: Request, res: Response) {
    const { code, error } = req.query;

    if (error) {
      console.error('Google login error:', error);
      return res.redirect('/?error=' + encodeURIComponent(error.toString()));
    }

    if (!code) {
      return res.status(400).json({ error: 'No code returned from Google' });
    }

    try {
      const tokenRes = await globalThis.fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code: code.toString(),
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: env.GOOGLE_CALLBACK_URL,
          grant_type: 'authorization_code',
        }).toString(),
      });

      if (!tokenRes.ok) {
        const errorText = await tokenRes.text();
        console.error('Token exchange failed:', errorText);
        throw new Error('Google OAuth token exchange failed');
      }

      const tokens = await tokenRes.json() as any;
      const { access_token } = tokens;

      const profileRes = await globalThis.fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${access_token}` },
      });

      if (!profileRes.ok) {
        throw new Error('Failed to retrieve user profile from Google');
      }

      const profile = await profileRes.json() as any;
      const { email, sub: googleId } = profile;

      if (!email) {
        return res.status(400).json({ error: 'Email not provided by Google' });
      }

      let user = await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
      });

      if (user) {
        if (!user.googleId) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: { googleId, emailVerified: true },
          });
        }
      } else {
        user = await prisma.user.create({
          data: {
            email: email.toLowerCase(),
            googleId,
            emailVerified: true,
          },
        });
      }

      const meta = getClientMeta(req);
      const accessToken = TokenService.generateAccessToken(user.id, user.email);
      const rawRefresh = TokenService.generateRefreshToken();
      const session = await TokenService.createRefreshTokenSession(user.id, rawRefresh, {
        ...meta,
        deviceName: meta.userAgent,
      });

      res.cookie('refreshToken', rawRefresh, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000,
      });

      const redirectUrl = `/?accessToken=${accessToken}&sessionId=${session.id}&email=${encodeURIComponent(user.email)}`;
      return res.redirect(redirectUrl);
    } catch (err: any) {
      console.error('Google callback error:', err);
      return res.redirect('/?error=' + encodeURIComponent(err.message || 'OAuth failed'));
    }
  }

  // GET /auth/debug/emails
  static getDebugEmails(req: Request, res: Response) {
    const emails = EmailService.getSentEmails();
    return res.json({ emails });
  }

  // POST /auth/password-strength
  static checkPasswordStrength(req: Request, res: Response) {
    const { password } = req.body;
    if (password === undefined) return res.status(400).json({ error: 'Password required' });
    const strength = PasswordService.validateStrength(password);
    return res.json(strength);
  }

  // POST /auth/debug/generate-session
  static async generateDebugSession(req: Request, res: Response) {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    let user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (!user) {
      const passwordHash = await PasswordService.hash(password);
      user = await prisma.user.create({
        data: { email: email.toLowerCase(), passwordHash }
      });
    }

    const meta = getClientMeta(req);
    const rawRefresh = TokenService.generateRefreshToken();
    const session = await TokenService.createRefreshTokenSession(user.id, rawRefresh, {
      ...meta,
      deviceName: meta.userAgent,
    });

    return res.json({
      refreshToken: rawRefresh,
      sessionId: session.id,
      email: user.email,
    });
  }

  // GET /auth/events
  static async listEvents(req: Request, res: Response) {
    const userId = (req as any).user.userId;
    const events = await prisma.securityEvent.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
    return res.json({ events });
  }

  // POST /auth/debug/reset-lockout
  static async resetLockout(req: Request, res: Response) {
    const rawIp = (req.headers['x-client-ip'] as string) || req.ip || 'unknown';
    const ip = rawIp.startsWith('::ffff:') ? rawIp.substring(7) : rawIp;
    const email = req.body.email?.toLowerCase() || 'unknown';

    const ipKey = `bf:ip:${ip}`;
    const emailKey = `bf:email:${email}`;

    const { redis } = require('../config/redis');
    await Promise.all([
      redis.del(ipKey),
      redis.del(emailKey)
    ]);

    console.log(`🔓 [DEBUG] Resetted brute-force lockout keys for IP: ${ip}, Email: ${email}`);
    return res.json({ message: 'Lockout reset successfully', ip, email });
  }
}