import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { bruteForceLimiter, apiRateLimiter } from '../middleware/rateLimit';
import { authenticate } from '../middleware/authenticate';
import { asyncHandler } from '../utils/asyncHandler';

const router = Router();

router.post('/register', apiRateLimiter, asyncHandler(AuthController.register));
router.post('/login', apiRateLimiter, bruteForceLimiter, asyncHandler(AuthController.login));
router.post('/refresh', asyncHandler(AuthController.refresh));
router.post('/logout', asyncHandler(AuthController.logout));

// Google OAuth routes
router.get('/google', AuthController.googleAuth);
router.get('/google/callback', asyncHandler(AuthController.googleCallback));

// Password validation endpoint
router.post('/password-strength', AuthController.checkPasswordStrength);

// Debug/testing endpoints
router.get('/debug/emails', AuthController.getDebugEmails);
router.post('/debug/generate-session', asyncHandler(AuthController.generateDebugSession));
router.post('/debug/reset-lockout', asyncHandler(AuthController.resetLockout));

// Protected routes
router.get('/sessions', authenticate, asyncHandler(AuthController.listSessions));
router.delete('/sessions/:id', authenticate, asyncHandler(AuthController.revokeSession));
router.delete('/sessions/others', authenticate, asyncHandler(AuthController.revokeOtherSessions));
router.get('/events', authenticate, asyncHandler(AuthController.listEvents));

export default router;