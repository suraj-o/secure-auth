import { Router,Response } from 'express';
import { z } from 'zod';
import ms from 'ms';
import { config } from '../config';
import { login, register } from '../services/auth.service';
import { rotateRefresh, revokeCurrentRefresh, revokeFamilyByToken, blacklistAccessJti } from '../services/token.service';
import { verifyAccess, verifyRefresh } from '../utils/token';
import { User } from '../models/User';

import { randomBytes } from 'crypto';
const router = Router();

const credsSchema = z.object({ email: z.string().email(), password: z.string().min(8) });
const csrfCookieName = 'csrf-token';
function newCsrf() { return randomBytes(16).toString('hex'); }

router.post('/register', async (req, res) => {
  try {
    const { email, password } = credsSchema.parse(req.body);
    const { access, refresh, cookie } = await register(email, password, req.ip, req.get('user-agent') || undefined);
    res.cookie(config.cookieName, refresh, cookie);
    res.cookie(csrfCookieName, newCsrf(), { httpOnly: false, sameSite: 'strict', secure: config.nodeEnv==='production', domain: config.cookieDomain, path: '/' });
    res.json({ accessToken: access });
  } catch (e: any) {
    res.status(400).json({ error: e.message || 'Register failed' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = credsSchema.parse(req.body);
    const { access, refresh, cookie } = await login(email, password, req.ip, req.get('user-agent') || undefined);
    res.cookie(config.cookieName, refresh, cookie);
    res.cookie(csrfCookieName, newCsrf(), { httpOnly: false, sameSite: 'strict', secure: config.nodeEnv==='production', domain: config.cookieDomain, path: '/' });
    res.json({ accessToken: access });
  } catch (e: any) {
    res.status(401).json({ error: e.message || 'Login failed' });
  }
});

// Rotating refresh
router.post('/refresh', async (req, res) => {
  try {
    const rt = req.cookies[config.cookieName];
    if (!rt) return res.status(401).json({ error: 'Missing refresh token' });
    const { access, refresh } = await rotateRefresh(rt, req.ip, req.get('user-agent') || undefined);
    res.cookie(config.cookieName, refresh, {
      httpOnly: true,
      secure: config.nodeEnv==='production',
      sameSite: 'strict',
      domain: config.cookieDomain,
      path: '/api/auth/refresh',
      maxAge: Number(ms(config.refreshTtl)),
    });
    res.json({ accessToken: access });
  } catch (e: any) {
    return res.status(401).json({ error: e.message || 'Refresh failed' });
  }
});

// Logout current session (blacklist current access + revoke current refresh)
router.post('/logout', async (req, res) => {
  try {
    const auth = req.header('authorization');
    if (auth?.startsWith('Bearer ')) {
      const at = auth.slice('Bearer '.length);
      const payload = await verifyAccess(at);
      const expMs = (payload.exp as number) * 1000 - Date.now();
      if (expMs > 0) await blacklistAccessJti(payload.jti, Math.ceil(expMs / 1000));
    }
    const rt = req.cookies[config.cookieName];
    if (rt) await revokeCurrentRefresh(rt);
    res.clearCookie(config.cookieName, { domain: config.cookieDomain, path: '/api/auth/refresh' });
    res.status(204).send();
  } catch {
    res.status(204).send();
  }
});

// Logout ALL sessions (revoke entire family)
router.post('/logout-all', async (req, res) => {
  try {
    const rt = req.cookies[config.cookieName];
    if (!rt) return res.status(401).json({ error: 'Missing refresh token' });
    await revokeFamilyByToken(rt);
    res.clearCookie(config.cookieName, { domain: config.cookieDomain, path: '/api/auth/refresh' });
    res.status(204).send();
  } catch (e: any) {
    res.status(401).json({ error: e.message || 'Logout-all failed' });
  }
});

// List active sessions (by family)
router.get('/sessions', async (req, res) => {
  try {
    const rt = req.cookies[config.cookieName];
    if (!rt) return res.status(401).json({ error: 'Missing refresh token' });
    const p = await verifyRefresh(rt);
    const user = await User.findById(p.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const sessions = user.refreshTokens
      .filter(r => r.familyId === p.familyId)
      .map(r => ({
        jti: r.jti,
        createdAt: r.createdAt,
        expiresAt: r.expiresAt,
        revokedAt: r.revokedAt,
        replacedBy: r.replacedBy,
        ip: r.ip,
        userAgent: r.userAgent
      }));

    res.json({ familyId: p.familyId, sessions });
  } catch (e: any) {
    res.status(401).json({ error: e.message || 'Cannot list sessions' });
  }
});

// Revoke a specific session by jti (requires a refresh cookie from same family)
router.delete('/sessions/:jti', async (req, res) => {
  try {
    const rt = req.cookies[config.cookieName];
    if (!rt) return res.status(401).json({ error: 'Missing refresh token' });
    const p = await verifyRefresh(rt);
    const jti = req.params.jti;
    await User.updateOne(
      { _id: p.sub, 'refreshTokens.jti': jti, 'refreshTokens.familyId': p.familyId },
      { $set: { 'refreshTokens.$.revokedAt': new Date() } }
    );
    res.status(204).send();
  } catch (e: any) {
    res.status(400).json({ error: e.message || 'Cannot revoke session' });
  }
});

export default router;
