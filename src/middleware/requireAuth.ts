import { Request, Response, NextFunction } from 'express';
import { verifyAccess } from '../utils/token';
import { redis } from '../redis';

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const auth = req.header('authorization');
    if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing Bearer token' });
    const token = auth.slice('Bearer '.length);
    const payload = await verifyAccess(token);
    const blacklisted = await redis.get(`blacklist:access:${payload.jti}`);
    if (blacklisted) return res.status(401).json({ error: 'Token revoked' });
    (req as any).user = { id: payload.sub, jti: payload.jti, exp: payload.exp };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid/expired token' });
  }
}
