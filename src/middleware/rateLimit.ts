import { Request, Response, NextFunction } from 'express';

const hits = new Map<string, { count: number; ts: number }>();

export function tinyRateLimit(limit = 60, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip;
    const now = Date.now();
    const rec = hits.get(key!);
    if (!rec || now - rec.ts > windowMs) {
      hits.set(key!, { count: 1, ts: now });
      return next();
    }
    rec.count += 1;
    if (rec.count > limit) return res.status(429).json({ error: 'Too many requests' });
    next();
  };
}
