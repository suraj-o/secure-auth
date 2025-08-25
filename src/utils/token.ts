import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { randomUUID } from 'crypto';
import ms from 'ms';
import { config } from '../config';

const enc = new TextEncoder();

export interface AccessPayload extends JWTPayload {
  sub: string;
  jti: string;
  kind: 'access';
}

export interface RefreshPayload extends JWTPayload {
  sub: string;
  jti: string;
  familyId: string;
  kind: 'refresh';
}

export async function signAccessToken(userId: string, jti = randomUUID()) {
  const ttlMs = ms(Number(config.accessTtl));
  return new SignJWT({ sub: userId, jti, kind: 'access' } as AccessPayload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(Math.floor((Date.now() + ttlMs) / 1000))
    .sign(enc.encode(config.accessSecret));
}

export async function signRefreshToken(userId: string, familyId: string, jti = randomUUID()) {
  const ttlMs = ms(Number(config.refreshTtl));
  return new SignJWT({ sub: userId, jti, familyId, kind: 'refresh' } as RefreshPayload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(Math.floor((Date.now() + ttlMs) / 1000))
    .sign(enc.encode(config.refreshSecret));
}

export async function verifyAccess(token: string) {
  const { payload } = await jwtVerify(token, enc.encode(config.accessSecret));
  if (payload.kind !== 'access') throw new Error('Invalid token kind');
  return payload as AccessPayload;
}

export async function verifyRefresh(token: string) {
  const { payload } = await jwtVerify(token, enc.encode(config.refreshSecret));
  if (payload.kind !== 'refresh') throw new Error('Invalid token kind');
  return payload as RefreshPayload;
}
