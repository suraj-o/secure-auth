import argon2 from 'argon2';
import ms from 'ms';
import { randomUUID } from 'crypto';
import { User } from '../models/User';
import { signAccessToken, signRefreshToken, verifyRefresh } from '../utils/tokens';
import { redis } from '../redis';
import { config } from '../config';

function cookieOptions() {
  return {
    httpOnly: true,
    secure: config.nodeEnv === 'production',
    sameSite: 'strict' as const,
    domain: config.cookieDomain,
    path: '/api/auth/refresh',
    maxAge: ms(config.refreshTtl)
  };
}

export async function issueNewTokens(
  userId: string,
  familyId?: string,
  ip?: string,
  userAgent?: string
) {
  const jti = randomUUID();
  const fam = familyId || randomUUID();
  const [access, refresh] = await Promise.all([
    signAccessToken(userId),
    signRefreshToken(userId, fam, jti),
  ]);

  const payload = await verifyRefresh(refresh);
  const expiresAt = new Date((payload.exp as number) * 1000);
  const hashed = await argon2.hash(refresh);

  await User.updateOne({ _id: userId }, {
    $push: {
      refreshTokens: {
        jti,
        familyId: fam,
        hashedToken: hashed,
        createdAt: new Date(),
        expiresAt,
        ip,
        userAgent
      },
    },
  });

  return { access, refresh, jti, familyId: fam, cookie: cookieOptions() };
}

export async function rotateRefresh(oldToken: string, ip?: string, userAgent?: string) {
  const payload = await verifyRefresh(oldToken);
  const user = await User.findById(payload.sub).lean();
  if (!user) throw new Error('User not found');

  // Find active record for presented token
  const record = user.refreshTokens.find(r => r.jti === payload.jti && !r.revokedAt);

  // Reuse detection: if token not present/active -> revoke whole family
  if (!record) {
    await User.updateOne({ _id: payload.sub }, {
      $set: { 'refreshTokens.$[elem].revokedAt': new Date() }
    }, { arrayFilters: [{ 'elem.familyId': payload.familyId, 'elem.revokedAt': { $exists: false } }] });
    throw new Error('Refresh token reuse detected; family revoked');
  }

  // Rotate
  const newJti = randomUUID();
  const [newAccess, newRefresh] = await Promise.all([
    signAccessToken(payload.sub),
    signRefreshToken(payload.sub, payload.familyId, newJti),
  ]);
  const newPayload = await verifyRefresh(newRefresh);
  const hashed = await argon2.hash(newRefresh);

  await User.updateOne({ _id: payload.sub, 'refreshTokens.jti': payload.jti }, {
    $set: { 'refreshTokens.$.revokedAt': new Date(), 'refreshTokens.$.replacedBy': newJti },
    $push: {
      refreshTokens: {
        jti: newJti,
        familyId: payload.familyId,
        hashedToken: hashed,
        createdAt: new Date(),
        expiresAt: new Date((newPayload.exp as number) * 1000),
        ip, userAgent
      },
    },
  });

  return { access: newAccess, refresh: newRefresh };
}

export async function revokeCurrentRefresh(rawRefresh: string) {
  try {
    const payload = await verifyRefresh(rawRefresh);
    await User.updateOne({ _id: payload.sub, 'refreshTokens.jti': payload.jti }, {
      $set: { 'refreshTokens.$.revokedAt': new Date() },
    });
  } catch {
    // swallow
  }
}

export async function revokeFamilyByToken(rawRefresh: string) {
  const p = await verifyRefresh(rawRefresh);
  await User.updateOne({ _id: p.sub }, {
    $set: { 'refreshTokens.$[elem].revokedAt': new Date() }
  }, { arrayFilters: [{ 'elem.familyId': p.familyId, 'elem.revokedAt': { $exists: false } }] });
}

export async function blacklistAccessJti(jti: string, expSecondsFromNow: number) {
  await redis.set(`blacklist:access:${jti}`, '1', 'EX', expSecondsFromNow);
}
