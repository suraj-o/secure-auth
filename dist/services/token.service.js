"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.issueNewTokens = issueNewTokens;
exports.rotateRefresh = rotateRefresh;
exports.revokeCurrentRefresh = revokeCurrentRefresh;
exports.revokeFamilyByToken = revokeFamilyByToken;
exports.blacklistAccessJti = blacklistAccessJti;
const argon2_1 = __importDefault(require("argon2"));
const ms_1 = __importDefault(require("ms"));
const crypto_1 = require("crypto");
const User_1 = require("../models/User");
const token_1 = require("../utils/token");
const config_1 = require("../config");
const redis_1 = require("../redis");
function cookieOptions() {
    return {
        httpOnly: true,
        secure: config_1.config.nodeEnv === 'production',
        sameSite: 'strict',
        domain: undefined,
        path: '/',
        maxAge: Number((0, ms_1.default)(config_1.config.refreshTtl))
    };
}
async function issueNewTokens(userId, familyId, ip, userAgent) {
    const jti = (0, crypto_1.randomUUID)();
    const fam = familyId || (0, crypto_1.randomUUID)();
    const [access, refresh] = await Promise.all([
        (0, token_1.signAccessToken)(userId),
        (0, token_1.signRefreshToken)(userId, fam, jti),
    ]);
    const payload = await (0, token_1.verifyRefresh)(refresh);
    const expiresAt = new Date(payload.exp * 1000);
    const hashed = await argon2_1.default.hash(refresh);
    await User_1.User.updateOne({ _id: userId }, {
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
async function rotateRefresh(oldToken, ip, userAgent) {
    const payload = await (0, token_1.verifyRefresh)(oldToken);
    const user = await User_1.User.findById(payload.sub).lean();
    if (!user)
        throw new Error('User not found');
    // Find active record for presented token
    const record = user.refreshTokens.find(r => r.jti === payload.jti && !r.revokedAt);
    // Reuse detection: if token not present/active -> revoke whole family
    if (!record) {
        await User_1.User.updateOne({ _id: payload.sub }, {
            $set: { 'refreshTokens.$[elem].revokedAt': new Date() }
        }, { arrayFilters: [{ 'elem.familyId': payload.familyId, 'elem.revokedAt': { $exists: false } }] });
        throw new Error('Refresh token reuse detected; family revoked');
    }
    // Rotate
    const newJti = (0, crypto_1.randomUUID)();
    const [newAccess, newRefresh] = await Promise.all([
        (0, token_1.signAccessToken)(payload.sub),
        (0, token_1.signRefreshToken)(payload.sub, payload.familyId, newJti),
    ]);
    const newPayload = await (0, token_1.verifyRefresh)(newRefresh);
    const hashed = await argon2_1.default.hash(newRefresh);
    await User_1.User.updateOne({ _id: payload.sub, 'refreshTokens.jti': payload.jti }, {
        $set: { 'refreshTokens.$.revokedAt': new Date(), 'refreshTokens.$.replacedBy': newJti },
        $push: {
            refreshTokens: {
                jti: newJti,
                familyId: payload.familyId,
                hashedToken: hashed,
                createdAt: new Date(),
                expiresAt: new Date(newPayload.exp * 1000),
                ip, userAgent
            },
        },
    });
    return { access: newAccess, refresh: newRefresh };
}
async function revokeCurrentRefresh(rawRefresh) {
    try {
        const payload = await (0, token_1.verifyRefresh)(rawRefresh);
        await User_1.User.updateOne({ _id: payload.sub, 'refreshTokens.jti': payload.jti }, {
            $set: { 'refreshTokens.$.revokedAt': new Date() },
        });
    }
    catch {
        // swallow
    }
}
async function revokeFamilyByToken(rawRefresh) {
    const p = await (0, token_1.verifyRefresh)(rawRefresh);
    await User_1.User.updateOne({ _id: p.sub }, {
        $set: { 'refreshTokens.$[elem].revokedAt': new Date() }
    }, { arrayFilters: [{ 'elem.familyId': p.familyId, 'elem.revokedAt': { $exists: false } }] });
}
async function blacklistAccessJti(jti, expSecondsFromNow) {
    await redis_1.redis.set(`blacklist:access:${jti}`, '1', 'EX', expSecondsFromNow);
}
//# sourceMappingURL=token.service.js.map