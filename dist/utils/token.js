"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.signAccessToken = signAccessToken;
exports.signRefreshToken = signRefreshToken;
exports.verifyAccess = verifyAccess;
exports.verifyRefresh = verifyRefresh;
const jose_1 = require("jose");
const crypto_1 = require("crypto");
const ms_1 = __importDefault(require("ms"));
const config_1 = require("../config");
const enc = new TextEncoder();
async function signAccessToken(userId, jti = (0, crypto_1.randomUUID)()) {
    const ttlMs = (0, ms_1.default)(config_1.config.accessTtl);
    if (typeof ttlMs !== "number") {
        throw new Error(`Invalid accessTtl: ${config_1.config.accessTtl}`);
    }
    return new jose_1.SignJWT({ sub: userId, jti, kind: 'access' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(Math.floor(((Date.now() + ttlMs)) / 1000))
        .sign(enc.encode(config_1.config.accessSecret));
}
async function signRefreshToken(userId, familyId, jti = (0, crypto_1.randomUUID)()) {
    const ttlMs = (0, ms_1.default)(config_1.config.refreshTtl);
    if (typeof ttlMs !== "number") {
        throw new Error(`Invalid refreshTtl: ${config_1.config.refreshTtl}`);
    }
    return new jose_1.SignJWT({ sub: userId, jti, familyId, kind: 'refresh' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(Math.floor((Date.now() + ttlMs) / 1000))
        .sign(enc.encode(config_1.config.refreshSecret));
}
async function verifyAccess(token) {
    const { payload } = await (0, jose_1.jwtVerify)(token, enc.encode(config_1.config.accessSecret));
    if (payload.kind !== 'access')
        throw new Error('Invalid token kind');
    return payload;
}
async function verifyRefresh(token) {
    const { payload } = await (0, jose_1.jwtVerify)(token, enc.encode(config_1.config.refreshSecret));
    if (payload.kind !== 'refresh')
        throw new Error('Invalid token kind');
    return payload;
}
//# sourceMappingURL=token.js.map