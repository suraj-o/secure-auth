"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const ms_1 = __importDefault(require("ms"));
const config_1 = require("../config");
const auth_service_1 = require("../services/auth.service");
const token_service_1 = require("../services/token.service");
const token_1 = require("../utils/token");
const User_1 = require("../models/User");
const crypto_1 = require("crypto");
const router = (0, express_1.Router)();
const credsSchema = zod_1.z.object({ email: zod_1.z.string().email(), password: zod_1.z.string().min(8) });
const csrfCookieName = 'csrf-token';
function newCsrf() { return (0, crypto_1.randomBytes)(16).toString('hex'); }
router.post('/register', async (req, res) => {
    try {
        const { email, password } = credsSchema.parse(req.body);
        const { access, refresh, cookie } = await (0, auth_service_1.register)(email, password, req.ip, req.get('user-agent') || undefined);
        res.cookie(config_1.config.cookieName, refresh, cookie);
        res.cookie(csrfCookieName, newCsrf(), { httpOnly: false, sameSite: 'strict', secure: config_1.config.nodeEnv === 'production', domain: config_1.config.cookieDomain, path: '/' });
        res.json({ accessToken: access });
    }
    catch (e) {
        res.status(400).json({ error: e.message || 'Register failed' });
    }
});
router.post('/login', async (req, res) => {
    try {
        const { email, password } = credsSchema.parse(req.body);
        const { access, refresh, cookie } = await (0, auth_service_1.login)(email, password, req.ip, req.get('user-agent') || undefined);
        res.cookie(config_1.config.cookieName, refresh, cookie);
        res.cookie(csrfCookieName, newCsrf(), { httpOnly: false, sameSite: 'strict', secure: config_1.config.nodeEnv === 'production', domain: config_1.config.cookieDomain, path: '/' });
        res.json({ accessToken: access });
    }
    catch (e) {
        res.status(401).json({ error: e.message || 'Login failed' });
    }
});
// Rotating refresh
router.post('/refresh', async (req, res) => {
    try {
        const rt = req.cookies[config_1.config.cookieName];
        if (!rt)
            return res.status(401).json({ error: 'Missing refresh token' });
        const { access, refresh } = await (0, token_service_1.rotateRefresh)(rt, req.ip, req.get('user-agent') || undefined);
        res.cookie(config_1.config.cookieName, refresh, {
            httpOnly: true,
            secure: config_1.config.nodeEnv === 'production',
            sameSite: 'strict',
            domain: config_1.config.cookieDomain,
            path: '/api/auth/refresh',
            maxAge: Number((0, ms_1.default)(config_1.config.refreshTtl)),
        });
        res.json({ accessToken: access });
    }
    catch (e) {
        return res.status(401).json({ error: e.message || 'Refresh failed' });
    }
});
// Logout current session (blacklist current access + revoke current refresh)
router.post('/logout', async (req, res) => {
    try {
        const auth = req.header('authorization');
        if (auth?.startsWith('Bearer ')) {
            const at = auth.slice('Bearer '.length);
            const payload = await (0, token_1.verifyAccess)(at);
            const expMs = payload.exp * 1000 - Date.now();
            if (expMs > 0)
                await (0, token_service_1.blacklistAccessJti)(payload.jti, Math.ceil(expMs / 1000));
        }
        const rt = req.cookies[config_1.config.cookieName];
        if (rt)
            await (0, token_service_1.revokeCurrentRefresh)(rt);
        res.clearCookie(config_1.config.cookieName, { domain: config_1.config.cookieDomain, path: '/api/auth/refresh' });
        res.status(204).send();
    }
    catch {
        res.status(204).send();
    }
});
// Logout ALL sessions (revoke entire family)
router.post('/logout-all', async (req, res) => {
    try {
        const rt = req.cookies[config_1.config.cookieName];
        if (!rt)
            return res.status(401).json({ error: 'Missing refresh token' });
        await (0, token_service_1.revokeFamilyByToken)(rt);
        res.clearCookie(config_1.config.cookieName, { domain: config_1.config.cookieDomain, path: '/api/auth/refresh' });
        res.status(204).send();
    }
    catch (e) {
        res.status(401).json({ error: e.message || 'Logout-all failed' });
    }
});
// List active sessions (by family)
router.get('/sessions', async (req, res) => {
    try {
        const rt = req.cookies[config_1.config.cookieName];
        if (!rt)
            return res.status(401).json({ error: 'Missing refresh token' });
        const p = await (0, token_1.verifyRefresh)(rt);
        const user = await User_1.User.findById(p.sub);
        if (!user)
            return res.status(404).json({ error: 'User not found' });
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
    }
    catch (e) {
        res.status(401).json({ error: e.message || 'Cannot list sessions' });
    }
});
// Revoke a specific session by jti (requires a refresh cookie from same family)
router.delete('/sessions/:jti', async (req, res) => {
    try {
        const rt = req.cookies[config_1.config.cookieName];
        if (!rt)
            return res.status(401).json({ error: 'Missing refresh token' });
        const p = await (0, token_1.verifyRefresh)(rt);
        const jti = req.params.jti;
        await User_1.User.updateOne({ _id: p.sub, 'refreshTokens.jti': jti, 'refreshTokens.familyId': p.familyId }, { $set: { 'refreshTokens.$.revokedAt': new Date() } });
        res.status(204).send();
    }
    catch (e) {
        res.status(400).json({ error: e.message || 'Cannot revoke session' });
    }
});
exports.default = router;
//# sourceMappingURL=auth.routes.js.map