"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAuth = requireAuth;
const token_1 = require("../utils/token");
const redis_1 = require("../redis");
async function requireAuth(req, res, next) {
    try {
        const auth = req.header('authorization');
        if (!auth?.startsWith('Bearer '))
            return res.status(401).json({ error: 'Missing Bearer token' });
        const token = auth.slice('Bearer '.length);
        const payload = await (0, token_1.verifyAccess)(token);
        const blacklisted = await redis_1.redis.get(`blacklist:access:${payload.jti}`);
        if (blacklisted)
            return res.status(401).json({ error: 'Token revoked' });
        req.user = { id: payload.sub, jti: payload.jti, exp: payload.exp };
        next();
    }
    catch {
        return res.status(401).json({ error: 'Invalid/expired token' });
    }
}
//# sourceMappingURL=requireAuth.js.map