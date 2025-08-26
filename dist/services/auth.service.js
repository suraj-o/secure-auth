"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.register = register;
exports.login = login;
const argon2_1 = __importDefault(require("argon2"));
const User_1 = require("../models/User");
const token_service_1 = require("./token.service");
async function register(email, password, ip, userAgent) {
    const existing = await User_1.User.findOne({ email });
    if (existing)
        throw new Error('Email already registered');
    const passwordHash = await argon2_1.default.hash(password);
    const user = await User_1.User.create({ email, passwordHash, refreshTokens: [] });
    const { access, refresh, cookie } = await (0, token_service_1.issueNewTokens)(user.id, undefined, ip, userAgent);
    return { user, access, refresh, cookie };
}
async function login(email, password, ip, userAgent) {
    const user = await User_1.User.findOne({ email });
    if (!user)
        throw new Error('Invalid credentials');
    const ok = await argon2_1.default.verify(user.passwordHash, password);
    if (!ok)
        throw new Error('Invalid credentials');
    const { access, refresh, cookie } = await (0, token_service_1.issueNewTokens)(user.id, undefined, ip, userAgent);
    return { user, access, refresh, cookie };
}
//# sourceMappingURL=auth.service.js.map