"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.User = void 0;
const mongoose_1 = require("mongoose");
const RefreshSchema = new mongoose_1.Schema({
    jti: {
        type: String, required: true
    },
    familyId: { type: String, required: true },
    hashedToken: { type: String, required: true },
    createdAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date },
    replacedBy: { type: String },
    ip: String,
    userAgent: String
}, { _id: false });
const UserSchema = new mongoose_1.Schema({
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    refreshTokens: { type: [RefreshSchema], default: [] }
}, { timestamps: true });
exports.User = (0, mongoose_1.model)('User', UserSchema);
//# sourceMappingURL=User.js.map