"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.redis = void 0;
const ioredis_1 = __importDefault(require("ioredis"));
const config_1 = require("./config");
exports.redis = new ioredis_1.default(config_1.config.redisUrl);
exports.redis.on('connect', () => console.log('Redis connected'));
//# sourceMappingURL=redis.js.map