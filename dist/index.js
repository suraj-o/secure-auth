"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const db_1 = require("./db");
const config_1 = require("./config");
const rateLimit_1 = require("./middleware/rateLimit");
const auth_routes_1 = __importDefault(require("./routes/auth.routes"));
// import protectedRoutes from './routes/protected.routes';
const app = (0, express_1.default)();
app.use((0, helmet_1.default)({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use((0, cors_1.default)({ origin: config_1.config.corsOrigin, credentials: true }));
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
app.use((0, rateLimit_1.tinyRateLimit)());
app.use('/api/auth', (req, res, next) => {
    console.log(req.cookies);
    next();
}, auth_routes_1.default);
// app.use('/api', protectedRoutes);
app.get('/api/health', (_req, res) => res.json({ ok: true }));
(0, db_1.connectMongo)().then(() => {
    app.listen(config_1.config.port, () => console.log(`Auth server on :${config_1.config.port}`));
});
//# sourceMappingURL=index.js.map