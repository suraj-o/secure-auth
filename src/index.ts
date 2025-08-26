import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { connectMongo } from './db';
import { config } from './config';
import { tinyRateLimit } from './middleware/rateLimit';
import authRoutes from './routes/auth.routes';
// import protectedRoutes from './routes/protected.routes';

const app = express();

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(tinyRateLimit());

app.use('/api/auth',(req,res,next)=>{
  console.log(req.cookies)
  next();
}, authRoutes);
// app.use('/api', protectedRoutes);

app.get('/api/health', (_req, res) => res.json({ ok: true }));

connectMongo().then(() => {
  app.listen(config.port, () => console.log(`Auth server on :${config.port}`));
});
