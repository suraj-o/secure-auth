import 'dotenv/config';

interface Config {
  port: number;
  mongoUri: string;
  redisUrl: string;
  accessSecret: string;
  refreshSecret: string;
  accessTtl: number;  // in minutes
  refreshTtl: number; // in days or minutes
  cookieName: string;
  cookieDomain: string;
  nodeEnv: string;
  corsOrigin: string;
}


export const config: Config = {
  port: parseInt(process.env.PORT || '8081', 10),
  mongoUri: process.env.MONGO_URI || '',
  redisUrl: process.env.REDIS_URL || '',
  accessSecret: process.env.JWT_ACCESS_SECRET || '',
  refreshSecret: process.env.JWT_REFRESH_SECRET || '',
  accessTtl: (process.env.ACCESS_TOKEN_TTL || '15') as unknown as number,
  refreshTtl: (process.env.REFRESH_TOKEN_TTL || '7d') as unknown as number,
  cookieName: process.env.REFRESH_COOKIE_NAME || 'rt',
  cookieDomain: process.env.COOKIE_DOMAIN || 'localhost', 
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173'
};
