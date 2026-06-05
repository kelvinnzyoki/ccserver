import helmet from 'helmet';
import hpp from 'hpp';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { env } from '../config/env.js';
export const securityMiddleware = [
  helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }),
  hpp(),
  cors({ origin: env.FRONTEND_URL, credentials: true }),
  rateLimit({ windowMs: 15*60*1000, max: 250, standardHeaders: true, legacyHeaders: false })
];
export const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 8, skipSuccessfulRequests: true });
export const paymentLimiter = rateLimit({ windowMs: 60*60*1000, max: 20 });
