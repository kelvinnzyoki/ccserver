import cors from 'cors';
import helmet from 'helmet';
import hpp from 'hpp';
import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

function normalizeOrigin(value?: string) {
  if (!value) return undefined;
  try {
    return new URL(value).origin;
  } catch {
    return value.replace(/\/$/, '');
  }
}

const explicitOrigins = new Set(
  [
    normalizeOrigin(env.FRONTEND_URL),
    'http://localhost:3000',
    'http://localhost:3001',
  ].filter(Boolean) as string[]
);

function isAllowedOrigin(origin?: string) {
  if (!origin) return true;

  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;
  if (explicitOrigins.has(normalized)) return true;

  try {
    const host = new URL(normalized).hostname;

    // Allows your own domains like shop.cctamcc.site, www.cctamcc.site, etc.
    if (host === 'cctamcc.site' || host.endsWith('.cctamcc.site')) return true;

    // Allows Vercel preview/production frontend deployments.
    if (host === 'vercel.app' || host.endsWith('.vercel.app')) return true;

    return false;
  } catch {
    return false;
  }
}

export const securityMiddleware = [
  helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }),
  cors({
    origin(origin, callback) {
      if (isAllowedOrigin(origin)) return callback(null, true);
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Cart-Session',
      'x-cart-session',
    ],
  }),
  hpp(),
];

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 80,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many authentication attempts. Try again later.',
  },
});

export const paymentLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many payment attempts. Try again later.',
  },
});
