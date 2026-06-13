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
    // ── Optional escape hatch ────────────────────────────────────────────────
    // Comma-separated list of additional EXACT origins to allow — e.g. a
    // specific Vercel preview URL you're actively testing against
    // (https://classic-closet-git-feature-x-yourteam.vercel.app).
    // Set EXTRA_CORS_ORIGINS in Vercel env vars; no code change needed.
    // Read directly from process.env so this works even if the var hasn't
    // been added to the Zod schema in env.ts yet.
    ...(process.env.EXTRA_CORS_ORIGINS || '')
      .split(',')
      .map((o) => normalizeOrigin(o.trim()))
      .filter(Boolean),
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
    // You control DNS for the entire cctamcc.site zone, so any subdomain
    // is trusted.
    if (host === 'cctamcc.site' || host.endsWith('.cctamcc.site')) return true;

    // ── REMOVED: blanket *.vercel.app allowance ──────────────────────────────
    // CRITICAL: vercel.app is shared hosting used by millions of unrelated
    // projects. With credentials: true, this let ANY *.vercel.app site read
    // authenticated responses (profile, orders, etc.) and perform
    // state-changing requests (checkout, profile updates, logout) using a
    // logged-in user's SameSite=None cookies — a full cross-site CSRF +
    // session-reading vulnerability requiring zero knowledge of the victim.
    //
    // If you need to test a specific Vercel preview deployment against this
    // API, add its exact URL to EXTRA_CORS_ORIGINS above instead.

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
