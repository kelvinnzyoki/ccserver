import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { validate } from '../middleware/validate.js';
import { authLimiter } from '../middleware/security.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import {
  signAccess, signRefresh, persistRefresh, cookieOptions,
} from '../services/token.service.js';
import { createOtp, verifyOtp } from '../services/otp.service.js';
import { trySendSms } from '../services/sms.service.js';
import { env } from '../config/env.js';

const router = Router();

if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error('[auth.routes] FATAL: JWT secrets must be set in Vercel env vars.');
}

const registerSchema = z.object({
  body: z.object({
    name: z.string().min(2),
    email: z.string().email().optional(),
    phone: z.string().min(7).optional(),
    identifier: z.string().min(3).optional(),
    password: z.string().min(8),
  }),
});

const loginSchema = z.object({
  body: z.object({
    login: z.string().min(3).optional(),
    identifier: z.string().min(3).optional(),
    email: z.string().email().optional(),
    phone: z.string().min(7).optional(),
    password: z.string().min(1),
  }),
});

const otpSchema = z.object({
  body: z.object({ code: z.string().length(6).regex(/^\d{6}$/) }),
});

function getSessionId(req: any): string | undefined {
  const h = req.headers['x-cart-session'];
  const v = Array.isArray(h) ? h[0] : h;
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

function normalizePhone(phone?: string): string | undefined {
  if (!phone) return undefined;
  let v = String(phone).replace(/[\s\-()+]/g, '');
  if (v.startsWith('07') || v.startsWith('01')) v = `254${v.slice(1)}`;
  return /^\d{7,15}$/.test(v) ? v : undefined;
}

function normalizeIdentifier(raw?: string): { email?: string; phone?: string } {
  if (!raw) return {};
  const v = String(raw).trim();
  if (!v) return {};
  if (v.includes('@')) return { email: v.toLowerCase() };
  return { phone: normalizePhone(v) };
}

function publicUser(user: any) {
  return {
    id: user.id, name: user.name,
    email: user.email?.endsWith('@phone.classic-closet.local') ? null : user.email,
    phone: user.phone, role: user.role,
    emailVerified: user.emailVerified, phoneVerified: user.phoneVerified,
  };
}

function setAuthCookies(res: any, access: string, refresh: string) {
  res.cookie('access_token', access, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
  res.cookie('refresh_token', refresh, { ...cookieOptions, maxAge: 30 * 24 * 60 * 60 * 1000 });
}

async function mergeGuestCart(sessionId: string | undefined, userId: string) {
  if (!sessionId) return;
  try {
    const guestCart = await prisma.cart.findUnique({ where: { sessionId }, include: { items: true } });
    if (!guestCart?.items.length) return;
    const userCart = await prisma.cart.upsert({ where: { userId }, create: { userId }, update: {} });
    for (const item of guestCart.items) {
      await prisma.cartItem.upsert({
        where: { cartId_productId: { cartId: userCart.id, productId: item.productId } },
        create: { cartId: userCart.id, productId: item.productId, quantity: item.quantity, price: item.price },
        update: { quantity: { increment: item.quantity }, price: item.price },
      });
    }
    await prisma.cart.delete({ where: { id: guestCart.id } }).catch(() => undefined);
  } catch (e) { console.error('[auth] guest cart merge (non-fatal):', e); }
}

async function issueSession(req: any, res: any, user: any, status = 200) {
  await mergeGuestCart(getSessionId(req), user.id);
  let access: string, refresh: string;
  try {
    access = signAccess(user.id);
    refresh = signRefresh(user.id);
  } catch (e) {
    console.error('[auth] JWT signing failed:', e);
    throw new ApiError(500, 'Authentication misconfiguration. Contact support.');
  }
  await persistRefresh(user.id, refresh);
  setAuthCookies(res, access, refresh);
  res.status(status).json({ status: 'success', data: { user: publicUser(user), accessToken: access } });
}

// ─── Register ──────────────────────────────────────────────────────────────

router.post('/register', authLimiter, validate(registerSchema), asyncHandler(async (req, res) => {
  const fromId = normalizeIdentifier(req.body.identifier);
  const email = (req.body.email || fromId.email)?.toLowerCase();
  const phone = normalizePhone(req.body.phone || fromId.phone);
  if (!email && !phone) throw new ApiError(400, 'Email or phone number is required');

  const storedEmail = email ?? `${phone}@phone.classic-closet.local`;
  const existing = await prisma.user.findFirst({
    where: { OR: [{ email: storedEmail }, ...(phone ? [{ phone }] : [])] },
  });
  if (existing) throw new ApiError(409, 'An account with this email or phone already exists');

  const user = await prisma.user.create({
    data: { name: req.body.name.trim(), email: storedEmail, phone, passwordHash: await bcrypt.hash(req.body.password, 12) },
  });

  if (phone) {
    createOtp(phone, 'PHONE_VERIFY')
      .then((code) => trySendSms(phone, `Classic Closet: Your code is ${code}. Expires in 10 min.`))
      .catch((e) => console.error('[auth] post-register OTP:', e));
  }

  return issueSession(req, res, user, 201);
}));

// ─── Login ─────────────────────────────────────────────────────────────────

router.post('/login', authLimiter, validate(loginSchema), asyncHandler(async (req, res) => {
  const fromId = normalizeIdentifier(req.body.login ?? req.body.identifier ?? req.body.email ?? req.body.phone);
  const email = (req.body.email || fromId.email)?.toLowerCase();
  const phone = normalizePhone(req.body.phone || fromId.phone);
  if (!email && !phone) throw new ApiError(400, 'Email or phone number is required');

  const user = await prisma.user.findFirst({
    where: { OR: [...(email ? [{ email }] : []), ...(phone ? [{ phone }] : [])] },
  });

  const match = user
    ? await bcrypt.compare(req.body.password, user.passwordHash)
    : await bcrypt.compare(req.body.password, '$2a$12$invalidhashfortimingnormalization');

  if (!user || !match) throw new ApiError(401, 'Invalid email/phone or password');
  return issueSession(req, res, user, 200);
}));

// ─── Refresh ───────────────────────────────────────────────────────────────
// Session policy:
//   Access token  — 15 min  (short-lived; stolen token window is minimal)
//   Refresh token — 30 days (renewed on each use via token rotation)
//   Idle timeout  — 30 days (no activity = sign in again)
//
// Token rotation: each refresh call issues a NEW refresh token and invalidates
// the old one (via hash update). A stolen refresh token is only valid until
// the legitimate user next refreshes — at which point the hash changes.

router.post('/refresh', asyncHandler(async (req, res) => {
  const token: string | undefined = req.cookies?.refresh_token;
  if (!token) throw new ApiError(401, 'No session found');

  let decoded: { id: string };
  try {
    decoded = jwt.verify(token, env.JWT_REFRESH_SECRET) as { id: string };
  } catch {
    throw new ApiError(401, 'Session expired — please sign in again');
  }

  const user = await prisma.user.findUnique({ where: { id: decoded.id } });
  if (!user?.refreshTokenHash) throw new ApiError(401, 'Session not found');

  const valid = await bcrypt.compare(token, user.refreshTokenHash);
  if (!valid) throw new ApiError(401, 'Session invalid — please sign in again');

  let newAccess: string, newRefresh: string;
  try {
    newAccess = signAccess(user.id);
    newRefresh = signRefresh(user.id);
  } catch {
    throw new ApiError(500, 'Token signing failed');
  }

  await persistRefresh(user.id, newRefresh);
  setAuthCookies(res, newAccess, newRefresh);
  res.json({ status: 'success', data: { accessToken: newAccess, user: publicUser(user) } });
}));

// ─── Me ────────────────────────────────────────────────────────────────────

router.get('/me', requireAuth, asyncHandler(async (req, res) => {
  res.json({ status: 'success', data: { user: req.user } });
}));

// ─── Logout ────────────────────────────────────────────────────────────────

router.post('/logout', asyncHandler(async (req: any, res) => {
  if (req.user?.id) {
    await prisma.user.update({ where: { id: req.user.id }, data: { refreshTokenHash: null } }).catch(() => undefined);
  }
  res.clearCookie('access_token', cookieOptions).clearCookie('refresh_token', cookieOptions).json({ status: 'success' });
}));

// ─── Phone OTP ─────────────────────────────────────────────────────────────

router.post('/phone/send-otp', requireAuth, asyncHandler(async (req: any, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!user?.phone) throw new ApiError(400, 'No phone number on account');
  if (user.phoneVerified) throw new ApiError(400, 'Already verified');
  const code = await createOtp(user.phone, 'PHONE_VERIFY');
  await trySendSms(user.phone, `Classic Closet: Your code is ${code}. Valid 10 min. Do not share.`);
  res.json({ status: 'success', message: 'Code sent', ...(process.env.NODE_ENV !== 'production' ? { __dev_code: code } : {}) });
}));

router.post('/phone/verify', requireAuth, validate(otpSchema), asyncHandler(async (req: any, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!user?.phone) throw new ApiError(400, 'No phone number on account');
  if (user.phoneVerified) return res.json({ status: 'success', message: 'Already verified' });
  const valid = await verifyOtp(user.phone, 'PHONE_VERIFY', req.body.code);
  if (!valid) throw new ApiError(400, 'Invalid or expired code');
  await prisma.user.update({ where: { id: user.id }, data: { phoneVerified: true } });
  res.json({ status: 'success', message: 'Phone verified' });
}));

export default router;
