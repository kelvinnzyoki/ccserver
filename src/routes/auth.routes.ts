import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { validate } from '../middleware/validate.js';
import { authLimiter } from '../middleware/security.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import {
  signAccess,
  signRefresh,
  persistRefresh,
  cookieOptions,
} from '../services/token.service.js';
import { createOtp, verifyOtp } from '../services/otp.service.js';
import { trySendSms } from '../services/sms.service.js';

const router = Router();

// ─── Startup env guard ────────────────────────────────────────────────────────
// Fail loudly at module load time rather than silently at the first login.
// jwt.sign(payload, undefined) throws "secretOrPrivateKey must have a value"
// which becomes a 500 with no useful message. This surfaces it immediately.
if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error(
    '[auth.routes] FATAL: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be set. ' +
      'The server cannot start without them. Check your Vercel environment variables.'
  );
}

// ─── Schemas ──────────────────────────────────────────────────────────────────

const registerSchema = z.object({
  body: z.object({
    name: z.string().min(2, 'Name is required'),
    email: z.string().email().optional(),
    phone: z.string().min(7).optional(),
    identifier: z.string().min(3).optional(),
    password: z.string().min(8, 'Password must be at least 8 characters'),
  }),
});

const loginSchema = z.object({
  body: z.object({
    login: z.string().min(3).optional(),
    identifier: z.string().min(3).optional(),
    email: z.string().email().optional(),
    phone: z.string().min(7).optional(),
    password: z.string().min(1, 'Password is required'),
  }),
});

const otpVerifySchema = z.object({
  body: z.object({
    code: z.string().length(6, 'OTP must be exactly 6 digits').regex(/^\d{6}$/, 'OTP must be numeric'),
  }),
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getSessionId(req: any): string | undefined {
  const header = req.headers['x-cart-session'];
  const sessionId = Array.isArray(header) ? header[0] : header;
  return typeof sessionId === 'string' && sessionId.trim().length > 0
    ? sessionId.trim()
    : undefined;
}

function normalizePhone(phone?: string): string | undefined {
  if (!phone) return undefined;
  let value = String(phone).replace(/[\s\-()]/g, '').trim();
  if (!value) return undefined;
  if (value.startsWith('+')) value = value.slice(1);
  if (value.startsWith('07') || value.startsWith('01')) {
    value = `254${value.slice(1)}`;
  }
  // Ensure it's a plausible phone number (7-15 digits)
  if (!/^\d{7,15}$/.test(value)) return undefined;
  return value;
}

function normalizeIdentifier(raw?: string): { email?: string; phone?: string } {
  if (!raw) return {};
  const value = String(raw).trim();
  if (!value) return {};
  if (value.includes('@')) return { email: value.toLowerCase() };
  return { phone: normalizePhone(value) };
}

function publicUser(user: any) {
  return {
    id: user.id,
    name: user.name,
    email: user.email?.endsWith('@phone.classic-closet.local') ? null : user.email,
    phone: user.phone,
    role: user.role,
    emailVerified: user.emailVerified,
    phoneVerified: user.phoneVerified,
  };
}

async function mergeGuestCartIntoUser(
  sessionId: string | undefined,
  userId: string
): Promise<void> {
  if (!sessionId) return;

  try {
    const guestCart = await prisma.cart.findUnique({
      where: { sessionId },
      include: { items: true },
    });

    if (!guestCart || guestCart.items.length === 0) return;

    const userCart = await prisma.cart.upsert({
      where: { userId },
      create: { userId },
      update: {},
    });

    for (const item of guestCart.items) {
      await prisma.cartItem.upsert({
        where: { cartId_productId: { cartId: userCart.id, productId: item.productId } },
        create: {
          cartId: userCart.id,
          productId: item.productId,
          quantity: item.quantity,
          price: item.price,
        },
        update: {
          quantity: { increment: item.quantity },
          price: item.price,
        },
      });
    }

    // Delete the guest cart — items are now in the user cart
    await prisma.cart.delete({ where: { id: guestCart.id } }).catch(() => undefined);
  } catch (error) {
    // Non-fatal: cart merge failure must not block login
    console.error('[auth] Non-fatal: guest cart merge failed.', error);
  }
}

function setAuthCookies(res: any, access: string, refresh: string): void {
  res.cookie('access_token', access, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
  res.cookie('refresh_token', refresh, { ...cookieOptions, maxAge: 30 * 24 * 60 * 60 * 1000 });
}

async function issueSession(
  req: any,
  res: any,
  user: any,
  statusCode = 200
): Promise<void> {
  // Merge any guest cart items before responding
  await mergeGuestCartIntoUser(getSessionId(req), user.id);

  // ── THE FIX: explicit try/catch around jwt.sign ──────────────────────────
  // If JWT_ACCESS_SECRET or JWT_REFRESH_SECRET are undefined, jwt.sign throws
  // "secretOrPrivateKey must have a value" — a cryptic 500.
  // We catch it here and surface a clear message in logs and the HTTP response.
  let access: string;
  let refresh: string;
  try {
    access = signAccess(user.id);
    refresh = signRefresh(user.id);
  } catch (jwtError) {
    console.error('[auth] JWT signing failed — are JWT_ACCESS_SECRET and JWT_REFRESH_SECRET set?', jwtError);
    throw new ApiError(
      500,
      'Authentication system misconfiguration. Contact support.'
    );
  }

  await persistRefresh(user.id, refresh);
  setAuthCookies(res, access, refresh);

  res.status(statusCode).json({
    status: 'success',
    data: {
      user: publicUser(user),
      accessToken: access,
    },
  });
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/auth/register
router.post(
  '/register',
  authLimiter,
  validate(registerSchema),
  asyncHandler(async (req, res) => {
    const fromIdentifier = normalizeIdentifier(req.body.identifier);
    const email = (req.body.email || fromIdentifier.email)?.toLowerCase();
    const phone = normalizePhone(req.body.phone || fromIdentifier.phone);

    if (!email && !phone) {
      throw new ApiError(400, 'Email or phone number is required');
    }

    const storedEmail = email ?? `${phone}@phone.classic-closet.local`;

    const existing = await prisma.user.findFirst({
      where: {
        OR: [
          { email: storedEmail },
          ...(email ? [{ email }] : []),
          ...(phone ? [{ phone }] : []),
        ],
      },
    });

    if (existing) throw new ApiError(409, 'An account with this email or phone already exists');

    const user = await prisma.user.create({
      data: {
        name: req.body.name.trim(),
        email: storedEmail,
        phone,
        passwordHash: await bcrypt.hash(req.body.password, 12),
      },
    });

    // After registration: if phone provided, auto-send OTP in background.
    // Non-fatal — registration succeeds regardless of SMS delivery.
    if (phone) {
      createOtp(phone, 'PHONE_VERIFY')
        .then((code) =>
          trySendSms(phone, `Classic Closet: Your verification code is ${code}. Expires in 10 minutes.`)
        )
        .catch((err) => console.error('[auth] OTP send after register failed:', err));
    }

    return issueSession(req, res, user, 201);
  })
);

// POST /api/auth/login
router.post(
  '/login',
  authLimiter,
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    // Support all identifier formats: email, phone, or combined login/identifier field
    const rawIdentifier =
      req.body.login ?? req.body.identifier ?? req.body.email ?? req.body.phone;

    const fromIdentifier = normalizeIdentifier(rawIdentifier);

    const email = (req.body.email || fromIdentifier.email)?.toLowerCase();
    const phone = normalizePhone(req.body.phone || fromIdentifier.phone);

    if (!email && !phone) {
      throw new ApiError(400, 'Email or phone number is required');
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          ...(email ? [{ email }] : []),
          ...(phone ? [{ phone }] : []),
        ],
      },
    });

    // Use a constant-time compare even on null to prevent user enumeration
    const passwordMatch = user
      ? await bcrypt.compare(req.body.password, user.passwordHash)
      : await bcrypt.compare(req.body.password, '$2a$12$invalidhashfortimingnormalization');

    if (!user || !passwordMatch) {
      throw new ApiError(401, 'Invalid email/phone or password');
    }

    return issueSession(req, res, user, 200);
  })
);

// GET /api/auth/me
router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { user: req.user } });
  })
);

// POST /api/auth/logout
router.post(
  '/logout',
  asyncHandler(async (_req, res) => {
    res
      .clearCookie('access_token', cookieOptions)
      .clearCookie('refresh_token', cookieOptions)
      .json({ status: 'success' });
  })
);

// ─── Phone Verification ────────────────────────────────────────────────────────

// POST /api/auth/phone/send-otp
// Requires: user logged in and has a phone on their account
router.post(
  '/phone/send-otp',
  requireAuth,
  asyncHandler(async (req: any, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (!user?.phone) {
      throw new ApiError(400, 'No phone number on this account');
    }

    if (user.phoneVerified) {
      throw new ApiError(400, 'Phone is already verified');
    }

    const code = await createOtp(user.phone, 'PHONE_VERIFY');

    try {
      await trySendSms(
        user.phone,
        `Classic Closet: Your verification code is ${code}. Valid for 10 minutes. Do not share this code.`
      );
    } catch {
      // trySendSms is already non-fatal, but belt-and-braces
    }

    res.json({
      status: 'success',
      message: 'Verification code sent',
      // Only expose in dev for testing — never in prod
      ...(process.env.NODE_ENV !== 'production' ? { __dev_code: code } : {}),
    });
  })
);

// POST /api/auth/phone/verify
// Body: { code: "123456" }
router.post(
  '/phone/verify',
  requireAuth,
  validate(otpVerifySchema),
  asyncHandler(async (req: any, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (!user?.phone) {
      throw new ApiError(400, 'No phone number on this account');
    }

    if (user.phoneVerified) {
      return res.json({ status: 'success', message: 'Phone already verified' });
    }

    const valid = await verifyOtp(user.phone, 'PHONE_VERIFY', req.body.code);

    if (!valid) {
      throw new ApiError(400, 'Invalid or expired verification code');
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { phoneVerified: true },
    });

    res.json({ status: 'success', message: 'Phone verified successfully' });
  })
);

export default router;
