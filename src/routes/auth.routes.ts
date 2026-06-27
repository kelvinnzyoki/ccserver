import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { validate } from '../middleware/validate.js';
import { authLimiter } from '../middleware/security.js';
import { requireAuth, optionalAuth } from '../middleware/auth.js';
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
import { sendOtpEmail } from '../services/email.service.js';
import { env } from '../config/env.js';

const router = Router();

if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error(
    '[auth.routes] FATAL: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be set.'
  );
}

// ─── Schemas ──────────────────────────────────────────────────────────────────

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
  body: z.object({
    code: z.string().length(6).regex(/^\d{6}$/),
    email: z.string().email().optional(),
    phone: z.string().min(7).optional(),
    identifier: z.string().min(3).optional(),
  }),
});

const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.string().email('Enter a valid email address'),
  }),
});

const resetPasswordSchema = z.object({
  body: z.object({
    email: z.string().email('Enter a valid email address'),
    code: z.string().length(6).regex(/^\d{6}$/),
    password: z.string().min(8, 'Password must be at least 8 characters'),
  }),
});

const profileSchema = z.object({
  body: z.object({
    name:  z.string().min(2, 'Name must be at least 2 characters').trim().optional(),
    phone: z.string().min(7).optional(),
    email: z.string().email('Enter a valid email address').optional(),
  }).refine(
    (d) => d.name || d.phone || d.email,
    { message: 'At least one field is required' }
  ),
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

function requireEmailOrPhone(email?: string, phone?: string) {
  if (!email && !phone) {
    throw new ApiError(400, 'Email or phone number is required');
  }
}


async function findUserForOtp(req: any, type: 'email' | 'phone') {
  if (req.user?.id) {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (user) return user;
  }

  const fromId = normalizeIdentifier(req.body?.identifier ?? req.body?.email ?? req.body?.phone);
  const email = (req.body?.email || fromId.email)?.toLowerCase();
  const phone = normalizePhone(req.body?.phone || fromId.phone);

  if (type === 'email') {
    if (!email) throw new ApiError(400, 'Email address is required');
    return prisma.user.findFirst({ where: { email } });
  }

  if (!phone) throw new ApiError(400, 'Phone number is required');
  return prisma.user.findFirst({ where: { phone } });
}

function publicUser(user: any) {
  return {
    id: user.id,
    name: user.name,
    email: user.email?.endsWith('@phone.classic-closet.local')
      ? null
      : user.email,
    phone: user.phone,
    role: user.role,
    emailVerified: user.emailVerified,
    phoneVerified: user.phoneVerified,
  };
}

function setAuthCookies(res: any, access: string, refresh: string) {
  res.cookie('access_token', access, {
    ...cookieOptions,
    maxAge: 15 * 60 * 1000,
  });
  res.cookie('refresh_token', refresh, {
    ...cookieOptions,
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

type PendingSignup = {
  name: string;
  email?: string;
  phone?: string;
  storedEmail: string;
  passwordHash: string;
  verificationType: 'email' | 'phone';
  target: string;
};

const PENDING_SIGNUP_COOKIE = 'pending_signup';
const PENDING_SIGNUP_MAX_AGE = 10 * 60 * 1000;

function setPendingSignupCookie(res: any, pending: PendingSignup) {
  const token = jwt.sign(pending, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: '10m',
  });

  res.cookie(PENDING_SIGNUP_COOKIE, token, {
    ...cookieOptions,
    maxAge: PENDING_SIGNUP_MAX_AGE,
  });
}

function clearPendingSignupCookie(res: any) {
  res.clearCookie(PENDING_SIGNUP_COOKIE, cookieOptions);

  const { domain, ...withoutDomain } = cookieOptions as Record<string, unknown>;
  res.clearCookie(PENDING_SIGNUP_COOKIE, withoutDomain);
}

function readPendingSignup(req: any): PendingSignup | null {
  const token = req.cookies?.[PENDING_SIGNUP_COOKIE];
  if (!token || typeof token !== 'string') return null;

  try {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as PendingSignup;
  } catch {
    return null;
  }
}

async function finishPendingSignup(req: any, res: any, pending: PendingSignup) {
  const existing = await prisma.user.findFirst({
    where: {
      OR: [
        { email: pending.storedEmail },
        ...(pending.phone ? [{ phone: pending.phone }] : []),
      ],
    },
  });

  if (existing) {
    clearPendingSignupCookie(res);
    throw new ApiError(409, 'An account with this email or phone already exists');
  }

  const user = await prisma.user.create({
    data: {
      name: pending.name,
      email: pending.storedEmail,
      phone: pending.phone,
      passwordHash: pending.passwordHash,
      emailVerified: pending.verificationType === 'email',
      phoneVerified: pending.verificationType === 'phone',
    },
  });

  clearPendingSignupCookie(res);
  return issueSession(req, res, user, 201);
}

async function mergeGuestCart(
  sessionId: string | undefined,
  userId: string
) {
  if (!sessionId) return;
  try {
    const guestCart = await prisma.cart.findUnique({
      where: { sessionId },
      include: { items: true },
    });
    if (!guestCart?.items.length) return;
    const userCart = await prisma.cart.upsert({
      where: { userId },
      create: { userId },
      update: {},
    });
    for (const item of guestCart.items) {
      await prisma.cartItem.upsert({
        where: {
          // FIX: the compound unique key is cartId_productId_size, not
          // cartId_productId. CartItem.size (String?) was added to support
          // product variants, and Prisma generated a new compound key name
          // to match @@unique([cartId, productId, size]).
          //
          // `as string` below is a deliberate type assertion, not a runtime
          // change: Prisma's generated WhereUniqueInput type for THIS
          // compound key requires `string` even though size is genuinely
          // nullable in the schema — a known gap in how Prisma generates
          // types for nullable fields inside @@unique. The query engine
          // itself still correctly matches/sends `null` in the actual SQL;
          // only the TS type definition is stricter than reality. Casting
          // preserves item.size's real value (including null) at runtime.
          cartId_productId_size: {
            cartId: userCart.id,
            productId: item.productId,
            size: item.size as string,
          },
        },
        create: {
          cartId: userCart.id,
          productId: item.productId,
          // FIX: item.size is `string | null` (nullable DB column), but
          // Prisma's generated create-input type for this field only
          // accepts `string | undefined` — not `null` — for "no value".
          // The compound where-clause above correctly accepts `string | null`
          // (that's a separate, more permissive generated type), so only
          // this create call needed the null → undefined conversion.
          size: item.size ?? undefined,
          quantity: item.quantity,
          price: item.price,
        },
        update: {
          quantity: { increment: item.quantity },
          price: item.price,
        },
      });
    }
    await prisma.cart
      .delete({ where: { id: guestCart.id } })
      .catch(() => undefined);
  } catch (e) {
    console.error('[auth] guest cart merge (non-fatal):', e);
  }
}

async function issueSession(
  req: any,
  res: any,
  user: any,
  status = 200
) {
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
  res.status(status).json({
    status: 'success',
    data: { user: publicUser(user), accessToken: access },
  });
}

// ─── Register ─────────────────────────────────────────────────────────────────

router.post(
  '/register',
  authLimiter,
  validate(registerSchema),
  asyncHandler(async (req, res) => {
    const fromId = normalizeIdentifier(req.body.identifier);
    const email = (req.body.email || fromId.email)?.toLowerCase();
    const phone = normalizePhone(req.body.phone || fromId.phone);
    requireEmailOrPhone(email, phone);

    const storedEmail = email ?? `${phone}@phone.classic-closet.local`;
    const existing = await prisma.user.findFirst({
      where: {
        OR: [{ email: storedEmail }, ...(phone ? [{ phone }] : [])],
      },
    });
    if (existing)
      throw new ApiError(
        409,
        'An account with this email or phone already exists'
      );

    const verificationType: 'email' | 'phone' = email ? 'email' : 'phone';
    const target = email ?? phone!;

    const pendingSignup: PendingSignup = {
      name: req.body.name.trim(),
      email,
      phone,
      storedEmail,
      passwordHash: await bcrypt.hash(req.body.password, 12),
      verificationType,
      target,
    };

    if (email) {
      const code = await createOtp(email, 'EMAIL_VERIFY', true);
      await sendOtpEmail(email, code);
    } else {
      const code = await createOtp(phone!, 'PHONE_VERIFY', true);
      const sent = await trySendSms(phone!, `Classic Closet: Your code is ${code}. Valid 10 min.`);
      if (!sent) {
        throw new ApiError(502, 'SMS verification code could not be sent. Please check your SMS provider setup.');
      }
    }

    setPendingSignupCookie(res, pendingSignup);

    res.status(201).json({
      status: 'success',
      message: email ? 'Code sent to your email' : 'Code sent to your phone',
      data: {
        requiresVerification: true,
        verificationType,
        identifier: target,
      },
    });
  })
);

// ─── Login ────────────────────────────────────────────────────────────────────

router.post(
  '/login',
  authLimiter,
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const fromId = normalizeIdentifier(
      req.body.login ?? req.body.identifier ?? req.body.email ?? req.body.phone
    );
    const email = (req.body.email || fromId.email)?.toLowerCase();
    const phone = normalizePhone(req.body.phone || fromId.phone);
    requireEmailOrPhone(email, phone);

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          ...(email ? [{ email }] : []),
          ...(phone ? [{ phone }] : []),
        ],
      },
    });

    const match = user
      ? await bcrypt.compare(req.body.password, user.passwordHash)
      : await bcrypt.compare(
          req.body.password,
          '$2a$12$invalidhashfortimingnormalization'
        );

    if (!user || !match)
      throw new ApiError(401, 'Invalid email/phone or password');

    return issueSession(req, res, user, 200);
  })
);


// ─── Password Reset ──────────────────────────────────────────────────────────

router.post(
  '/password/forgot',
  authLimiter,
  validate(forgotPasswordSchema),
  asyncHandler(async (req, res) => {
    const email = req.body.email.toLowerCase().trim();
    const user = await prisma.user.findFirst({ where: { email } });

    // Always return success so attackers cannot confirm registered emails.
    if (!user || user.email.endsWith('@phone.classic-closet.local')) {
      return res.json({
        status: 'success',
        message: 'If that email exists, a password reset code has been sent.',
      });
    }

    const code = await createOtp(email, 'PASSWORD_RESET');
    await sendOtpEmail(email, code);

    res.json({
      status: 'success',
      message: 'If that email exists, a password reset code has been sent.',
      ...(process.env.NODE_ENV !== 'production' ? { __dev_code: code } : {}),
    });
  })
);

router.post(
  '/password/reset',
  authLimiter,
  validate(resetPasswordSchema),
  asyncHandler(async (req, res) => {
    const email = req.body.email.toLowerCase().trim();
    const valid = await verifyOtp(email, 'PASSWORD_RESET', req.body.code);
    if (!valid) throw new ApiError(400, 'Invalid or expired reset code');

    const user = await prisma.user.findFirst({ where: { email } });
    if (!user || user.email.endsWith('@phone.classic-closet.local')) {
      throw new ApiError(400, 'Invalid or expired reset code');
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: await bcrypt.hash(req.body.password, 12),
        refreshTokenHash: null,
      },
    });

    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);
    const { domain, ...withoutDomain } = cookieOptions as Record<string, unknown>;
    if (domain) {
      res.clearCookie('access_token', withoutDomain);
      res.clearCookie('refresh_token', withoutDomain);
    }

    res.json({ status: 'success', message: 'Password reset successful. Please sign in with your new password.' });
  })
);

// ─── Refresh ──────────────────────────────────────────────────────────────────

router.post(
  '/refresh',
  asyncHandler(async (req, res) => {
    const token: string | undefined = req.cookies?.refresh_token;
    if (!token) throw new ApiError(401, 'No session found');

    let decoded: { id: string };
    try {
      decoded = jwt.verify(token, env.JWT_REFRESH_SECRET) as { id: string };
    } catch {
      throw new ApiError(401, 'Session expired — please sign in again');
    }

    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user?.refreshTokenHash)
      throw new ApiError(401, 'Session not found — please sign in again');

    const valid = await bcrypt.compare(token, user.refreshTokenHash);
    if (!valid)
      throw new ApiError(401, 'Session invalid — please sign in again');

    let newAccess: string, newRefresh: string;
    try {
      newAccess = signAccess(user.id);
      newRefresh = signRefresh(user.id);
    } catch {
      throw new ApiError(500, 'Token signing failed');
    }

    await persistRefresh(user.id, newRefresh);
    setAuthCookies(res, newAccess, newRefresh);
    res.json({
      status: 'success',
      data: { accessToken: newAccess, user: publicUser(user) },
    });
  })
);

// ─── Me ───────────────────────────────────────────────────────────────────────

router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { user: req.user } });
  })
);

// ─── Profile update ───────────────────────────────────────────────────────────

router.patch(
  '/profile',
  requireAuth,
  validate(profileSchema),
  asyncHandler(async (req: any, res) => {
    const updates: Record<string, unknown> = {};

    if (req.body.name) {
      updates.name = req.body.name.trim();
    }

    if (req.body.phone) {
      const phone = normalizePhone(req.body.phone);
      if (!phone) throw new ApiError(400, 'Invalid phone number format');

      const taken = await prisma.user.findFirst({
        where: { phone, NOT: { id: req.user.id } },
      });
      if (taken) throw new ApiError(409, 'This phone number is already linked to another account');

      updates.phone = phone;
      updates.phoneVerified = false; // Reset — must re-verify the new number
    }

    if (req.body.email) {
      const email = req.body.email.toLowerCase().trim();

      const taken = await prisma.user.findFirst({
        where: { email, NOT: { id: req.user.id } },
      });
      if (taken) throw new ApiError(409, 'This email is already linked to another account');

      updates.email = email;
      updates.emailVerified = false; // Reset — must re-verify the new address
    }

    const user = await prisma.user.update({
      where: { id: req.user.id },
      data: updates,
    });

    res.json({
      status: 'success',
      data: { user: publicUser(user) },
      otpSent: false,
    });
  })
);

// ─── Logout ───────────────────────────────────────────────────────────────────
// FIX: added optionalAuth middleware.
//
// Without it, req.user was ALWAYS undefined (nothing populated it), so
// `if (req.user?.id)` never ran, and refreshTokenHash was never cleared
// in the database. The cookies were cleared client-side, but the OLD
// refresh token remained valid server-side — if it leaked or was cached
// anywhere (e.g. a browser that restores cookies from a previous session,
// or a service worker), POST /api/auth/refresh would still succeed and
// silently re-authenticate the user, making logout look like it "didn't work".
//
// optionalAuth populates req.user from the access token if present and
// valid, but does NOT throw if it's missing/expired — so logout always
// returns 200 regardless of token state, while still invalidating the
// refresh token server-side whenever possible.

router.post(
  '/logout',
  optionalAuth,
  asyncHandler(async (req: any, res) => {
    if (req.user?.id) {
      await prisma.user
        .update({
          where: { id: req.user.id },
          data: { refreshTokenHash: null },
        })
        .catch(() => undefined);
    }

    // Clear with the configured options (covers cookies set with Domain=...)
    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);

    // FIX: ALSO clear host-only variants (no Domain attribute).
    //
    // If COOKIE_DOMAIN was unset at the time a user logged in, their
    // browser received a host-only cookie (scoped to the exact hostname,
    // no Domain attribute). clearCookie(name, cookieOptions) now sends
    // `Domain=.cctamcc.site` — a DIFFERENT scope to the browser than the
    // host-only cookie it's holding, so the original is never removed.
    // That browser stays logged in indefinitely via the stale cookie,
    // even though logout succeeds everywhere else. Clearing the no-domain
    // variant too covers both possible cookie scopes.
    const { domain, ...withoutDomain } = cookieOptions as Record<string, unknown>;
    if (domain) {
      res.clearCookie('access_token', withoutDomain);
      res.clearCookie('refresh_token', withoutDomain);
    }

    res.json({ status: 'success' });
  })
);

// ─── Phone OTP ────────────────────────────────────────────────────────────────

router.post(
  '/phone/send-otp',
  optionalAuth,
  asyncHandler(async (req: any, res) => {
    const pending = readPendingSignup(req);
    const requested = normalizePhone(req.body?.phone || req.body?.identifier);

    if (pending?.verificationType === 'phone') {
      if (requested && requested !== pending.target) {
        throw new ApiError(400, 'This signup is for a different phone number');
      }

      const code = await createOtp(pending.target, 'PHONE_VERIFY');
      const sent = await trySendSms(pending.target, `Classic Closet: Your code is ${code}. Valid 10 min.`);
      if (!sent) {
        throw new ApiError(502, 'SMS verification code could not be sent. Please check your SMS provider setup.');
      }

      return res.json({
        status: 'success',
        message: 'Code sent',
        ...(process.env.NODE_ENV !== 'production' ? { __dev_code: code } : {}),
      });
    }

    const user = await findUserForOtp(req, 'phone');
    if (!user?.phone) throw new ApiError(400, 'No phone number on account');
    if (user.phoneVerified) throw new ApiError(400, 'Phone already verified');
    const code = await createOtp(user.phone, 'PHONE_VERIFY');
    const sent = await trySendSms(user.phone, `Classic Closet: Your code is ${code}. Valid 10 min.`);
    if (!sent) {
      throw new ApiError(502, 'SMS verification code could not be sent. Please check your SMS provider setup.');
    }
    res.json({
      status: 'success',
      message: 'Code sent',
      ...(process.env.NODE_ENV !== 'production' ? { __dev_code: code } : {}),
    });
  })
);

router.post(
  '/phone/verify',
  optionalAuth,
  validate(otpSchema),
  asyncHandler(async (req: any, res) => {
    const pending = readPendingSignup(req);
    const requested = normalizePhone(req.body.phone || req.body.identifier);

    if (pending?.verificationType === 'phone') {
      if (requested && requested !== pending.target) {
        throw new ApiError(400, 'This code is for a different phone number');
      }

      const valid = await verifyOtp(pending.target, 'PHONE_VERIFY', req.body.code);
      if (!valid) throw new ApiError(400, 'Invalid or expired code');

      return finishPendingSignup(req, res, pending);
    }

    const user = await findUserForOtp(req, 'phone');
    if (!user?.phone) throw new ApiError(400, 'No phone number on account');
    if (user.phoneVerified)
      return res.json({ status: 'success', message: 'Already verified' });
    const valid = await verifyOtp(user.phone, 'PHONE_VERIFY', req.body.code);
    if (!valid) throw new ApiError(400, 'Invalid or expired code');
    const verifiedUser = await prisma.user.update({
      where: { id: user.id },
      data: { phoneVerified: true },
    });
    if (!req.user?.id) return issueSession(req, res, verifiedUser, 200);
    res.json({ status: 'success', message: 'Phone verified' });
  })
);

// ─── Email OTP ────────────────────────────────────────────────────────────────

router.post(
  '/email/send-otp',
  optionalAuth,
  asyncHandler(async (req: any, res) => {
    const pending = readPendingSignup(req);
    const requested = (req.body?.email || req.body?.identifier)?.toLowerCase();

    if (pending?.verificationType === 'email') {
      if (requested && requested !== pending.target) {
        throw new ApiError(400, 'This signup is for a different email address');
      }

      const code = await createOtp(pending.target, 'EMAIL_VERIFY');
      await sendOtpEmail(pending.target, code);

      return res.json({
        status: 'success',
        message: 'Code sent to your email',
        ...(process.env.NODE_ENV !== 'production' ? { __dev_code: code } : {}),
      });
    }

    const user = await findUserForOtp(req, 'email');
    if (
      !user?.email ||
      user.email.endsWith('@phone.classic-closet.local')
    ) {
      throw new ApiError(400, 'No email address on this account');
    }
    if (user.emailVerified) throw new ApiError(400, 'Email already verified');
    const code = await createOtp(user.email, 'EMAIL_VERIFY');
    await sendOtpEmail(user.email, code);
    res.json({
      status: 'success',
      message: 'Code sent to your email',
      ...(process.env.NODE_ENV !== 'production' ? { __dev_code: code } : {}),
    });
  })
);

router.post(
  '/email/verify',
  optionalAuth,
  validate(otpSchema),
  asyncHandler(async (req: any, res) => {
    const pending = readPendingSignup(req);
    const requested = (req.body.email || req.body.identifier)?.toLowerCase();

    if (pending?.verificationType === 'email') {
      if (requested && requested !== pending.target) {
        throw new ApiError(400, 'This code is for a different email address');
      }

      const valid = await verifyOtp(pending.target, 'EMAIL_VERIFY', req.body.code);
      if (!valid) throw new ApiError(400, 'Invalid or expired code');

      return finishPendingSignup(req, res, pending);
    }

    const user = await findUserForOtp(req, 'email');
    if (
      !user?.email ||
      user.email.endsWith('@phone.classic-closet.local')
    ) {
      throw new ApiError(400, 'No email address on this account');
    }
    if (user.emailVerified)
      return res.json({ status: 'success', message: 'Already verified' });
    const valid = await verifyOtp(user.email, 'EMAIL_VERIFY', req.body.code);
    if (!valid) throw new ApiError(400, 'Invalid or expired code');
    const verifiedUser = await prisma.user.update({
      where: { id: user.id },
      data: { emailVerified: true },
    });
    if (!req.user?.id) return issueSession(req, res, verifiedUser, 200);
    res.json({ status: 'success', message: 'Email verified' });
  })
);

export default router;
