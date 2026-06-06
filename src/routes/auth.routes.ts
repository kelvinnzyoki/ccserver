import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { validate } from '../middleware/validate.js';
import { authLimiter } from '../middleware/security.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { signAccess, signRefresh, persistRefresh, cookieOptions } from '../services/token.service.js';
import { mergeGuestCartIntoUser, normalizeCartSession } from '../services/cart.service.js';
import { sendEmailVerificationCode } from '../services/email.service.js';
import { sendPhoneVerificationCode } from '../services/sms.service.js';

const router = Router();
const CODE_TTL_MINUTES = 10;

const registerSchema = z.object({
  body: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(8),
    phone: z.string().min(9).optional(),
  }),
});

const loginSchema = z.object({
  body: z.object({
    identifier: z.string().min(3).optional(),
    email: z.string().email().optional(),
    phone: z.string().min(9).optional(),
    password: z.string().min(1),
  }).refine((body) => Boolean(body.identifier || body.email || body.phone), {
    message: 'Email or phone is required',
  }),
});

const emailSchema = z.object({
  body: z.object({
    email: z.string().email(),
  }),
});

const phoneSchema = z.object({
  body: z.object({
    phone: z.string().min(9),
  }),
});

const verifySchema = z.object({
  body: z.object({
    target: z.string().min(3),
    code: z.string().regex(/^\d{6}$/),
  }),
});

function publicUser(user: any) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    emailVerified: user.emailVerified,
    phoneVerified: user.phoneVerified,
  };
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function normalizePhone(phone?: string) {
  if (!phone) return undefined;
  const cleaned = phone.replace(/[\s-]/g, '');

  if (cleaned.startsWith('+')) return cleaned;
  if (cleaned.startsWith('254')) return `+${cleaned}`;
  if (cleaned.startsWith('07') || cleaned.startsWith('01')) return `+254${cleaned.slice(1)}`;

  return cleaned;
}

function makeCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function saveCode(target: string, type: 'EMAIL' | 'PHONE', code: string) {
  await prisma.verificationCode.deleteMany({
    where: {
      target,
      type,
      consumedAt: null,
    },
  });

  await prisma.verificationCode.create({
    data: {
      target,
      type,
      codeHash: await bcrypt.hash(code, 10),
      expiresAt: new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000),
    },
  });
}

async function verifyCode(target: string, type: 'EMAIL' | 'PHONE', code: string) {
  const verification = await prisma.verificationCode.findFirst({
    where: {
      target,
      type,
      consumedAt: null,
      expiresAt: {
        gt: new Date(),
      },
    },
    orderBy: {
      createdAt: 'desc',
    },
  });

  if (!verification || !(await bcrypt.compare(code, verification.codeHash))) {
    throw new ApiError(400, 'Invalid or expired verification code');
  }

  await prisma.verificationCode.update({
    where: { id: verification.id },
    data: { consumedAt: new Date() },
  });
}

async function issueSession(res: any, user: any, sessionId?: string) {
  await mergeGuestCartIntoUser(sessionId, user.id);

  const access = signAccess(user.id);
  const refresh = signRefresh(user.id);

  await persistRefresh(user.id, refresh);

  res
    .cookie('access_token', access, { ...cookieOptions, maxAge: 15 * 60 * 1000 })
    .cookie('refresh_token', refresh, { ...cookieOptions, maxAge: 30 * 86400 * 1000 });

  return access;
}

router.post(
  '/register',
  authLimiter,
  validate(registerSchema),
  asyncHandler(async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const phone = normalizePhone(req.body.phone);

    if (await prisma.user.findUnique({ where: { email } })) {
      throw new ApiError(409, 'Email already registered');
    }

    if (phone && (await prisma.user.findUnique({ where: { phone } }))) {
      throw new ApiError(409, 'Phone number already registered');
    }

    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        email,
        phone,
        passwordHash: await bcrypt.hash(req.body.password, 12),
      },
    });

    const access = await issueSession(res, user, normalizeCartSession(req.headers['x-cart-session']));

    res.status(201).json({
      status: 'success',
      data: {
        user: publicUser(user),
        accessToken: access,
      },
    });
  })
);

router.post(
  '/login',
  authLimiter,
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const rawIdentifier = req.body.identifier || req.body.email || req.body.phone;
    const identifier = String(rawIdentifier).trim();
    const email = identifier.includes('@') ? normalizeEmail(identifier) : undefined;
    const phone = !email ? normalizePhone(identifier) : undefined;

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          ...(email ? [{ email }] : []),
          ...(phone ? [{ phone }] : []),
        ],
      },
    });

    if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
      throw new ApiError(401, 'Invalid email/phone or password');
    }

    const access = await issueSession(res, user, normalizeCartSession(req.headers['x-cart-session']));

    res.json({
      status: 'success',
      data: {
        user: publicUser(user),
        accessToken: access,
      },
    });
  })
);

router.post(
  '/send-email-code',
  authLimiter,
  validate(emailSchema),
  asyncHandler(async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) throw new ApiError(404, 'Account not found');

    const code = makeCode();
    await saveCode(email, 'EMAIL', code);
    await sendEmailVerificationCode(email, code);

    res.json({ status: 'success', message: 'Email verification code sent' });
  })
);

router.post(
  '/verify-email-code',
  validate(verifySchema),
  asyncHandler(async (req, res) => {
    const email = normalizeEmail(req.body.target);
    await verifyCode(email, 'EMAIL', req.body.code);

    const user = await prisma.user.update({
      where: { email },
      data: { emailVerified: true },
    });

    res.json({ status: 'success', data: { user: publicUser(user) } });
  })
);

router.post(
  '/send-phone-code',
  authLimiter,
  validate(phoneSchema),
  asyncHandler(async (req, res) => {
    const phone = normalizePhone(req.body.phone)!;
    const user = await prisma.user.findUnique({ where: { phone } });

    if (!user) throw new ApiError(404, 'Account not found');

    const code = makeCode();
    await saveCode(phone, 'PHONE', code);
    await sendPhoneVerificationCode(phone, code);

    res.json({ status: 'success', message: 'SMS verification code sent' });
  })
);

router.post(
  '/verify-phone-code',
  validate(verifySchema),
  asyncHandler(async (req, res) => {
    const phone = normalizePhone(req.body.target)!;
    await verifyCode(phone, 'PHONE', req.body.code);

    const user = await prisma.user.update({
      where: { phone },
      data: { phoneVerified: true },
    });

    res.json({ status: 'success', data: { user: publicUser(user) } });
  })
);

router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { user: req.user } });
  })
);

router.post(
  '/logout',
  requireAuth,
  asyncHandler(async (req, res) => {
    await prisma.user.update({
      where: { id: req.user!.id },
      data: { refreshTokenHash: null },
    });

    res
      .clearCookie('access_token')
      .clearCookie('refresh_token')
      .json({ status: 'success' });
  })
);

export default router;
