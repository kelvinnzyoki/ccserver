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

const router = Router();

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

function getSessionId(req: any) {
  const header = req.headers['x-cart-session'];
  const sessionId = Array.isArray(header) ? header[0] : header;
  return typeof sessionId === 'string' && sessionId.trim().length > 0
    ? sessionId.trim()
    : undefined;
}

function normalizePhone(phone?: string) {
  if (!phone) return undefined;
  let value = String(phone).replace(/[\s-]/g, '').trim();
  if (!value) return undefined;
  if (value.startsWith('+')) value = value.slice(1);
  if (value.startsWith('07') || value.startsWith('01')) value = `254${value.slice(1)}`;
  return value;
}

function normalizeIdentifier(raw?: string) {
  if (!raw) return {} as { email?: string; phone?: string };
  const value = String(raw).trim();
  if (!value) return {} as { email?: string; phone?: string };
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
  };
}

async function mergeGuestCartIntoUser(sessionId: string | undefined, userId: string) {
  if (!sessionId) return;

  try {
    const guestCart = await prisma.cart.findUnique({
      where: { sessionId },
      include: { items: true },
    });

    if (!guestCart) return;

    const userCart = await prisma.cart.upsert({
      where: { userId },
      create: { userId },
      update: {},
    });

    for (const item of guestCart.items) {
      await prisma.cartItem.upsert({
        where: {
          cartId_productId: {
            cartId: userCart.id,
            productId: item.productId,
          },
        },
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

    await prisma.cart.delete({ where: { id: guestCart.id } }).catch(() => undefined);
  } catch (error) {
    console.error('Non-fatal: failed to merge guest cart into user cart.', error);
  }
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

async function issueSession(req: any, res: any, user: any, statusCode = 200) {
  await mergeGuestCartIntoUser(getSessionId(req), user.id);

  const access = signAccess(user.id);
  const refresh = signRefresh(user.id);

  await persistRefresh(user.id, refresh);
  setAuthCookies(res, access, refresh);

  return res.status(statusCode).json({
    status: 'success',
    data: {
      user: publicUser(user),
      accessToken: access,
    },
  });
}

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

    const storedEmail = email || `${phone}@phone.classic-closet.local`;

    const existing = await prisma.user.findFirst({
      where: {
        OR: [
          { email: storedEmail },
          ...(email ? [{ email }] : []),
          ...(phone ? [{ phone }] : []),
        ],
      },
    });

    if (existing) throw new ApiError(409, 'Account already exists');

    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        email: storedEmail,
        phone,
        passwordHash: await bcrypt.hash(req.body.password, 12),
      },
    });

    return issueSession(req, res, user, 201);
  })
);

router.post(
  '/login',
  authLimiter,
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const fromIdentifier = normalizeIdentifier(
      req.body.login || req.body.identifier || req.body.email || req.body.phone
    );

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

    if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
      throw new ApiError(401, 'Invalid login details');
    }

    return issueSession(req, res, user, 200);
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
  asyncHandler(async (_req, res) => {
    res
      .clearCookie('access_token', cookieOptions)
      .clearCookie('refresh_token', cookieOptions)
      .json({ status: 'success' });
  })
);

export default router;
