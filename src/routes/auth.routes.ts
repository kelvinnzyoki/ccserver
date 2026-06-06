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

const router = Router();

const registerSchema = z.object({
  body: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    phone: z.string().optional(),
    password: z.string().min(8),
  }),
});

const loginSchema = z.object({
  body: z.object({
    login: z.string().min(3).optional(),
    email: z.string().email().optional(),
    phone: z.string().min(7).optional(),
    password: z.string().min(1),
  }),
});

function getSessionId(req: any) {
  const value = req.headers['x-cart-session'];
  return Array.isArray(value) ? value[0] : value;
}

function normalizePhone(phone?: string) {
  if (!phone) return undefined;
  let p = phone.replace(/\s+/g, '');
  if (p.startsWith('07')) p = `254${p.slice(1)}`;
  if (p.startsWith('+')) p = p.slice(1);
  return p;
}

function publicUser(u: any) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, phone: u.phone };
}

async function mergeGuestCartIntoUser(sessionId: string | undefined, userId: string) {
  if (!sessionId) return;

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
      where: { cartId_productId: { cartId: userCart.id, productId: item.productId } },
      create: {
        cartId: userCart.id,
        productId: item.productId,
        quantity: item.quantity,
        price: item.price,
      },
      update: { quantity: { increment: item.quantity } },
    });
  }

  await prisma.cart.delete({ where: { id: guestCart.id } }).catch(() => undefined);
}

function setAuthCookies(res: any, access: string, refresh: string) {
  res.cookie('access_token', access, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
  res.cookie('refresh_token', refresh, { ...cookieOptions, maxAge: 30 * 86400 * 1000 });
}

router.post(
  '/register',
  authLimiter,
  validate(registerSchema),
  asyncHandler(async (req, res) => {
    const email = req.body.email.toLowerCase();
    const phone = normalizePhone(req.body.phone);

    const existing = await prisma.user.findFirst({
      where: { OR: [{ email }, ...(phone ? [{ phone }] : [])] },
    });
    if (existing) throw new ApiError(409, 'Email or phone already registered');

    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        email,
        phone,
        passwordHash: await bcrypt.hash(req.body.password, 12),
      },
    });

    await mergeGuestCartIntoUser(getSessionId(req), user.id);

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await persistRefresh(user.id, refresh);
    setAuthCookies(res, access, refresh);

    res.status(201).json({ status: 'success', data: { user: publicUser(user), accessToken: access } });
  })
);

router.post(
  '/login',
  authLimiter,
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const rawLogin = req.body.login || req.body.email || req.body.phone;
    if (!rawLogin) throw new ApiError(400, 'Email or phone is required');

    const login = String(rawLogin).trim();
    const email = login.includes('@') ? login.toLowerCase() : undefined;
    const phone = normalizePhone(login);

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

    await mergeGuestCartIntoUser(getSessionId(req), user.id);

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await persistRefresh(user.id, refresh);
    setAuthCookies(res, access, refresh);

    res.json({ status: 'success', data: { user: publicUser(user), accessToken: access } });
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
    await prisma.user.update({ where: { id: req.user!.id }, data: { refreshTokenHash: null } });
    res.clearCookie('access_token', cookieOptions).clearCookie('refresh_token', cookieOptions).json({ status: 'success' });
  })
);

export default router;
