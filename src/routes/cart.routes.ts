import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { optionalAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';

const router = Router();

function getSessionId(req: any) {
  const value = req.headers['x-cart-session'];
  return Array.isArray(value) ? value[0] : value;
}

async function getCart(userId?: string, sessionId?: string) {
  if (userId) {
    return prisma.cart.upsert({
      where: { userId },
      create: { userId },
      update: {},
      include: { items: { include: { product: true }, orderBy: { id: 'desc' } } },
    });
  }

  if (!sessionId) throw new ApiError(400, 'Cart session is required');

  return prisma.cart.upsert({
    where: { sessionId },
    create: { sessionId },
    update: {},
    include: { items: { include: { product: true }, orderBy: { id: 'desc' } } },
  });
}

router.get(
  '/',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cart = await getCart(req.user?.id, getSessionId(req));
    res.json({ status: 'success', data: { cart } });
  })
);

router.post(
  '/items',
  optionalAuth,
  validate(
    z.object({
      body: z.object({
        productId: z.string().uuid(),
        quantity: z.number().int().min(1).max(20).default(1),
      }),
    })
  ),
  asyncHandler(async (req, res) => {
    const cart = await getCart(req.user?.id, getSessionId(req));
    const product = await prisma.product.findUnique({ where: { id: req.body.productId } });

    if (!product || !product.isActive) throw new ApiError(404, 'Product unavailable');
    if (product.stock < req.body.quantity) throw new ApiError(400, 'Insufficient stock');

    await prisma.cartItem.upsert({
      where: { cartId_productId: { cartId: cart.id, productId: product.id } },
      create: {
        cartId: cart.id,
        productId: product.id,
        quantity: req.body.quantity,
        price: product.price,
      },
      update: { quantity: { increment: req.body.quantity } },
    });

    res.status(201).json({ status: 'success', data: { cart: await getCart(req.user?.id, getSessionId(req)) } });
  })
);

router.patch(
  '/items/:id',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const qty = Number(req.body.quantity);
    if (!Number.isInteger(qty) || qty < 1 || qty > 20) throw new ApiError(400, 'Invalid quantity');

    const cart = await getCart(req.user?.id, getSessionId(req));
    const result = await prisma.cartItem.updateMany({
      where: { id: req.params.id, cartId: cart.id },
      data: { quantity: qty },
    });

    if (result.count === 0) throw new ApiError(404, 'Cart item not found');

    res.json({ status: 'success', data: { cart: await getCart(req.user?.id, getSessionId(req)) } });
  })
);

router.delete(
  '/items/:id',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cart = await getCart(req.user?.id, getSessionId(req));
    const result = await prisma.cartItem.deleteMany({ where: { id: req.params.id, cartId: cart.id } });
    if (result.count === 0) throw new ApiError(404, 'Cart item not found');
    res.json({ status: 'success', data: { cart: await getCart(req.user?.id, getSessionId(req)) } });
  })
);

export default router;
