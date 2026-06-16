import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { optionalAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';

const router = Router();

function getSessionId(req: any) {
  const header = req.headers['x-cart-session'];
  const sessionId = Array.isArray(header) ? header[0] : header;
  return typeof sessionId === 'string' && sessionId.trim().length > 0
    ? sessionId.trim()
    : undefined;
}

async function getOrCreateCart(userId?: string, sessionId?: string) {
  if (userId) {
    return prisma.cart.upsert({
      where: { userId },
      create: { userId },
      update: {},
      include: {
        items: {
          include: { product: true },
          orderBy: { id: 'desc' },
        },
      },
    });
  }

  if (!sessionId) {
    throw new ApiError(400, 'Cart session is required');
  }

  return prisma.cart.upsert({
    where: { sessionId },
    create: { sessionId },
    update: {},
    include: {
      items: {
        include: { product: true },
        orderBy: { id: 'desc' },
      },
    },
  });
}

router.get(
  '/',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cart = await getOrCreateCart(req.user?.id, getSessionId(req));
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
        quantity: z.coerce.number().int().min(1).max(20).default(1),
        size: z.string().trim().optional(),
      }),
    })
  ),
  asyncHandler(async (req, res) => {
    const cart = await getOrCreateCart(req.user?.id, getSessionId(req));

    const product = await prisma.product.findUnique({
      where: { id: req.body.productId },
    });

    if (!product || !product.isActive) {
      throw new ApiError(404, 'Product unavailable');
    }

    if (product.stock < req.body.quantity) {
      throw new ApiError(400, 'Insufficient stock');
    }

    const requestedSize = req.body.size?.toUpperCase();

    if (product.sizes.length > 0) {
      if (!requestedSize) {
        throw new ApiError(400, 'Please select a size');
      }

      if (!product.sizes.map((size) => size.toUpperCase()).includes(requestedSize)) {
        throw new ApiError(400, 'Selected size is not available for this product');
      }
    }

    await prisma.cartItem.upsert({
      where: {
        cartId_productId_size: {
          cartId: cart.id,
          productId: product.id,
          size: requestedSize ?? null,
        },
      },
      create: {
        cartId: cart.id,
        productId: product.id,
        size: requestedSize,
        quantity: req.body.quantity,
        price: product.price,
      },
      update: {
        quantity: { increment: req.body.quantity },
        price: product.price,
      },
    });

    const updatedCart = await getOrCreateCart(req.user?.id, getSessionId(req));
    res.status(201).json({ status: 'success', data: { cart: updatedCart } });
  })
);

router.patch(
  '/items/:id',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const quantity = Number(req.body.quantity);
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 20) {
      throw new ApiError(400, 'Invalid quantity');
    }

    const cart = await getOrCreateCart(req.user?.id, getSessionId(req));

    const result = await prisma.cartItem.updateMany({
      where: { id: req.params.id, cartId: cart.id },
      data: { quantity },
    });

    if (result.count === 0) throw new ApiError(404, 'Cart item not found');

    const updatedCart = await getOrCreateCart(req.user?.id, getSessionId(req));
    res.json({ status: 'success', data: { cart: updatedCart } });
  })
);

router.delete(
  '/items/:id',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cart = await getOrCreateCart(req.user?.id, getSessionId(req));

    const result = await prisma.cartItem.deleteMany({
      where: { id: req.params.id, cartId: cart.id },
    });

    if (result.count === 0) throw new ApiError(404, 'Cart item not found');

    const updatedCart = await getOrCreateCart(req.user?.id, getSessionId(req));
    res.json({ status: 'success', data: { cart: updatedCart } });
  })
);

export default router;
