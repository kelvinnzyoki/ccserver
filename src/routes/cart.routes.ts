import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { optionalAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { getOrCreateCart, normalizeCartSession } from '../services/cart.service.js';

const router = Router();

const itemSchema = z.object({
  body: z.object({
    productId: z.string().uuid(),
    quantity: z.number().int().min(1).max(20).default(1),
  }),
});

function cartSession(req: any) {
  return normalizeCartSession(req.headers['x-cart-session']);
}

async function currentCart(req: any) {
  const cart = await getOrCreateCart(req.user?.id, cartSession(req));

  if (!cart) {
    throw new ApiError(400, 'Missing guest cart session');
  }

  return cart;
}

router.get(
  '/',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cart = await getOrCreateCart(req.user?.id, cartSession(req));

    res.json({
      status: 'success',
      data: { cart: cart ?? { items: [] } },
    });
  })
);

router.post(
  '/items',
  optionalAuth,
  validate(itemSchema),
  asyncHandler(async (req, res) => {
    const cart = await currentCart(req);
    const product = await prisma.product.findUnique({
      where: { id: req.body.productId },
    });

    if (!product || !product.isActive) {
      throw new ApiError(404, 'Product unavailable');
    }

    if (product.stock < req.body.quantity) {
      throw new ApiError(400, 'Insufficient stock');
    }

    await prisma.cartItem.upsert({
      where: {
        cartId_productId: {
          cartId: cart.id,
          productId: product.id,
        },
      },
      create: {
        cartId: cart.id,
        productId: product.id,
        quantity: req.body.quantity,
        price: product.price,
      },
      update: {
        quantity: {
          increment: req.body.quantity,
        },
      },
    });

    res.status(201).json({
      status: 'success',
      data: { cart: await getOrCreateCart(req.user?.id, cartSession(req)) },
    });
  })
);

router.patch(
  '/items/:id',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const qty = Number(req.body.quantity);

    if (!Number.isInteger(qty) || qty < 1 || qty > 20) {
      throw new ApiError(400, 'Invalid quantity');
    }

    const cart = await currentCart(req);
    const item = await prisma.cartItem.findFirst({
      where: {
        id: req.params.id,
        cartId: cart.id,
      },
    });

    if (!item) throw new ApiError(404, 'Cart item not found');

    await prisma.cartItem.update({
      where: { id: item.id },
      data: { quantity: qty },
    });

    res.json({
      status: 'success',
      data: { cart: await getOrCreateCart(req.user?.id, cartSession(req)) },
    });
  })
);

router.delete(
  '/items/:id',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cart = await currentCart(req);
    const item = await prisma.cartItem.findFirst({
      where: {
        id: req.params.id,
        cartId: cart.id,
      },
    });

    if (!item) throw new ApiError(404, 'Cart item not found');

    await prisma.cartItem.delete({
      where: { id: item.id },
    });

    res.json({
      status: 'success',
      data: { cart: await getOrCreateCart(req.user?.id, cartSession(req)) },
    });
  })
);

export default router;
