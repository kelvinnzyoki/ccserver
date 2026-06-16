import { Router } from 'express';
import { z } from 'zod';
import type { Prisma } from '@prisma/client';

import { prisma } from '../config/prisma.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { makeOrderNumber } from '../utils/orderNumber.js';

const router = Router();

const PENDING_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

const schema = z.object({
  body: z.object({
    paymentMethod: z.literal('PAYSTACK'),
    shippingAddress: z.object({
      firstName: z.string().min(2),
      lastName: z.string().min(2),
      phone: z.string().min(9),
      email: z.string().email().optional(),
      address1: z.string().min(3),
      address2: z.string().optional(),
      city: z.string().min(2),
      county: z.string().optional(),
      postalCode: z.string().optional(),
      country: z.string().default('Kenya'),
    }),
  }),
});

router.post(
  '/',
  requireAuth,
  validate(schema),
  asyncHandler(async (req, res) => {
    if (req.body.paymentMethod !== 'PAYSTACK') {
      throw new ApiError(503, 'M-Pesa payments are coming soon. Please use Paystack for now.');
    }

    const cart = await prisma.cart.findFirst({
      where: { userId: req.user!.id },
      include: { items: { include: { product: true } } },
    });

    if (!cart?.items.length) throw new ApiError(400, 'Cart is empty');

    for (const item of cart.items) {
      if (!item.product.isActive)
        throw new ApiError(400, `${item.product.name} is not available`);
      if (item.quantity < 1)
        throw new ApiError(400, 'Invalid cart quantity');
      if (item.product.stock < item.quantity) {
        throw new ApiError(
          400,
          `${item.product.name} has only ${item.product.stock} left in stock`
        );
      }
    }

    // ── FIX: Release stale pending orders before creating a new one ──────────
    // If the user previously started checkout but never paid, their stock
    // reservation would be locked forever. This cleanup restores that stock
    // and cancels those orders, so inventory stays accurate.
    // This runs OUTSIDE the main transaction and is intentionally non-fatal —
    // a cleanup failure must never block the new checkout attempt.
    try {
      const cutoff = new Date(Date.now() - PENDING_TIMEOUT_MS);
      const staleOrders = await prisma.order.findMany({
        where: {
          userId: req.user!.id,
          status: 'PENDING',
          createdAt: { lt: cutoff },
          payment: { status: 'PENDING' },
        },
        include: { items: true },
      });

      if (staleOrders.length > 0) {
        await prisma.$transaction(async (tx) => {
          for (const stale of staleOrders) {
            for (const item of stale.items) {
              await tx.product.update({
                where: { id: item.productId },
                data: { stock: { increment: item.quantity } },
              });
            }
            await tx.order.update({
              where: { id: stale.id },
              data: { status: 'CANCELLED' },
            });
            await tx.payment.updateMany({
              where: { orderId: stale.id, status: 'PENDING' },
              data: {
                status: 'FAILED',
                failureReason:
                  'Order expired — payment not completed within 30 minutes',
              },
            });
          }
        });
        console.log(
          `[checkout] Released ${staleOrders.length} stale order(s) for user ${req.user!.id}`
        );
      }
    } catch (staleErr) {
      console.error('[checkout] Stale order cleanup failed (non-fatal):', staleErr);
    }

    const subtotal = cart.items.reduce(
      (sum: number, item: (typeof cart.items)[number]) =>
        sum + Number(item.price) * item.quantity,
      0
    );
    const shippingCost = 0;
    const total = subtotal + shippingCost;

    const order = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      // Reserve stock at checkout. Uses a conditional updateMany so the DB
      // rejects writes that would push stock negative (stock >= quantity guard).
      for (const item of cart.items) {
        const updated = await tx.product.updateMany({
          where: {
            id: item.productId,
            isActive: true,
            stock: { gte: item.quantity },
          },
          data: { stock: { decrement: item.quantity } },
        });

        if (updated.count !== 1) {
          throw new ApiError(
            409,
            `${item.product.name} is no longer available in the requested quantity`
          );
        }
      }

      const address = await tx.address.create({
        data: {
          ...req.body.shippingAddress,
          userId: req.user!.id,
          email:
            req.body.shippingAddress.email || req.user!.email,
        },
      });

      const createdOrder = await tx.order.create({
        data: {
          orderNumber: makeOrderNumber(),
          userId: req.user!.id,
          email: req.user!.email,
          subtotal,
          shippingCost,
          total,
          paymentMethod: req.body.paymentMethod,
          shippingAddressId: address.id,
          items: {
            create: cart.items.map((item: (typeof cart.items)[number]) => ({
              productId: item.productId,
              productName: item.product.name,
              productImage: item.product.image,
              size: item.size,
              price: item.price,
              quantity: item.quantity,
              total: Number(item.price) * item.quantity,
            })),
          },
          payment: {
            create: {
              provider: req.body.paymentMethod,
              amount: total,
              currency: 'KES',
              metadata: { stockReserved: true },
            },
          },
        },
        include: { items: true, payment: true, shippingAddress: true },
      });

      await tx.cartItem.deleteMany({ where: { cartId: cart.id } });

      return createdOrder;
    });

    res.status(201).json({ status: 'success', data: { order } });
  })
);

export default router;
