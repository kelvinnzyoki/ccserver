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

const schema = z.object({
  body: z.object({
    paymentMethod: z.enum(['MPESA', 'PAYSTACK']),
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
    const cart = await prisma.cart.findFirst({
      where: { userId: req.user!.id },
      include: { items: { include: { product: true } } },
    });

    if (!cart?.items.length) throw new ApiError(400, 'Cart is empty');

    for (const item of cart.items) {
      if (!item.product.isActive) throw new ApiError(400, `${item.product.name} is not available`);
      if (item.quantity < 1) throw new ApiError(400, 'Invalid cart quantity');
      if (item.product.stock < item.quantity) {
        throw new ApiError(400, `${item.product.name} has only ${item.product.stock} left in stock`);
      }
    }

    const subtotal = cart.items.reduce(
      (sum: number, item: (typeof cart.items)[number]) => sum + Number(item.price) * item.quantity,
      0
    );

    const shippingCost = 0;
    const total = subtotal + shippingCost;

    const order = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      // Reserve stock at checkout, not at add-to-cart. This prevents fake cart clicks
      // from draining inventory, while ensuring stock is locked before payment starts.
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
          throw new ApiError(409, `${item.product.name} is no longer available in the requested quantity`);
        }
      }

      const address = await tx.address.create({
        data: {
          ...req.body.shippingAddress,
          userId: req.user!.id,
          email: req.body.shippingAddress.email || req.user!.email,
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
