import { Router } from 'express';
import type { Prisma } from '@prisma/client';
import { prisma } from '../config/prisma.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';

const router = Router();

// ─── Stale-order cleanup ──────────────────────────────────────────────────────
// A PENDING order means checkout was completed but payment never arrived.
// Stock was reserved at checkout creation to prevent overselling, so
// abandoned orders permanently hold inventory unless explicitly released.
//
// This runs before /mine returns so the user always sees accurate statuses
// and so released stock is immediately available to other buyers — without
// needing a cron job or a separate background process.
//
// Timeout: 30 minutes. Long enough for a slow M-Pesa PIN entry or a Paystack
// redirect, short enough that inventory isn't locked indefinitely.

const STALE_TIMEOUT_MINUTES = 30;

async function cleanupStaleOrders(userId: string): Promise<void> {
  const cutoff = new Date(Date.now() - STALE_TIMEOUT_MINUTES * 60 * 1000);

  const stale = await prisma.order.findMany({
    where: {
      userId,
      status: 'PENDING',
      createdAt: { lt: cutoff },
    },
    include: { items: true },
  });

  if (stale.length === 0) return;

  for (const order of stale) {
    await prisma
      .$transaction(async (tx: Prisma.TransactionClient) => {
        // Release stock back to products
        for (const item of order.items) {
          await tx.product.update({
            where: { id: item.productId },
            data: { stock: { increment: item.quantity } },
          });
        }

        // Cancel the order
        await tx.order.update({
          where: { id: order.id },
          data: { status: 'CANCELLED' },
        });

        // Mark payment as failed so the payment record doesn't stay PENDING
        await tx.payment.updateMany({
          where: { orderId: order.id, status: { not: 'COMPLETED' } },
          data: {
            status: 'FAILED',
            failureReason: `Payment not received within ${STALE_TIMEOUT_MINUTES} minutes — order auto-cancelled`,
          },
        });
      })
      .catch((err) =>
        // Non-fatal — log and continue; a failed cleanup is better than
        // crashing the entire order list response.
        console.error(`[orders] stale cleanup failed for ${order.id}:`, err)
      );
  }
}

// ─── GET /api/orders/mine ─────────────────────────────────────────────────────

router.get(
  '/mine',
  requireAuth,
  asyncHandler(async (req: any, res) => {
    // Release stale orders BEFORE listing — user sees accurate statuses
    // and freed stock is immediately visible to other shoppers.
    await cleanupStaleOrders(req.user.id).catch((err) =>
      console.error('[orders] cleanup error (non-fatal):', err)
    );

    const orders = await prisma.order.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' },
      include: {
        items: true,
        payment: { select: { status: true, provider: true, transactionRef: true, paidAt: true, phoneNumber: true } },
      },
    });

    res.json({ status: 'success', data: { orders } });
  })
);

// ─── GET /api/orders/:id ──────────────────────────────────────────────────────

router.get(
  '/:id',
  requireAuth,
  asyncHandler(async (req: any, res) => {
    const order = await prisma.order.findFirst({
      where: { id: req.params.id, userId: req.user.id },
      include: {
        items: true,
        payment: true,
        shippingAddress: true,
      },
    });

    if (!order) throw new ApiError(404, 'Order not found');

    res.json({ status: 'success', data: { order } });
  })
);

export default router;
