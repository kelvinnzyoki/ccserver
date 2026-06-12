import { Router } from 'express';
import crypto from 'crypto';
import type { Prisma } from '@prisma/client';

import { prisma } from '../config/prisma.js';
import { requireAuth } from '../middleware/auth.js';
import { paymentLimiter } from '../middleware/security.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { paystack } from '../services/paystack.service.js';
import { mpesa } from '../services/mpesa.service.js';
import { env } from '../config/env.js';

const router = Router();

// ─── releaseOrderStock ────────────────────────────────────────────────────────
// Restores stock for every item in an order back to the product.
// Called when a payment explicitly fails (M-Pesa ResultCode !== 0) or an order
// is cancelled by the stale-order cleanup in checkout.routes.ts.

async function releaseOrderStock(
  orderId: string,
  tx: Prisma.TransactionClient
): Promise<void> {
  const order = await tx.order.findUnique({
    where: { id: orderId },
    include: { items: true },
  });
  if (!order) return;

  for (const item of order.items) {
    await tx.product.update({
      where: { id: item.productId },
      data: { stock: { increment: item.quantity } },
    });
  }
}

// ─── markPaid ─────────────────────────────────────────────────────────────────
// Stock is decremented (reserved) at checkout creation, NOT here.
//
// Security guarantees:
//  1. IDEMPOTENT — checks payment.status first; safe to call multiple times.
//  2. ATOMIC     — single Prisma $transaction; partial updates are impossible.

async function markPaid(orderId: string, ref: string): Promise<void> {
  const existing = await prisma.payment.findUnique({
    where: { orderId },
    select: { status: true },
  });

  if (existing?.status === 'COMPLETED') return;

  const order = await prisma.order.findUnique({ where: { id: orderId } });
  if (!order) throw new ApiError(404, 'Order not found');

  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    await tx.payment.update({
      where: { orderId },
      data: { status: 'COMPLETED', transactionRef: ref, paidAt: new Date() },
    });

    await tx.order.update({
      where: { id: orderId },
      data: { status: 'PAID' },
    });
  });
}

// ─── Paystack: initialize ─────────────────────────────────────────────────────

router.post(
  '/paystack/initialize/:orderId',
  requireAuth,
  paymentLimiter,
  asyncHandler(async (req, res) => {
    const order = await prisma.order.findFirst({
      where: { id: req.params.orderId, userId: req.user!.id },
      include: { payment: true },
    });

    if (!order) throw new ApiError(404, 'Order not found');
    if (order.payment?.status === 'COMPLETED') {
      throw new ApiError(400, 'This order has already been paid');
    }

    const data = await paystack.initialize(order.id, order.email, Number(order.total));

    await prisma.payment.update({
      where: { orderId: order.id },
      data: { providerRef: data.reference, checkoutUrl: data.authorization_url },
    });

    res.json({
      status: 'success',
      data: {
        authorizationUrl: data.authorization_url,
        authorization_url: data.authorization_url,
        reference: data.reference,
      },
    });
  })
);

// ─── Paystack: verify (client-side after redirect) ────────────────────────────

router.get(
  '/paystack/verify/:reference',
  requireAuth,
  asyncHandler(async (req, res) => {
    const data = await paystack.verify(req.params.reference);

    if (data.status !== 'success') {
      throw new ApiError(400, 'Payment not completed by Paystack');
    }

    const payment = await prisma.payment.findFirst({
      where: {
        providerRef: req.params.reference,
        order: { userId: req.user!.id },
      },
    });

    if (!payment) throw new ApiError(404, 'Payment record not found');

    await markPaid(payment.orderId, data.reference);

    res.json({ status: 'success' });
  })
);

// ─── Paystack: webhook (Paystack servers → our backend, async) ────────────────

router.post(
  '/paystack/webhook',
  asyncHandler(async (req, res) => {
    const secret = env.PAYSTACK_SECRET_KEY || '';

    const rawBody: Buffer | undefined = (req as any).rawBody;

    if (!rawBody) {
      console.error('[webhook] rawBody missing — check express.json verify in app.ts');
      return res.sendStatus(400);
    }

    const hash = crypto
      .createHmac('sha512', secret)
      .update(rawBody)
      .digest('hex');

    if (hash !== req.headers['x-paystack-signature']) {
      return res.sendStatus(401);
    }

    res.sendStatus(200);

    if (req.body.event === 'charge.success') {
      const payment = await prisma.payment.findFirst({
        where: { providerRef: req.body.data.reference },
      });

      if (payment) {
        await markPaid(payment.orderId, req.body.data.reference).catch((err) =>
          console.error('[webhook] markPaid error:', err)
        );
      }
    }
  })
);

// ─── M-Pesa: STK push ────────────────────────────────────────────────────────

router.post(
  '/mpesa/stk/:orderId',
  requireAuth,
  paymentLimiter,
  asyncHandler(async (req, res) => {
    const order = await prisma.order.findFirst({
      where: { id: req.params.orderId, userId: req.user!.id },
      include: { payment: true },
    });

    if (!order) throw new ApiError(404, 'Order not found');
    if (order.payment?.status === 'COMPLETED') {
      throw new ApiError(400, 'This order has already been paid');
    }

    const data = await mpesa.stkPush(order.id, req.body.phoneNumber, Number(order.total));

    await prisma.payment.update({
      where: { orderId: order.id },
      data: { providerRef: data.CheckoutRequestID, phoneNumber: req.body.phoneNumber },
    });

    res.json({ status: 'success', data });
  })
);

// ─── M-Pesa: callback (Safaricom → our backend, async) ───────────────────────

router.post(
  '/mpesa/callback',
  asyncHandler(async (req, res) => {
    res.sendStatus(200); // Acknowledge immediately

    const cb = req.body?.Body?.stkCallback;
    if (!cb) return;

    const payment = await prisma.payment.findFirst({
      where: { providerRef: cb.CheckoutRequestID },
    });

    if (!payment) return;

    if (cb.ResultCode === 0) {
      const receipt =
        cb.CallbackMetadata?.Item?.find(
          (x: { Name: string; Value?: string }) => x.Name === 'MpesaReceiptNumber'
        )?.Value || cb.CheckoutRequestID;

      await markPaid(payment.orderId, receipt).catch((err) =>
        console.error('[mpesa-callback] markPaid error:', err)
      );
    } else if (payment.status !== 'COMPLETED') {
      // ── FIX: double-release guard ─────────────────────────────────────────
      // The stale-order cleanup in checkout.routes.ts can independently cancel
      // a PENDING order and release its stock if 30+ minutes pass with no
      // payment. If Safaricom's failure callback arrives AFTER that cleanup
      // already ran, this branch would run releaseOrderStock a second time on
      // the same order — over-crediting inventory.
      //
      // Fix: check the order's CURRENT status inside the transaction. If it's
      // already CANCELLED, stock was already released — skip silently.
      await prisma
        .$transaction(async (tx) => {
          const order = await tx.order.findUnique({
            where: { id: payment.orderId },
            select: { status: true },
          });

          if (!order || order.status === 'CANCELLED') {
            // Already released (e.g. by stale-order cleanup) — just sync
            // the payment record so it doesn't stay PENDING forever.
            await tx.payment.update({
              where: { id: payment.id },
              data: { status: 'FAILED', failureReason: cb.ResultDesc },
            });
            return;
          }

          await releaseOrderStock(payment.orderId, tx);

          await tx.payment.update({
            where: { id: payment.id },
            data: { status: 'FAILED', failureReason: cb.ResultDesc },
          });

          await tx.order.update({
            where: { id: payment.orderId },
            data: { status: 'CANCELLED' },
          });
        })
        .catch((err) => console.error('[mpesa-callback] release error:', err));
    }
  })
);

export default router;
