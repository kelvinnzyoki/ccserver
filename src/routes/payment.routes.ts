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

// ─── markPaid ─────────────────────────────────────────────────────────────────
// Called by BOTH the webhook (server-side, async) and the verify endpoint
// (client-side, after redirect).  Must be idempotent — if the webhook fires
// first and the user's browser verify call arrives 2 seconds later (or vice
// versa), we must not decrement stock twice or double-write the payment.

async function markPaid(orderId: string, ref: string): Promise<void> {
  const existing = await prisma.payment.findUnique({
    where: { orderId },
    select: { status: true },
  });

  // Already processed — bail out silently. This is not an error.
  if (existing?.status === 'COMPLETED') return;

  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: { items: true },
  });

  if (!order) throw new ApiError(404, 'Order not found');

  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    await tx.payment.update({
      where: { orderId },
      data: {
        status: 'COMPLETED',
        transactionRef: ref,
        paidAt: new Date(),
      },
    });

    await tx.order.update({
      where: { id: orderId },
      data: { status: 'PAID' },
    });

    // Decrement stock for every item in the order
    for (const item of order.items) {
      await tx.product.update({
        where: { id: item.productId },
        data: { stock: { decrement: item.quantity } },
      });
    }
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

    // Guard: don't re-initialize an already paid order
    if (order.payment?.status === 'COMPLETED') {
      throw new ApiError(400, 'This order has already been paid');
    }

    const data = await paystack.initialize(
      order.id,
      order.email,
      Number(order.total)
    );

    await prisma.payment.update({
      where: { orderId: order.id },
      data: {
        providerRef: data.reference,
        checkoutUrl: data.authorization_url,
      },
    });

    res.json({
      status: 'success',
      data: {
        authorizationUrl: data.authorization_url,
        reference: data.reference,
      },
    });
  })
);

// ─── Paystack: verify (called by frontend after redirect) ─────────────────────

router.get(
  '/paystack/verify/:reference',
  requireAuth,
  asyncHandler(async (req, res) => {
    const data = await paystack.verify(req.params.reference);

    if (data.status !== 'success') {
      throw new ApiError(400, 'Payment not completed');
    }

    const payment = await prisma.payment.findFirst({
      where: { providerRef: req.params.reference },
    });

    if (!payment) throw new ApiError(404, 'Payment record not found');

    // markPaid is idempotent — safe to call even if webhook already ran it
    await markPaid(payment.orderId, data.reference);

    res.json({ status: 'success' });
  })
);

// ─── Paystack: webhook (called by Paystack servers, async) ───────────────────

router.post(
  '/paystack/webhook',
  asyncHandler(async (req, res) => {
    const secret = env.PAYSTACK_SECRET_KEY || '';

    const hash = crypto
      .createHmac('sha512', secret)
      .update(JSON.stringify(req.body))
      .digest('hex');

    if (hash !== req.headers['x-paystack-signature']) {
      throw new ApiError(401, 'Invalid webhook signature');
    }

    if (req.body.event === 'charge.success') {
      const payment = await prisma.payment.findFirst({
        where: { providerRef: req.body.data.reference },
      });

      if (payment) {
        // markPaid is idempotent — safe even if verify already ran it
        await markPaid(payment.orderId, req.body.data.reference);
      }
    }

    // Always respond 200 to Paystack immediately
    res.sendStatus(200);
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

    const data = await mpesa.stkPush(
      order.id,
      req.body.phoneNumber,
      Number(order.total)
    );

    await prisma.payment.update({
      where: { orderId: order.id },
      data: {
        providerRef: data.CheckoutRequestID,
        phoneNumber: req.body.phoneNumber,
      },
    });

    res.json({ status: 'success', data });
  })
);

// ─── M-Pesa: callback (called by Safaricom servers) ──────────────────────────

router.post(
  '/mpesa/callback',
  asyncHandler(async (req, res) => {
    const cb = req.body?.Body?.stkCallback;

    if (!cb) return res.sendStatus(200);

    const payment = await prisma.payment.findFirst({
      where: { providerRef: cb.CheckoutRequestID },
    });

    if (!payment) return res.sendStatus(200);

    if (cb.ResultCode === 0) {
      const receipt =
        cb.CallbackMetadata?.Item?.find(
          (x: { Name: string; Value?: string }) => x.Name === 'MpesaReceiptNumber'
        )?.Value || cb.CheckoutRequestID;

      await markPaid(payment.orderId, receipt);
    } else {
      // Only mark failed if not already completed
      if (payment.status !== 'COMPLETED') {
        await prisma.payment.update({
          where: { id: payment.id },
          data: { status: 'FAILED', failureReason: cb.ResultDesc },
        });
      }
    }

    res.sendStatus(200);
  })
);

export default router;
