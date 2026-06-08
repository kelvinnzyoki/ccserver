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
// Called by BOTH the Paystack webhook (async, server-to-server) and the
// /verify endpoint (client-side, after the payment redirect).
//
// Security guarantees:
//  1. IDEMPOTENT   — checks payment.status first; never double-bills or
//                    double-decrements stock no matter how many times it runs.
//  2. STOCK GUARD  — uses updateMany WHERE stock >= quantity; the DB rejects
//                    the write instead of letting stock go negative.
//  3. ATOMIC       — single Prisma $transaction; partial updates are impossible.

async function markPaid(orderId: string, ref: string): Promise<void> {
  const existing = await prisma.payment.findUnique({
    where: { orderId },
    select: { status: true },
  });

  // Already processed — webhook and verify both fired; first one won. Safe to exit.
  if (existing?.status === 'COMPLETED') return;

  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: { items: true },
  });

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

    for (const item of order.items) {
      // Only decrement if stock is sufficient — prevents negative stock.
      // updateMany returns { count: 0 } when WHERE matched nothing → roll back.
      const result = await tx.product.updateMany({
        where: { id: item.productId, stock: { gte: item.quantity } },
        data: { stock: { decrement: item.quantity } },
      });

      if (result.count === 0) {
        throw new ApiError(
          409,
          `Stock changed since checkout. Contact support — ref: ${ref}`
        );
      }
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

    // Ownership check — prevents one user verifying another user's payment
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

    // ── CRITICAL FIX: use req.rawBody, NOT JSON.stringify(req.body) ───────────
    // The HMAC must be computed over the exact raw bytes Paystack sent.
    // JSON.stringify re-serializes the already-parsed body and can differ in
    // whitespace/key order → HMAC always mismatched → webhook always 401
    // → markPaid never runs → stock never decrements after payment.
    //
    // req.rawBody is set in app.ts:
    //   express.json({ verify: (req, _res, buf) => { req.rawBody = buf } })
    const rawBody: Buffer | undefined = (req as any).rawBody;

    if (!rawBody) {
      console.error('[webhook] rawBody missing — check express.json verify in app.ts');
      return res.sendStatus(400);
    }

    const hash = crypto
      .createHmac('sha512', secret)
      .update(rawBody)           // ← raw Buffer, not re-serialized JSON
      .digest('hex');

    if (hash !== req.headers['x-paystack-signature']) {
      return res.sendStatus(401);
    }

    // Acknowledge immediately — Paystack has a short delivery timeout.
    // Slow DB work after this point will not cause a retry.
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
      await prisma.payment.update({
        where: { id: payment.id },
        data: { status: 'FAILED', failureReason: cb.ResultDesc },
      }).catch((err) => console.error('[mpesa-callback] update error:', err));
    }
  })
);

export default router;
