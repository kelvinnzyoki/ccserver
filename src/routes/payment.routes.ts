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
import { notifyOwnerPaymentReceived } from '../services/notifications.service.js';

const router = Router();

// ─── releaseOrderStock ────────────────────────────────────────────────────────

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

  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: { user: { select: { name: true } } },
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
  });

  // ── Owner SMS notification ───────────────────────────────────────────────
  // Fires AFTER the transaction commits so a failed SMS never rolls back a
  // confirmed payment. Non-fatal — trySendSms already swallows errors.
  notifyOwnerPaymentReceived({
    orderNumber: order.orderNumber,
    customerName: (order as any).user?.name ?? 'Customer',
    total: Number(order.total),
    method: order.paymentMethod,
    transactionRef: ref,
  }).catch((err) => console.error('[notify] owner SMS error:', err));
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
    const secret = env.PAYSTACK_SECRET_KEY;

    // ── FIX 1: refuse rather than computing HMAC with an empty key ───────────
    // HMAC-SHA512('') is computable by ANYONE without knowing the real secret.
    // If PAYSTACK_SECRET_KEY were ever unset, the hash-comparison below would
    // still "succeed" for a forged signature — an attacker (or a curious
    // legitimate user, using their own `reference` from /paystack/initialize)
    // could POST {"event":"charge.success","data":{"reference":"<theirs>"}}
    // with a self-computed signature and get markPaid called for free.
    if (!secret) {
      console.error('[webhook] PAYSTACK_SECRET_KEY not configured — rejecting webhook');
      return res.sendStatus(503);
    }

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
        try {
          // ── FIX 2: defense-in-depth — confirm with Paystack's own API ──────
          // Even with a valid HMAC, independently call Paystack's verify
          // endpoint (the same call /paystack/verify makes) before marking
          // paid. This means markPaid can ONLY be reached if Paystack's own
          // servers confirm the transaction succeeded — not just because a
          // webhook body said so.
          const verify = await paystack.verify(req.body.data.reference);
          if (verify.status === 'success') {
            await markPaid(payment.orderId, req.body.data.reference);
          } else {
            console.error(
              `[webhook] Paystack verify did not confirm success for ${req.body.data.reference} (status: ${verify.status})`
            );
          }
        } catch (err) {
          console.error('[webhook] verify/markPaid error:', err);
        }
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
    res.sendStatus(200); // Acknowledge immediately — Safaricom expects fast ack

    const cb = req.body?.Body?.stkCallback;
    if (!cb) return;

    const payment = await prisma.payment.findFirst({
      where: { providerRef: cb.CheckoutRequestID },
    });

    if (!payment) return;

    // Already settled — nothing to do (idempotent, avoids a redundant stkQuery call)
    if (payment.status === 'COMPLETED') return;

    if (cb.ResultCode === 0) {
      // ── FIX: defense-in-depth — confirm with Safaricom's STK Query API ────
      // Safaricom does NOT sign callbacks. A user who received their own
      // CheckoutRequestID (returned by /mpesa/stk/:orderId to their browser)
      // could POST a forged callback claiming ResultCode: 0 without ever
      // entering their M-Pesa PIN. Before trusting that, independently ask
      // Safaricom — using OUR credentials, which a client cannot forge —
      // whether the transaction actually completed.
      let confirmed = false;
      try {
        const query = await mpesa.stkQuery(cb.CheckoutRequestID);
        confirmed = String(query.ResultCode) === '0';
        if (!confirmed) {
          console.error(
            `[mpesa-callback] stkQuery did not confirm success for ${cb.CheckoutRequestID}: ${query.ResultDesc}`
          );
        }
      } catch (err) {
        console.error(
          '[mpesa-callback] stkQuery failed:',
          (err as any)?.response?.data ?? err
        );
      }

      if (!confirmed) {
        // Do not mark paid, and do not mark failed either — the real
        // transaction may still be processing on Safaricom's side and a
        // later legitimate callback could still arrive. Leave PENDING.
        return;
      }

      // Secondary check: the amount Safaricom's callback says was paid must
      // match the order total. Cheap, and catches tampering or stale refs.
      const callbackAmount = cb.CallbackMetadata?.Item?.find(
        (x: { Name: string; Value?: number }) => x.Name === 'Amount'
      )?.Value;

      const order = await prisma.order.findUnique({
        where: { id: payment.orderId },
        select: { total: true },
      });

      if (
        callbackAmount != null &&
        order &&
        Number(callbackAmount) !== Number(order.total)
      ) {
        console.error(
          `[mpesa-callback] Amount mismatch for order ${payment.orderId}: paid ${callbackAmount}, expected ${order.total}`
        );
        return; // Flag for manual review — do not auto-mark paid
      }

      const receipt =
        cb.CallbackMetadata?.Item?.find(
          (x: { Name: string; Value?: string }) => x.Name === 'MpesaReceiptNumber'
        )?.Value || cb.CheckoutRequestID;

      await markPaid(payment.orderId, receipt).catch((err) =>
        console.error('[mpesa-callback] markPaid error:', err)
      );
    } else {
      // ── Double-release guard ─────────────────────────────────────────────
      // The stale-order cleanup in checkout.routes.ts can independently
      // cancel a PENDING order and release its stock after 30 minutes.
      // If Safaricom's failure callback arrives AFTER that cleanup already
      // ran, this would release stock a second time — over-crediting
      // inventory. Check the order's CURRENT status inside the transaction;
      // if already CANCELLED, stock was already released — skip silently.
      await prisma
        .$transaction(async (tx) => {
          const order = await tx.order.findUnique({
            where: { id: payment.orderId },
            select: { status: true },
          });

          if (!order || order.status === 'CANCELLED') {
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
