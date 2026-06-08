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

async function markPaid(orderId: string, ref: string): Promise<void> {
  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    const paymentUpdate = await tx.payment.updateMany({
      where: {
        orderId,
        status: { not: 'COMPLETED' },
      },
      data: {
        status: 'COMPLETED',
        transactionRef: ref,
        paidAt: new Date(),
        failureReason: null,
      },
    });

    // Idempotency guard: webhook and browser verify may both arrive.
    if (paymentUpdate.count === 0) return;

    await tx.order.update({
      where: { id: orderId },
      data: { status: 'PAID' },
    });
  });
}

async function releaseReservedStock(orderId: string, reason: string): Promise<void> {
  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    const order = await tx.order.findUnique({
      where: { id: orderId },
      include: { items: true, payment: true },
    });

    if (!order || order.status !== 'PENDING' || order.payment?.status === 'COMPLETED') return;

    await tx.payment.updateMany({
      where: { orderId, status: { not: 'COMPLETED' } },
      data: { status: 'FAILED', failureReason: reason },
    });

    await tx.order.update({
      where: { id: orderId },
      data: { status: 'CANCELLED' },
    });

    for (const item of order.items) {
      await tx.product.update({
        where: { id: item.productId },
        data: { stock: { increment: item.quantity } },
      });
    }
  });
}

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
    if (order.status === 'CANCELLED') throw new ApiError(400, 'This order was cancelled');
    if (order.payment?.status === 'COMPLETED') throw new ApiError(400, 'This order has already been paid');

    // Reuse existing checkout URL/reference when present to prevent duplicate Paystack sessions.
    if (order.payment?.checkoutUrl && order.payment?.providerRef) {
      return res.json({
        status: 'success',
        data: {
          authorizationUrl: order.payment.checkoutUrl,
          reference: order.payment.providerRef,
        },
      });
    }

    const data = await paystack.initialize(order.id, order.email, Number(order.total));

    await prisma.payment.update({
      where: { orderId: order.id },
      data: {
        providerRef: data.reference,
        checkoutUrl: data.authorization_url,
      },
    });

    res.json({
      status: 'success',
      data: { authorizationUrl: data.authorization_url, reference: data.reference },
    });
  })
);

router.get(
  '/paystack/verify/:reference',
  requireAuth,
  asyncHandler(async (req, res) => {
    const payment = await prisma.payment.findFirst({ where: { providerRef: req.params.reference } });
    if (!payment) throw new ApiError(404, 'Payment record not found');

    const data = await paystack.verify(req.params.reference);

    if (data.status !== 'success') {
      await releaseReservedStock(payment.orderId, 'Paystack payment was not completed');
      throw new ApiError(400, 'Payment not completed');
    }

    await markPaid(payment.orderId, data.reference);
    res.json({ status: 'success' });
  })
);

router.post(
  '/paystack/webhook',
  asyncHandler(async (req, res) => {
    const secret = env.PAYSTACK_SECRET_KEY || '';
    const hash = crypto.createHmac('sha512', secret).update(JSON.stringify(req.body)).digest('hex');

    if (!secret || hash !== req.headers['x-paystack-signature']) {
      throw new ApiError(401, 'Invalid webhook signature');
    }

    const reference = req.body?.data?.reference;
    if (reference) {
      const payment = await prisma.payment.findFirst({ where: { providerRef: reference } });
      if (payment && req.body.event === 'charge.success') {
        await markPaid(payment.orderId, reference);
      }
      if (payment && (req.body.event === 'charge.failed' || req.body.event === 'charge.dispute.create')) {
        await releaseReservedStock(payment.orderId, `Paystack event: ${req.body.event}`);
      }
    }

    res.sendStatus(200);
  })
);

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
    if (order.status === 'CANCELLED') throw new ApiError(400, 'This order was cancelled');
    if (order.payment?.status === 'COMPLETED') throw new ApiError(400, 'This order has already been paid');

    const data = await mpesa.stkPush(order.id, req.body.phoneNumber, Number(order.total));

    await prisma.payment.update({
      where: { orderId: order.id },
      data: { providerRef: data.CheckoutRequestID, phoneNumber: req.body.phoneNumber },
    });

    res.json({ status: 'success', data });
  })
);

router.post(
  '/mpesa/callback',
  asyncHandler(async (req, res) => {
    const cb = req.body?.Body?.stkCallback;
    if (!cb) return res.sendStatus(200);

    const payment = await prisma.payment.findFirst({ where: { providerRef: cb.CheckoutRequestID } });
    if (!payment) return res.sendStatus(200);

    if (cb.ResultCode === 0) {
      const receipt =
        cb.CallbackMetadata?.Item?.find((x: { Name: string; Value?: string }) => x.Name === 'MpesaReceiptNumber')
          ?.Value || cb.CheckoutRequestID;

      await markPaid(payment.orderId, receipt);
    } else {
      await releaseReservedStock(payment.orderId, cb.ResultDesc || 'M-Pesa payment failed or was cancelled');
    }

    res.sendStatus(200);
  })
);

export default router;
