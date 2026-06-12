import { Router } from 'express';
import { prisma } from '../config/prisma.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';

const router = Router();

// ─── All orders for the current user ─────────────────────────────────────────

router.get(
  '/mine',
  requireAuth,
  asyncHandler(async (req, res) => {
    const orders = await prisma.order.findMany({
      where: { userId: req.user!.id },
      include: { items: true, payment: true },
      orderBy: { createdAt: 'desc' },
    });
    res.json({ status: 'success', data: { orders } });
  })
);

// ─── Single order by ID ───────────────────────────────────────────────────────
// FIX: new endpoint — was missing, causing api.order(id) to 404 on the frontend.
// Ownership is enforced via userId so users can only fetch their own orders.

router.get(
  '/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const order = await prisma.order.findFirst({
      where: { id: req.params.id, userId: req.user!.id },
      include: { items: true, payment: true, shippingAddress: true },
    });

    if (!order) throw new ApiError(404, 'Order not found');

    res.json({ status: 'success', data: { order } });
  })
);

export default router;
