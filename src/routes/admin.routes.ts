import { Router } from 'express';
import { z } from 'zod';
import type { OrderStatus } from '@prisma/client';
import { prisma } from '../config/prisma.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';

const router = Router();
router.use(requireAuth, requireAdmin);

// ─── Dashboard stats ────────────────────────────────────────────────────────
// Powers the admin overview: revenue, order counts, customer counts, low
// stock alerts, and a 30-day sales series for the chart.

router.get(
  '/stats',
  asyncHandler(async (_req, res) => {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    // Revenue only counts orders that have actually been paid —
    // PENDING/CANCELLED orders never represent real money received.
    const PAID_STATUSES: OrderStatus[] = ['PAID', 'PROCESSING', 'SHIPPED', 'DELIVERED'];

    const [
      totalRevenueAgg,
      todayRevenueAgg,
      last7DaysRevenueAgg,
      totalOrders,
      pendingOrders,
      paidOrdersLast30,
      totalCustomers,
      newCustomersLast30,
      lowStockProducts,
      outOfStockCount,
      recentOrders,
      topProducts,
      revenueByDay,
    ] = await Promise.all([
      // Total all-time revenue
      prisma.order.aggregate({
        where: { status: { in: PAID_STATUSES } },
        _sum: { total: true },
      }),
      // Today's revenue
      prisma.order.aggregate({
        where: {
          status: { in: PAID_STATUSES },
          createdAt: { gte: startOfToday },
        },
        _sum: { total: true },
      }),
      // Last 7 days revenue
      prisma.order.aggregate({
        where: {
          status: { in: PAID_STATUSES },
          createdAt: { gte: sevenDaysAgo },
        },
        _sum: { total: true },
      }),
      // Total order count (all statuses)
      prisma.order.count(),
      // Orders awaiting payment right now
      prisma.order.count({ where: { status: 'PENDING' } }),
      // Paid orders in the last 30 days (for the chart denominator context)
      prisma.order.count({
        where: {
          status: { in: PAID_STATUSES },
          createdAt: { gte: thirtyDaysAgo },
        },
      }),
      // Total registered customers
      prisma.user.count({ where: { role: 'USER' } }),
      // New customers in the last 30 days
      prisma.user.count({
        where: { role: 'USER', createdAt: { gte: thirtyDaysAgo } },
      }),
      // Products running low (stock between 1 and 5)
      prisma.product.findMany({
        where: { isActive: true, stock: { gt: 0, lte: 5 } },
        select: { id: true, name: true, stock: true, image: true, slug: true },
        orderBy: { stock: 'asc' },
        take: 10,
      }),
      // Completely out of stock
      prisma.product.count({ where: { isActive: true, stock: 0 } }),
      // Most recent orders for the activity feed
      prisma.order.findMany({
        orderBy: { createdAt: 'desc' },
        take: 8,
        include: {
          user: { select: { name: true, email: true, phone: true } },
          payment: { select: { status: true, provider: true } },
          items: { select: { quantity: true } },
        },
      }),
      // Top-selling products by units sold (all time)
      prisma.orderItem.groupBy({
        by: ['productId', 'productName', 'productImage'],
        _sum: { quantity: true, total: true },
        orderBy: { _sum: { quantity: 'desc' } },
        take: 5,
      }),
      // Daily revenue for the last 30 days — built in JS since Prisma's
      // query builder doesn't support GROUP BY DATE() portably across
      // providers. 30 days is small enough this is cheap and reliable.
      prisma.order.findMany({
        where: {
          status: { in: PAID_STATUSES },
          createdAt: { gte: thirtyDaysAgo },
        },
        select: { total: true, createdAt: true },
      }),
    ]);

    // Bucket revenueByDay into a 30-entry array, oldest → newest
    const dayBuckets: Record<string, number> = {};
    for (let i = 29; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const key = d.toISOString().slice(0, 10);
      dayBuckets[key] = 0;
    }
    for (const order of revenueByDay) {
      const key = order.createdAt.toISOString().slice(0, 10);
      if (key in dayBuckets) dayBuckets[key] += Number(order.total);
    }
    const salesSeries = Object.entries(dayBuckets).map(([date, revenue]) => ({
      date,
      revenue: Math.round(revenue),
    }));

    res.json({
      status: 'success',
      data: {
        revenue: {
          total: Number(totalRevenueAgg._sum?.total ?? 0),
          today: Number(todayRevenueAgg._sum?.total ?? 0),
          last7Days: Number(last7DaysRevenueAgg._sum?.total ?? 0),
        },
        orders: {
          total: totalOrders,
          pending: pendingOrders,
          paidLast30Days: paidOrdersLast30,
        },
        customers: {
          total: totalCustomers,
          newLast30Days: newCustomersLast30,
        },
        inventory: {
          lowStock: lowStockProducts,
          outOfStockCount,
        },
        recentOrders: recentOrders.map((o) => ({
          id: o.id,
          orderNumber: o.orderNumber,
          customerId: o.userId,
          customerName: o.user?.name ?? 'Unknown',
          customerContact: o.user?.email ?? o.user?.phone ?? '',
          status: o.status,
          total: Number(o.total),
          itemCount: o.items.reduce((s, i) => s + i.quantity, 0),
          paymentProvider: o.payment?.provider ?? o.paymentMethod,
          paymentStatus: o.payment?.status ?? 'PENDING',
          createdAt: o.createdAt,
        })),
        topProducts: topProducts.map((p) => ({
          productId: p.productId,
          name: p.productName,
          image: p.productImage,
          unitsSold: p._sum.quantity ?? 0,
          revenue: Number(p._sum.total ?? 0),
        })),
        salesSeries,
      },
    });
  })
);

// ─── Orders: list with filters ─────────────────────────────────────────────────

const listOrdersQuery = z.object({
  query: z.object({
    status: z.string().optional(),
    search: z.string().optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  }),
});

router.get(
  '/orders',
  validate(listOrdersQuery),
  asyncHandler(async (req: any, res) => {
    const { status, search, page, limit } = req.validated.query;

    const where: any = {};
    if (status && status !== 'ALL') where.status = status;
    if (search) {
      where.OR = [
        { orderNumber: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
        { user: { name: { contains: search, mode: 'insensitive' } } },
      ];
    }

    const [orders, total] = await Promise.all([
      prisma.order.findMany({
        where,
        include: { items: true, payment: true, user: true, shippingAddress: true },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.order.count({ where }),
    ]);

    res.json({
      status: 'success',
      data: { orders, total, page, totalPages: Math.ceil(total / limit) },
    });
  })
);

// ─── Orders: update status ──────────────────────────────────────────────────────
// For fulfilment progression (PROCESSING → SHIPPED → DELIVERED) and manual
// CANCELLED/REFUNDED overrides. Does NOT touch payment status or stock —
// those are owned exclusively by payment.routes.ts to avoid two code paths
// fighting over the same state.

const updateOrderStatusSchema = z.object({
  body: z.object({
    status: z.enum([
      'PENDING', 'PAID', 'PROCESSING', 'SHIPPED', 'DELIVERED', 'CANCELLED', 'REFUNDED',
    ]),
  }),
});

router.patch(
  '/orders/:id/status',
  validate(updateOrderStatusSchema),
  asyncHandler(async (req, res) => {
    const order = await prisma.order.findUnique({ where: { id: req.params.id } });
    if (!order) throw new ApiError(404, 'Order not found');

    // Guard against accidentally "un-cancelling" stock-released orders back
    // into an active state without restoring stock — manual recovery should
    // go through a deliberate re-order, not a status flip.
    if (order.status === 'CANCELLED' && req.body.status !== 'CANCELLED') {
      throw new ApiError(
        400,
        'Cannot reactivate a cancelled order — stock was already released. Create a new order instead.'
      );
    }

    const updated = await prisma.order.update({
      where: { id: req.params.id },
      data: { status: req.body.status },
    });

    res.json({ status: 'success', data: { order: updated } });
  })
);

// ─── Products: list (admin view — includes inactive) ──────────────────────────

const listProductsQuery = z.object({
  query: z.object({
    search: z.string().optional(),
    category: z.string().optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  }),
});

router.get(
  '/products',
  validate(listProductsQuery),
  asyncHandler(async (req: any, res) => {
    const { search, category, page, limit } = req.validated.query;

    const where: any = {};
    if (category) where.category = category;
    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { slug: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [products, total] = await Promise.all([
      prisma.product.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.product.count({ where }),
    ]);

    res.json({
      status: 'success',
      data: { products, total, page, totalPages: Math.ceil(total / limit) },
    });
  })
);

// ─── Products: create ─────────────────────────────────────────────────────────

const createProductSchema = z.object({
  body: z.object({
    name: z.string().min(1),
    slug: z.string().min(1).regex(/^[a-z0-9-]+$/, 'Slug must be lowercase with hyphens only'),
    description: z.string().min(1),
    price: z.number().positive(),
    image: z.string().url(),
    category: z.string().min(1),
    stock: z.number().int().min(0),
    sizes: z.array(z.string()).default([]),
    colors: z.array(z.string()).default([]),
    featured: z.boolean().default(false),
    isActive: z.boolean().default(true),
  }),
});

router.post(
  '/products',
  validate(createProductSchema),
  asyncHandler(async (req, res) => {
    const product = await prisma.product.create({ data: req.body });
    res.status(201).json({ status: 'success', data: { product } });
  })
);

// ─── Products: update ─────────────────────────────────────────────────────────

const updateProductSchema = z.object({
  body: z.object({
    name: z.string().min(1).optional(),
    description: z.string().min(1).optional(),
    price: z.number().positive().optional(),
    image: z.string().url().optional(),
    category: z.string().min(1).optional(),
    stock: z.number().int().min(0).optional(),
    sizes: z.array(z.string()).optional(),
    colors: z.array(z.string()).optional(),
    featured: z.boolean().optional(),
    isActive: z.boolean().optional(),
  }),
});

router.patch(
  '/products/:id',
  validate(updateProductSchema),
  asyncHandler(async (req, res) => {
    const product = await prisma.product.update({
      where: { id: req.params.id },
      data: req.body,
    });
    res.json({ status: 'success', data: { product } });
  })
);

// ─── Products: delete ───────────────────────────────────────────────────────────
// Soft-delete by default (isActive: false) to preserve order history
// integrity — OrderItem rows reference productId and would break display
// of past orders if the product were hard-deleted. ?hard=true forces a real
// ─── Products: get one ──────────────────────────────────────────────────────────
// Used by the "Edit" deep-link (?edit=<id>) so opening the edit form never
// depends on that product happening to be on the currently loaded page of
// the paginated list — which was the root cause of edit links silently
// doing nothing for any product beyond page 1.

router.get(
  '/products/:id',
  asyncHandler(async (req, res) => {
    const product = await prisma.product.findUnique({ where: { id: req.params.id } });
    if (!product) throw new ApiError(404, 'Product not found');
    res.json({ status: 'success', data: { product } });
  })
);

// ─── Products: delete ───────────────────────────────────────────────────────────
// Soft-delete by default (isActive: false) to preserve order history
// integrity — OrderItem rows reference productId and would break display
// of past orders if the product were hard-deleted. ?hard=true forces a real
// delete, which will fail with a clear error if the product has any orders.

router.delete(
  '/products/:id',
  asyncHandler(async (req, res) => {
    const hard = req.query.hard === 'true';

    if (!hard) {
      const product = await prisma.product.update({
        where: { id: req.params.id },
        data: { isActive: false },
      });
      return res.json({ status: 'success', data: { product }, message: 'Product deactivated' });
    }

    const orderItemCount = await prisma.orderItem.count({
      where: { productId: req.params.id },
    });
    if (orderItemCount > 0) {
      throw new ApiError(
        400,
        `Cannot permanently delete — this product appears in ${orderItemCount} past order(s). Deactivate it instead.`
      );
    }

    await prisma.product.delete({ where: { id: req.params.id } });
    res.json({ status: 'success', message: 'Product permanently deleted' });
  })
);

// ─── Customers: list ────────────────────────────────────────────────────────────

const listCustomersQuery = z.object({
  query: z.object({
    search: z.string().optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  }),
});

router.get(
  '/customers',
  validate(listCustomersQuery),
  asyncHandler(async (req: any, res) => {
    const { search, page, limit } = req.validated.query;

    const where: any = { role: 'USER' };
    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
        { phone: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        select: {
          id: true, name: true, email: true, phone: true,
          emailVerified: true, phoneVerified: true, createdAt: true,
          _count: { select: { orders: true } },
        },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.user.count({ where }),
    ]);

    // Total spend per customer (paid orders only)
    const userIds = users.map((u) => u.id);
    const spendAgg = await prisma.order.groupBy({
      by: ['userId'],
      where: {
        userId: { in: userIds },
        status: { in: ['PAID', 'PROCESSING', 'SHIPPED', 'DELIVERED'] },
      },
      _sum: { total: true },
    });
    const spendMap = new Map(spendAgg.map((s) => [s.userId, Number(s._sum.total ?? 0)]));

    res.json({
      status: 'success',
      data: {
        customers: users.map((u) => ({
          ...u,
          orderCount: u._count.orders,
          totalSpent: spendMap.get(u.id) ?? 0,
        })),
        total,
        page,
        totalPages: Math.ceil(total / limit),
      },
    });
  })
);

// ─── Customers: full profile ─────────────────────────────────────────────────────
// Powers the customer detail page: contact info, every saved address, and
// COMPLETE order history with line items, payment status/provider/reference,
// and the shipping address used on each individual order. This is the
// "billing information and order history" view that was previously missing
// entirely — the customers list only ever showed aggregate totals.

router.get(
  '/customers/:id',
  asyncHandler(async (req, res) => {
    const customer = await prisma.user.findUnique({
      where: { id: req.params.id },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        role: true,
        emailVerified: true,
        phoneVerified: true,
        createdAt: true,
        addresses: {
          orderBy: { isDefault: 'desc' },
        },
      },
    });

    if (!customer) throw new ApiError(404, 'Customer not found');

    const orders = await prisma.order.findMany({
      where: { userId: req.params.id },
      orderBy: { createdAt: 'desc' },
      include: {
        items: true,
        payment: true,
        shippingAddress: true,
      },
    });

    const paidOrders = orders.filter((o) =>
      ['PAID', 'PROCESSING', 'SHIPPED', 'DELIVERED'].includes(o.status)
    );
    const totalSpent = paidOrders.reduce((sum, o) => sum + Number(o.total), 0);

    res.json({
      status: 'success',
      data: {
        customer: {
          ...customer,
          // Hide the synthetic placeholder email used for phone-only signups
          email: customer.email.endsWith('@phone.classic-closet.local')
            ? null
            : customer.email,
        },
        orders,
        summary: {
          totalOrders: orders.length,
          paidOrders: paidOrders.length,
          totalSpent,
        },
      },
    });
  })
);

export default router;
