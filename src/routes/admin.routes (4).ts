import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const router = Router();
router.use(requireAuth, requireAdmin);

// ─── Orders ───────────────────────────────────────────────────────────────────

router.get(
  '/orders',
  asyncHandler(async (_req, res) =>
    res.json({
      status: 'success',
      data: {
        orders: await prisma.order.findMany({
          include: { items: true, payment: true, user: true },
          orderBy: { createdAt: 'desc' },
        }),
      },
    })
  )
);

// ─── Products: create ─────────────────────────────────────────────────────────
// FIX: schema now matches actual Prisma Product fields.
// Removed non-existent fields: isFeatured (renamed to featured), tags, sku, compareAtPrice, images, badge.

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
// FIX: added Zod validation — previously accepted raw req.body with no schema,
// allowing arbitrary fields (including id/slug) to be overwritten.

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

export default router;
