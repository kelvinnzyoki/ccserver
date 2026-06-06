import type { Prisma } from '@prisma/client';
import { prisma } from '../config/prisma.js';

const cartInclude = {
  items: {
    include: {
      product: true,
    },
  },
} satisfies Prisma.CartInclude;

export function normalizeCartSession(value: unknown) {
  const sessionId = Array.isArray(value) ? value[0] : value;
  return typeof sessionId === 'string' && sessionId.trim().length >= 10
    ? sessionId.trim()
    : undefined;
}

export async function getOrCreateCart(userId?: string, sessionId?: string) {
  if (userId) {
    return prisma.cart.upsert({
      where: { userId },
      create: { userId },
      update: {},
      include: cartInclude,
    });
  }

  if (!sessionId) {
    return null;
  }

  return prisma.cart.upsert({
    where: { sessionId },
    create: { sessionId },
    update: {},
    include: cartInclude,
  });
}

export async function mergeGuestCartIntoUser(sessionId: string | undefined, userId: string) {
  if (!sessionId) return;

  const guestCart = await prisma.cart.findUnique({
    where: { sessionId },
    include: { items: true },
  });

  if (!guestCart || guestCart.items.length === 0) return;

  const userCart = await prisma.cart.upsert({
    where: { userId },
    create: { userId },
    update: {},
  });

  await prisma.$transaction(async (tx) => {
    for (const item of guestCart.items) {
      await tx.cartItem.upsert({
        where: {
          cartId_productId: {
            cartId: userCart.id,
            productId: item.productId,
          },
        },
        create: {
          cartId: userCart.id,
          productId: item.productId,
          quantity: item.quantity,
          price: item.price,
        },
        update: {
          quantity: {
            increment: item.quantity,
          },
        },
      });
    }

    await tx.cart.delete({
      where: { id: guestCart.id },
    });
  });
}

export async function getHydratedUserCart(userId: string) {
  return prisma.cart.upsert({
    where: { userId },
    create: { userId },
    update: {},
    include: cartInclude,
  });
}
