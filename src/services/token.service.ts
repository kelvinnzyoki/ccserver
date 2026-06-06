import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { env, isProd } from '../config/env.js';
import { prisma } from '../config/prisma.js';

export const signAccess = (id: string) =>
  jwt.sign({ id }, env.JWT_ACCESS_SECRET, { expiresIn: '15m' });

export const signRefresh = (id: string) =>
  jwt.sign({ id }, env.JWT_REFRESH_SECRET, { expiresIn: '30d' });

export const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? ('none' as const) : ('lax' as const),
  path: '/',
  ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
};

export async function persistRefresh(userId: string, refresh: string) {
  await prisma.user.update({
    where: { id: userId },
    data: { refreshTokenHash: await bcrypt.hash(refresh, 10) },
  });
}
