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

/**
 * Stores refresh token hash when the DB column exists.
 * This is intentionally non-fatal so login/register do not crash if Neon has not
 * been migrated with refreshTokenHash yet. Access-token auth still works because
 * the frontend stores the access token and sends it as Authorization: Bearer.
 */
export async function persistRefresh(userId: string, refresh: string) {
  try {
    await prisma.user.update({
      where: { id: userId },
      data: { refreshTokenHash: await bcrypt.hash(refresh, 10) },
    });
  } catch (error) {
    console.error('Non-fatal: failed to persist refresh token hash.', error);
  }
}
