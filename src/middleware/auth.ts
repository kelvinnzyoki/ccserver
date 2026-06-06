import jwt from 'jsonwebtoken';
import { prisma } from '../config/prisma.js';
import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

function getBearerToken(req: any) {
  const header = req.headers.authorization;
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice(7);
  }
  return undefined;
}

async function getUserFromRequest(req: any) {
  const token = getBearerToken(req) || req.cookies?.access_token;
  if (!token) return null;

  try {
    const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as { id: string };
    return await prisma.user.findUnique({
      where: { id: payload.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        phone: true,
      },
    });
  } catch {
    return null;
  }
}

export const optionalAuth = asyncHandler(async (req, _res, next) => {
  const user = await getUserFromRequest(req);
  if (user) req.user = user;
  next();
});

export const requireAuth = asyncHandler(async (req, _res, next) => {
  const user = await getUserFromRequest(req);
  if (!user) throw new ApiError(401, 'Authentication required');
  req.user = user;
  next();
});

export const requireAdmin = (req: any, _res: any, next: any) => {
  if (!['ADMIN', 'SUPER_ADMIN'].includes(req.user?.role)) {
    throw new ApiError(403, 'Admin access required');
  }
  next();
};
