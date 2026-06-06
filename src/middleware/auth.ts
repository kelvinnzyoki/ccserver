import jwt from 'jsonwebtoken';
import { prisma } from '../config/prisma.js';
import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const userSelect = {
  id: true,
  email: true,
  name: true,
  role: true,
  phone: true,
  emailVerified: true,
  phoneVerified: true,
};

function getToken(req: any) {
  const bearer = req.headers.authorization?.startsWith('Bearer ')
    ? req.headers.authorization.slice(7)
    : undefined;

  return bearer || req.cookies?.access_token;
}

export const optionalAuth = asyncHandler(async (req, _res, next) => {
  const token = getToken(req);

  if (!token) {
    next();
    return;
  }

  try {
    const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as { id: string };
    const user = await prisma.user.findUnique({
      where: { id: payload.id },
      select: userSelect,
    });

    if (user) req.user = user;
  } catch {
    // Guests should still browse and manage guest cart when token is missing/expired.
  }

  next();
});

export const requireAuth = asyncHandler(async (req, _res, next) => {
  const token = getToken(req);

  if (!token) throw new ApiError(401, 'Authentication required');

  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as { id: string };
  const user = await prisma.user.findUnique({
    where: { id: payload.id },
    select: userSelect,
  });

  if (!user) throw new ApiError(401, 'Invalid session');

  req.user = user;
  next();
});

export const requireAdmin = (req: any, _res: any, next: any) => {
  if (!['ADMIN', 'SUPER_ADMIN'].includes(req.user?.role)) {
    throw new ApiError(403, 'Admin access required');
  }

  next();
};
