import jwt from 'jsonwebtoken';
import { prisma } from '../config/prisma.js';
import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
export const requireAuth = asyncHandler(async (req, _res, next) => {
  const bearer = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : undefined;
  const token = bearer || req.cookies?.access_token;
  if (!token) throw new ApiError(401, 'Authentication required');
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as { id:string };
  const user = await prisma.user.findUnique({ where:{ id: payload.id }, select:{ id:true,email:true,name:true,role:true }});
  if (!user) throw new ApiError(401, 'Invalid session');
  req.user = user; next();
});
export const requireAdmin = (req:any, _res:any, next:any) => {
  if (!['ADMIN','SUPER_ADMIN'].includes(req.user?.role)) throw new ApiError(403, 'Admin access required');
  next();
};
