import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { validate } from '../middleware/validate.js';
import { authLimiter } from '../middleware/security.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { signAccess, signRefresh, persistRefresh, cookieOptions } from '../services/token.service.js';
const router = Router();
const registerSchema = z.object({ body:z.object({ name:z.string().min(2), email:z.string().email(), password:z.string().min(8), phone:z.string().optional() }) });
const loginSchema = z.object({ body:z.object({ email:z.string().email(), password:z.string().min(1) }) });
function publicUser(u:any){ return { id:u.id, name:u.name, email:u.email, role:u.role, phone:u.phone }; }
router.post('/register', authLimiter, validate(registerSchema), asyncHandler(async(req,res)=>{
  const { name,email,password,phone } = req.body; const e=email.toLowerCase();
  if(await prisma.user.findUnique({ where:{email:e} })) throw new ApiError(409,'Email already registered');
  const user = await prisma.user.create({ data:{ name, email:e, phone, passwordHash: await bcrypt.hash(password,12) }});
  const access=signAccess(user.id), refresh=signRefresh(user.id); await persistRefresh(user.id, refresh);
  res.cookie('access_token',access,{...cookieOptions,maxAge:15*60*1000}).cookie('refresh_token',refresh,{...cookieOptions,maxAge:30*86400*1000}).status(201).json({status:'success',data:{user:publicUser(user),accessToken:access}});
}));
router.post('/login', authLimiter, validate(loginSchema), asyncHandler(async(req,res)=>{
  const user=await prisma.user.findUnique({where:{email:req.body.email.toLowerCase()}});
  if(!user || !(await bcrypt.compare(req.body.password,user.passwordHash))) throw new ApiError(401,'Invalid email or password');
  const access=signAccess(user.id), refresh=signRefresh(user.id); await persistRefresh(user.id, refresh);
  res.cookie('access_token',access,{...cookieOptions,maxAge:15*60*1000}).cookie('refresh_token',refresh,{...cookieOptions,maxAge:30*86400*1000}).json({status:'success',data:{user:publicUser(user),accessToken:access}});
}));
router.get('/me', requireAuth, asyncHandler(async(req,res)=> res.json({status:'success',data:{user:req.user}})));
router.post('/logout', requireAuth, asyncHandler(async(req,res)=>{ await prisma.user.update({where:{id:req.user!.id},data:{refreshTokenHash:null}}); res.clearCookie('access_token').clearCookie('refresh_token').json({status:'success'}); }));
export default router;
