import { Router } from 'express';
import { prisma } from '../config/prisma.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../utils/asyncHandler.js';
const router=Router();
router.get('/mine', requireAuth, asyncHandler(async(req,res)=>{ const orders=await prisma.order.findMany({where:{userId:req.user!.id},include:{items:true,payment:true},orderBy:{createdAt:'desc'}}); res.json({status:'success',data:{orders}}); }));
export default router;
