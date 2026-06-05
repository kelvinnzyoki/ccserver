import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
const router=Router();
async function getCart(userId:string){ return prisma.cart.upsert({ where:{ userId: userId as any }, create:{ userId }, update:{}, include:{items:{include:{product:true}}} }); }
router.get('/', requireAuth, asyncHandler(async(req,res)=> res.json({status:'success',data:{cart: await getCart(req.user!.id)}})));
router.post('/items', requireAuth, validate(z.object({body:z.object({productId:z.string().uuid(),quantity:z.number().int().min(1).max(20).default(1)})})), asyncHandler(async(req,res)=>{
  const cart=await getCart(req.user!.id); const product=await prisma.product.findUnique({where:{id:req.body.productId}});
  if(!product || !product.isActive) throw new ApiError(404,'Product unavailable');
  if(product.stock < req.body.quantity) throw new ApiError(400,'Insufficient stock');
  await prisma.cartItem.upsert({where:{cartId_productId:{cartId:cart.id, productId:product.id}}, create:{cartId:cart.id, productId:product.id, quantity:req.body.quantity, price:product.price}, update:{quantity:{increment:req.body.quantity}}});
  res.status(201).json({status:'success',data:{cart: await getCart(req.user!.id)}});
}));
router.patch('/items/:id', requireAuth, asyncHandler(async(req,res)=>{ const qty=Number(req.body.quantity); if(qty<1||qty>20) throw new ApiError(400,'Invalid quantity'); await prisma.cartItem.update({where:{id:req.params.id},data:{quantity:qty}}); res.json({status:'success',data:{cart:await getCart(req.user!.id)}}); }));
router.delete('/items/:id', requireAuth, asyncHandler(async(req,res)=>{ await prisma.cartItem.delete({where:{id:req.params.id}}); res.json({status:'success',data:{cart:await getCart(req.user!.id)}}); }));
export default router;
