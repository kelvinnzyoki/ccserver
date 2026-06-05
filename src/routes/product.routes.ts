import { Router } from 'express';
import { prisma } from '../config/prisma.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
const router = Router();
router.get('/', asyncHandler(async(req,res)=>{
  const { q, category, featured, page='1', limit='24' } = req.query as Record<string,string>;
  const take=Math.min(Number(limit)||24,60), skip=(Math.max(Number(page)||1,1)-1)*take;
  const where:any={ isActive:true };
  if(category) where.category=category;
  if(featured==='true') where.isFeatured=true;
  if(q) where.OR=[{name:{contains:q,mode:'insensitive'}},{description:{contains:q,mode:'insensitive'}},{tags:{has:q}}];
  const [products,total]=await Promise.all([prisma.product.findMany({where,skip,take,orderBy:{createdAt:'desc'}}),prisma.product.count({where})]);
  res.json({status:'success',data:{products,total,page:Number(page),limit:take}});
}));
router.get('/:slug', asyncHandler(async(req,res)=>{
  const product=await prisma.product.findUnique({where:{slug:req.params.slug}});
  if(!product || !product.isActive) throw new ApiError(404,'Product not found');
  res.json({status:'success',data:{product}});
}));
export default router;
