import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { makeOrderNumber } from '../utils/orderNumber.js';
const router=Router();
const schema=z.object({body:z.object({paymentMethod:z.enum(['MPESA','PAYSTACK']),shippingAddress:z.object({firstName:z.string().min(2),lastName:z.string().min(2),phone:z.string().min(9),email:z.string().email().optional(),address1:z.string().min(3),address2:z.string().optional(),city:z.string().min(2),county:z.string().optional(),postalCode:z.string().optional(),country:z.string().default('Kenya')})})});
router.post('/', requireAuth, validate(schema), asyncHandler(async(req,res)=>{
  const cart=await prisma.cart.findFirst({where:{userId:req.user!.id},include:{items:{include:{product:true}}}});
  if(!cart?.items.length) throw new ApiError(400,'Cart is empty');
  for(const item of cart.items){ if(!item.product.isActive || item.product.stock < item.quantity) throw new ApiError(400,`${item.product.name} is out of stock`); }
  const subtotal=cart.items.reduce((s,i)=>s+Number(i.price)*i.quantity,0); const shippingCost=subtotal>=5000?0:300; const total=subtotal+shippingCost;
  const order=await prisma.$transaction(async(tx)=>{
    const address=await tx.address.create({data:{...req.body.shippingAddress,userId:req.user!.id,email:req.body.shippingAddress.email || req.user!.email}});
    const order=await tx.order.create({data:{orderNumber:makeOrderNumber(),userId:req.user!.id,email:req.user!.email,subtotal,shippingCost,total,paymentMethod:req.body.paymentMethod,shippingAddressId:address.id,items:{create:cart.items.map(i=>({productId:i.productId,productName:i.product.name,productImage:i.product.image,price:i.price,quantity:i.quantity,total:Number(i.price)*i.quantity}))},payment:{create:{provider:req.body.paymentMethod,amount:total,currency:'KES'}}},include:{items:true,payment:true,shippingAddress:true}});
    await tx.cartItem.deleteMany({where:{cartId:cart.id}});
    return order;
  });
  res.status(201).json({status:'success',data:{order}});
}));
export default router;
