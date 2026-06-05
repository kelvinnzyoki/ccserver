import { Router } from 'express';
import crypto from 'crypto';
import { prisma } from '../config/prisma.js';
import { requireAuth } from '../middleware/auth.js';
import { paymentLimiter } from '../middleware/security.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/apiError.js';
import { paystack } from '../services/paystack.service.js';
import { mpesa } from '../services/mpesa.service.js';
import { env } from '../config/env.js';
const router=Router();
async function markPaid(orderId:string, ref:string){
  const order=await prisma.order.findUnique({where:{id:orderId},include:{items:true}}); if(!order) throw new ApiError(404,'Order not found');
  await prisma.$transaction(async(tx)=>{ await tx.payment.update({where:{orderId},data:{status:'COMPLETED',transactionRef:ref,paidAt:new Date()}}); await tx.order.update({where:{id:orderId},data:{status:'PAID'}}); for(const item of order.items){ await tx.product.update({where:{id:item.productId},data:{stock:{decrement:item.quantity}}}); } });
}
router.post('/paystack/initialize/:orderId', requireAuth, paymentLimiter, asyncHandler(async(req,res)=>{
  const order=await prisma.order.findFirst({where:{id:req.params.orderId,userId:req.user!.id},include:{payment:true}}); if(!order) throw new ApiError(404,'Order not found');
  const data=await paystack.initialize(order.id, order.email, Number(order.total));
  await prisma.payment.update({where:{orderId:order.id},data:{providerRef:data.reference,checkoutUrl:data.authorization_url}});
  res.json({status:'success',data:{authorizationUrl:data.authorization_url,reference:data.reference}});
}));
router.get('/paystack/verify/:reference', requireAuth, asyncHandler(async(req,res)=>{
  const data=await paystack.verify(req.params.reference); if(data.status !== 'success') throw new ApiError(400,'Payment not completed');
  const payment=await prisma.payment.findFirst({where:{providerRef:req.params.reference}}); if(!payment) throw new ApiError(404,'Payment not found');
  await markPaid(payment.orderId, data.reference); res.json({status:'success'});
}));
router.post('/paystack/webhook', asyncHandler(async(req,res)=>{
  const secret=env.PAYSTACK_SECRET_KEY || ''; const hash=crypto.createHmac('sha512',secret).update(JSON.stringify(req.body)).digest('hex');
  if(hash !== req.headers['x-paystack-signature']) throw new ApiError(401,'Invalid signature');
  if(req.body.event==='charge.success'){ const payment=await prisma.payment.findFirst({where:{providerRef:req.body.data.reference}}); if(payment) await markPaid(payment.orderId, req.body.data.reference); }
  res.sendStatus(200);
}));
router.post('/mpesa/stk/:orderId', requireAuth, paymentLimiter, asyncHandler(async(req,res)=>{
  const order=await prisma.order.findFirst({where:{id:req.params.orderId,userId:req.user!.id},include:{payment:true}}); if(!order) throw new ApiError(404,'Order not found');
  const data=await mpesa.stkPush(order.id, req.body.phoneNumber, Number(order.total));
  await prisma.payment.update({where:{orderId:order.id},data:{providerRef:data.CheckoutRequestID,phoneNumber:req.body.phoneNumber}});
  res.json({status:'success',data});
}));
router.post('/mpesa/callback', asyncHandler(async(req,res)=>{
  const cb=req.body?.Body?.stkCallback; if(!cb) return res.sendStatus(200);
  const payment=await prisma.payment.findFirst({where:{providerRef:cb.CheckoutRequestID}}); if(!payment) return res.sendStatus(200);
  if(cb.ResultCode===0){ const receipt=cb.CallbackMetadata?.Item?.find((x:any)=>x.Name==='MpesaReceiptNumber')?.Value || cb.CheckoutRequestID; await markPaid(payment.orderId, receipt); }
  else await prisma.payment.update({where:{id:payment.id},data:{status:'FAILED',failureReason:cb.ResultDesc}});
  res.sendStatus(200);
}));
export default router;
