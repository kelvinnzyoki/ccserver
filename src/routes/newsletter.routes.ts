import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../config/prisma.js';
import { validate } from '../middleware/validate.js';
import { asyncHandler } from '../utils/asyncHandler.js';
const router=Router();
router.post('/subscribe', validate(z.object({body:z.object({email:z.string().email()})})), asyncHandler(async(req,res)=>{ await prisma.newsletterSubscriber.upsert({where:{email:req.body.email.toLowerCase()},create:{email:req.body.email.toLowerCase()},update:{}}); res.status(201).json({status:'success'}); }));
export default router;
