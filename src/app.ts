import express from 'express';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import morgan from 'morgan';
import { securityMiddleware } from './middleware/security.js';
import { errorHandler, notFound } from './middleware/error.js';
import authRoutes from './routes/auth.routes.js';
import productRoutes from './routes/product.routes.js';
import cartRoutes from './routes/cart.routes.js';
import checkoutRoutes from './routes/checkout.routes.js';
import paymentRoutes from './routes/payment.routes.js';
import orderRoutes from './routes/order.routes.js';
import adminRoutes from './routes/admin.routes.js';
import newsletterRoutes from './routes/newsletter.routes.js';
export const app = express();
app.set('trust proxy', 1);
app.use(...securityMiddleware);
app.use('/api/payments/paystack/webhook', express.json({ verify:(req:any,_res,buf)=>{ req.rawBody=buf; } }));
app.use(express.json({limit:'1mb'})); app.use(express.urlencoded({extended:true})); app.use(cookieParser()); app.use(compression());
if(process.env.NODE_ENV==='development') app.use(morgan('dev'));
app.get('/', (_req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Classic Closet API is running',
  });
});
app.get('/health', (_req,res)=>res.json({status:'success', service:'classic-closet-api'}));
app.use('/api/auth', authRoutes); app.use('/api/products', productRoutes); app.use('/api/cart', cartRoutes); app.use('/api/checkout', checkoutRoutes); app.use('/api/payments', paymentRoutes); app.use('/api/orders', orderRoutes); app.use('/api/admin', adminRoutes); app.use('/api/newsletter', newsletterRoutes);
app.use(notFound); app.use(errorHandler);
