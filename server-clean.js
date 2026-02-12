/* ==========================================
   PREMIUM CLOSET - COMPLETE BACKEND
   Production-Ready E-Commerce API
   ========================================== */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import { Resend } from 'resend';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import winston from 'winston';
import { z } from 'zod';

dotenv.config();

// ==========================================
// CONFIGURATION
// ==========================================

const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Prisma
const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['error', 'warn'] : ['error'],
});

// Initialize Redis (optional - falls back gracefully)
let redisClient = null;
try {
  if (process.env.REDIS_URL) {
    redisClient = new Redis(process.env.REDIS_URL, {
      retryStrategy: (times) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
    });
    redisClient.on('error', (err) => console.log('Redis error:', err));
  }
} catch (error) {
  console.log('Redis not available, using memory cache');
}

// Initialize Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [new winston.transports.Console()],
});

// Initialize Email (optional)
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// ==========================================
// MIDDLEWARE
// ==========================================

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(compression());

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Rate Limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
});

app.use('/api/', globalLimiter);

// ==========================================
// UTILITIES
// ==========================================

class ApiError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET || 'fallback-secret', {
    expiresIn: '7d',
  });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET || 'fallback-refresh', {
    expiresIn: '30d',
  });
};

const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user.id);
  const refreshToken = generateRefreshToken(user.id);

  const cookieOptions = {
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  };

  res
    .status(statusCode)
    .cookie('token', token, cookieOptions)
    .json({
      status: 'success',
      data: {
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
        token,
        refreshToken,
      },
    });
};

// Redis helpers
const cacheSet = async (key, value, expiry = 3600) => {
  if (redisClient) {
    try {
      await redisClient.setex(key, expiry, JSON.stringify(value));
    } catch (err) {
      logger.error('Cache set error:', err);
    }
  }
};

const cacheGet = async (key) => {
  if (redisClient) {
    try {
      const data = await redisClient.get(key);
      return data ? JSON.parse(data) : null;
    } catch (err) {
      return null;
    }
  }
  return null;
};

const cacheDel = async (pattern) => {
  if (redisClient) {
    try {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) await redisClient.del(...keys);
    } catch (err) {
      logger.error('Cache delete error:', err);
    }
  }
};

// Email helper
const sendEmail = async (to, subject, html) => {
  if (resend) {
    try {
      await resend.emails.send({
        from: process.env.FROM_EMAIL || 'noreply@premiumcloset.com',
        to,
        subject,
        html,
      });
    } catch (error) {
      logger.error('Email error:', error);
    }
  }
};

// ==========================================
// M-PESA SERVICE
// ==========================================

const MPESA_BASE_URL = process.env.MPESA_ENVIRONMENT === 'production'
  ? 'https://api.safaricom.co.ke'
  : 'https://sandbox.safaricom.co.ke';

class MpesaService {
  async getAccessToken() {
    const auth = Buffer.from(
      `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
    ).toString('base64');
    
    const response = await axios.get(
      `${MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
      { headers: { Authorization: `Basic ${auth}` } }
    );
    return response.data.access_token;
  }

  generatePassword() {
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
    const password = Buffer.from(
      `${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`
    ).toString('base64');
    return { password, timestamp };
  }

  async initiateSTKPush(orderId, phoneNumber, amount) {
    const accessToken = await this.getAccessToken();
    const { password, timestamp } = this.generatePassword();

    let formattedPhone = phoneNumber.replace(/^0/, '254').replace(/^\+/, '');
    if (!formattedPhone.startsWith('254')) formattedPhone = '254' + formattedPhone;

    const payload = {
      BusinessShortCode: process.env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.round(amount),
      PartyA: formattedPhone,
      PartyB: process.env.MPESA_SHORTCODE,
      PhoneNumber: formattedPhone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: orderId,
      TransactionDesc: `Order ${orderId}`,
    };

    const response = await axios.post(
      `${MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
      payload,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    await prisma.payment.update({
      where: { orderId },
      data: { providerRef: response.data.CheckoutRequestID },
    });

    return {
      success: true,
      checkoutRequestId: response.data.CheckoutRequestID,
    };
  }

  async handleCallback(callbackData) {
    const { Body } = callbackData;
    const resultCode = Body.stkCallback.ResultCode;
    const checkoutRequestID = Body.stkCallback.CheckoutRequestID;

    const payment = await prisma.payment.findFirst({
      where: { providerRef: checkoutRequestID },
      include: { order: true },
    });

    if (!payment) return { success: false };

    if (resultCode === 0) {
      const mpesaReceiptNumber = Body.stkCallback.CallbackMetadata.Item.find(
        item => item.Name === 'MpesaReceiptNumber'
      )?.Value;

      await prisma.payment.update({
        where: { id: payment.id },
        data: { status: 'COMPLETED', transactionRef: mpesaReceiptNumber, paidAt: new Date() },
      });

      await prisma.order.update({
        where: { id: payment.orderId },
        data: { status: 'PAID' },
      });

      const orderItems = await prisma.orderItem.findMany({
        where: { orderId: payment.orderId },
      });

      for (const item of orderItems) {
        await prisma.product.update({
          where: { id: item.productId },
          data: { stock: { decrement: item.quantity }, totalSales: { increment: item.quantity } },
        });
      }

      return { success: true };
    }

    await prisma.payment.update({
      where: { id: payment.id },
      data: { status: 'FAILED' },
    });

    return { success: false };
  }
}

const mpesaService = new MpesaService();

// ==========================================
// AUTH MIDDLEWARE
// ==========================================

const protect = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization?.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) throw new ApiError(401, 'Not authorized');

  const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
  const user = await prisma.user.findUnique({
    where: { id: decoded.id },
    select: { id: true, email: true, name: true, role: true },
  });

  if (!user) throw new ApiError(401, 'User not found');

  req.user = user;
  next();
});

const optionalAuth = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization?.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.token) {
    token = req.cookies.token;
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
      const user = await prisma.user.findUnique({
        where: { id: decoded.id },
        select: { id: true, email: true, name: true, role: true },
      });
      if (user) req.user = user;
    } catch (err) {
      // Continue without auth
    }
  }
  next();
});

const adminOnly = (req, res, next) => {
  if (!req.user || !['ADMIN', 'SUPER_ADMIN'].includes(req.user.role)) {
    throw new ApiError(403, 'Admin access required');
  }
  next();
};

// ==========================================
// VALIDATION
// ==========================================

const schemas = {
  register: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(8),
    phone: z.string().optional(),
  }),
  login: z.object({
    email: z.string().email(),
    password: z.string(),
  }),
  addToCart: z.object({
    productId: z.string().uuid(),
    quantity: z.number().int().positive().default(1),
  }),
};

const validate = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (error) {
    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors: error.errors,
    });
  }
};

// ==========================================
// CART HELPERS
// ==========================================

const getCartIdentifier = (req) => {
  return req.user ? `user:${req.user.id}` : `session:${req.cookies.sessionId || crypto.randomUUID()}`;
};

// ==========================================
// ROUTES
// ==========================================

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'success',
    message: 'Premium Closet API is running',
    timestamp: new Date().toISOString(),
  });
});

// Auth Routes
app.post('/api/auth/register', authLimiter, validate(schemas.register), asyncHandler(async (req, res) => {
  const { name, email, password, phone } = req.body;

  const existing = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  if (existing) throw new ApiError(400, 'Email already registered');

  const hashedPassword = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: { name, email: email.toLowerCase(), passwordHash: hashedPassword, phone },
    select: { id: true, name: true, email: true, role: true },
  });

  sendTokenResponse(user, 201, res);
}));

app.post('/api/auth/login', authLimiter, validate(schemas.login), asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  if (!user) throw new ApiError(401, 'Invalid credentials');

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) throw new ApiError(401, 'Invalid credentials');

  sendTokenResponse(user, 200, res);
}));

app.get('/api/auth/me', protect, asyncHandler(async (req, res) => {
  res.json({ status: 'success', data: { user: req.user } });
}));

app.post('/api/auth/logout', (req, res) => {
  res.cookie('token', 'none', { expires: new Date(Date.now() + 10000), httpOnly: true });
  res.json({ status: 'success', message: 'Logged out' });
});

// Product Routes
app.get('/api/products', asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, category, search } = req.query;
  const skip = (parseInt(page) - 1) * parseInt(limit);

  const where = {
    isActive: true,
    ...(category && { category }),
    ...(search && {
      OR: [
        { name: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
      ],
    }),
  };

  const [products, total] = await Promise.all([
    prisma.product.findMany({ where, skip, take: parseInt(limit) }),
    prisma.product.count({ where }),
  ]);

  res.json({
    status: 'success',
    data: { products },
    pagination: { page: parseInt(page), limit: parseInt(limit), total },
  });
}));

app.get('/api/products/:id', asyncHandler(async (req, res) => {
  const product = await prisma.product.findUnique({ where: { id: req.params.id } });
  if (!product) throw new ApiError(404, 'Product not found');
  res.json({ status: 'success', data: { product } });
}));

// Cart Routes
app.get('/api/cart', optionalAuth, asyncHandler(async (req, res) => {
  const identifier = getCartIdentifier(req);
  const [userId, sessionId] = identifier.startsWith('user:')
    ? [identifier.split(':')[1], null]
    : [null, identifier.split(':')[1]];

  const cart = await prisma.cart.findFirst({
    where: userId ? { userId } : { sessionId },
    include: { items: { include: { product: true } } },
  });

  const items = cart?.items || [];
  const subtotal = items.reduce((sum, item) => sum + parseFloat(item.price) * item.quantity, 0);

  res.json({ status: 'success', data: { cart: { items, subtotal, total: subtotal } } });
}));

app.post('/api/cart/add', optionalAuth, validate(schemas.addToCart), asyncHandler(async (req, res) => {
  const { productId, quantity } = req.body;
  const identifier = getCartIdentifier(req);

  const product = await prisma.product.findUnique({ where: { id: productId } });
  if (!product) throw new ApiError(404, 'Product not found');
  if (product.stock < quantity) throw new ApiError(400, 'Insufficient stock');

  const [userId, sessionId] = identifier.startsWith('user:')
    ? [identifier.split(':')[1], null]
    : [null, identifier.split(':')[1]];

  let cart = await prisma.cart.findFirst({ where: userId ? { userId } : { sessionId } });

  if (!cart) {
    cart = await prisma.cart.create({
      data: { userId, sessionId, expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) },
    });
  }

  const existing = await prisma.cartItem.findFirst({ where: { cartId: cart.id, productId } });

  if (existing) {
    await prisma.cartItem.update({
      where: { id: existing.id },
      data: { quantity: existing.quantity + quantity },
    });
  } else {
    await prisma.cartItem.create({
      data: { cartId: cart.id, productId, quantity, price: product.price },
    });
  }

  await cacheDel(`cart:${identifier}`);
  res.json({ status: 'success', message: 'Item added to cart' });
}));

// Order Routes
app.post('/api/checkout/confirm', protect, asyncHandler(async (req, res) => {
  const { shippingAddress, paymentMethod, couponCode } = req.body;

  const cart = await prisma.cart.findFirst({
    where: { userId: req.user.id },
    include: { items: { include: { product: true } } },
  });

  if (!cart || cart.items.length === 0) throw new ApiError(400, 'Cart is empty');

  const subtotal = cart.items.reduce((sum, item) => sum + parseFloat(item.price) * item.quantity, 0);
  const shippingCost = subtotal >= 5000 ? 0 : 500;
  const tax = subtotal * 0.16;
  const total = subtotal + shippingCost + tax;

  const address = await prisma.address.create({
    data: { userId: req.user.id, ...shippingAddress },
  });

  const orderNumber = `ORD-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

  const order = await prisma.order.create({
    data: {
      orderNumber,
      userId: req.user.id,
      email: req.user.email,
      subtotal,
      shippingCost,
      tax,
      total,
      paymentMethod,
      shippingAddressId: address.id,
      couponCode,
      items: {
        create: cart.items.map(item => ({
          productId: item.productId,
          productName: item.product.name,
          productImage: item.product.image,
          price: item.price,
          quantity: item.quantity,
          total: parseFloat(item.price) * item.quantity,
        })),
      },
    },
    include: { items: true },
  });

  await prisma.payment.create({
    data: { orderId: order.id, provider: paymentMethod, amount: total, currency: 'KES' },
  });

  await prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
  await cacheDel(`cart:user:${req.user.id}`);

  res.status(201).json({ status: 'success', data: { order } });
}));

app.get('/api/orders/user', protect, asyncHandler(async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { userId: req.user.id },
    include: { items: true, payment: true },
    orderBy: { createdAt: 'desc' },
  });
  res.json({ status: 'success', data: { orders } });
}));

// Payment Routes
app.post('/api/payments/mpesa/stk-push', protect, paymentLimiter, asyncHandler(async (req, res) => {
  const { orderId, phoneNumber } = req.body;

  const order = await prisma.order.findFirst({
    where: { id: orderId, userId: req.user.id },
    include: { payment: true },
  });

  if (!order) throw new ApiError(404, 'Order not found');
  if (order.payment.status === 'COMPLETED') throw new ApiError(400, 'Already paid');

  const result = await mpesaService.initiateSTKPush(orderId, phoneNumber, order.total);

  res.json({ status: 'success', message: 'STK push sent', data: result });
}));

app.post('/api/payments/mpesa/callback', express.raw({ type: 'application/json' }), asyncHandler(async (req, res) => {
  const callbackData = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  await mpesaService.handleCallback(callbackData);
  res.json({ ResultCode: 0, ResultDesc: 'Success' });
}));

// Admin Routes
app.get('/api/admin/orders', protect, adminOnly, asyncHandler(async (req, res) => {
  const orders = await prisma.order.findMany({
    include: { user: { select: { name: true, email: true } }, items: true },
    orderBy: { createdAt: 'desc' },
  });
  res.json({ status: 'success', data: { orders } });
}));

app.get('/api/admin/analytics', protect, adminOnly, asyncHandler(async (req, res) => {
  const [totalOrders, totalRevenue, totalCustomers] = await Promise.all([
    prisma.order.count(),
    prisma.order.aggregate({ _sum: { total: true } }),
    prisma.user.count({ where: { role: 'USER' } }),
  ]);

  res.json({
    status: 'success',
    data: { totalOrders, totalRevenue: totalRevenue._sum.total || 0, totalCustomers },
  });
}));

// Newsletter
app.post('/api/newsletter/subscribe', asyncHandler(async (req, res) => {
  const { email } = req.body;
  await prisma.newsletter.upsert({
    where: { email },
    create: { email },
    update: { isSubscribed: true },
  });
  res.json({ status: 'success', message: 'Subscribed' });
}));

// ==========================================
// ERROR HANDLING
// ==========================================

app.use('*', (req, res) => {
  res.status(404).json({ status: 'error', message: 'Route not found' });
});

app.use((err, req, res, next) => {
  logger.error(err);
  res.status(err.statusCode || 500).json({
    status: 'error',
    message: err.message || 'Internal Server Error',
  });
});

// ==========================================
// START SERVER
// ==========================================

prisma.$connect()
  .then(() => logger.info('✅ Database connected'))
  .catch((err) => {
    logger.error('❌ Database failed:', err);
    process.exit(1);
  });

const server = app.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT}`);
  logger.info(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});

export default app;
