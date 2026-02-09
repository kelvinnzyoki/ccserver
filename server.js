/* ==========================================
   PREMIUM CLOSET - COMPLETE BACKEND
   All-in-One Server for E-Commerce Platform
   ==========================================
   
   Features:
   - Authentication (JWT with refresh tokens)
   - Product Management
   - Shopping Cart (Guest & User)
   - Order Management
   - M-Pesa Payment Integration (Kenya)
   - Flutterwave, Paystack, Stripe
   - Email Notifications (Resend)
   - Admin Dashboard APIs
   - Coupon System
   - Newsletter
   - Analytics
   - Reviews
   - Security (Rate Limiting, Validation)
   
   Author: Premium Closet Team
   Version: 1.0.0
   ========================================== */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import mongoSanitize from 'express-mongo-sanitize';
import xss from 'xss-clean';
import hpp from 'hpp';
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
// CONFIGURATION & INITIALIZATION
// ==========================================

const app = express();
const PORT = process.env.PORT;

// Initialize Prisma (Database)
// Optimized for Vercel/Serverless
let prisma;

if (process.env.NODE_ENV === 'production') {
  prisma = new PrismaClient();
} else {
  if (!global.prisma) {
    global.prisma = new PrismaClient();
  }
  prisma = global.prisma;
}

// Initialize Redis (Caching)
let redisClient = null;
try {
  redisClient = new Redis(process.env.REDIS_URL, {
    password: process.env.REDIS_PASSWORD || undefined,
    retryStrategy: (times) => Math.min(times * 50, 2000),
    maxRetriesPerRequest: 3,
  });
  
  redisClient.on('connect', () => console.log('✅ Redis connected'));
  redisClient.on('error', (err) => console.error('❌ Redis error:', err));
} catch (error) {
  console.warn('⚠️  Redis not available, using memory cache');
}

// Initialize Logger
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'development' ? 'debug' : 'warn',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/all.log' }),
  ],
});

// Initialize Email Service
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = process.env.FROM_EMAIL || 'tam&cc@cctamcc.site';

// ==========================================
// MIDDLEWARE SETUP
// ==========================================

app.set('trust proxy', 1);

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Body Parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Compression
app.use(compression());

// Data Sanitization
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// ==========================================
// RATE LIMITERS
// ==========================================

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { status: 'error', message: 'Too many requests' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: { status: 'error', message: 'Too many auth attempts' },
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { status: 'error', message: 'Too many payment attempts' },
});

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

// API Error Class
class ApiError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
  }
}

// Async Handler
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// JWT Token Generation
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
  });
};

// Send Token Response
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
    .cookie('refreshToken', refreshToken, {
      ...cookieOptions,
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    })
    .json({
      status: 'success',
      data: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
        token,
        refreshToken,
      },
    });
};

// Redis Helper Functions
const cacheSet = async (key, value, expiry = 3600) => {
  if (redisClient) {
    try {
      await redisClient.setex(key, expiry, JSON.stringify(value));
    } catch (err) {
      logger.error('Redis set error:', err);
    }
  }
};

const cacheGet = async (key) => {
  if (redisClient) {
    try {
      const data = await redisClient.get(key);
      return data ? JSON.parse(data) : null;
    } catch (err) {
      logger.error('Redis get error:', err);
      return null;
    }
  }
  return null;
};

const cacheDel = async (pattern) => {
  if (redisClient) {
    try {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) {
        await redisClient.del(...keys);
      }
    } catch (err) {
      logger.error('Redis delete error:', err);
    }
  }
};

// ==========================================
// EMAIL TEMPLATES & FUNCTIONS
// ==========================================

const emailTemplates = {
  welcome: (name) => ({
    subject: 'Welcome to Premium Closet',
    html: `
      <!DOCTYPE html>
      <html>
      <head><style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #000; color: #d4af37; padding: 30px; text-align: center; }
        .content { padding: 30px; background: #f9f9f9; }
        .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
      </style></head>
      <body>
        <div class="container">
          <div class="header"><h1>PREMIUM CLOSET</h1></div>
          <div class="content">
            <h2>Welcome, ${name}!</h2>
            <p>Thank you for joining Premium Closet. We're excited to have you!</p>
          </div>
          <div class="footer"><p>Premium Closet | Luxury Fashion</p></div>
        </div>
      </body>
      </html>
    `,
  }),

  orderConfirmation: (order) => ({
    subject: `Order Confirmation - #${order.orderNumber}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head><style>
        body { font-family: Arial, sans-serif; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #000; color: #d4af37; padding: 30px; text-align: center; }
        .content { padding: 30px; background: #f9f9f9; }
        .total { font-size: 18px; font-weight: bold; margin-top: 20px; }
      </style></head>
      <body>
        <div class="container">
          <div class="header"><h1>ORDER CONFIRMED</h1><p>Order #${order.orderNumber}</p></div>
          <div class="content">
            <h2>Thank you for your order!</h2>
            <div class="total">Total: KES ${Number(order.total).toFixed(2)}</div>
          </div>
        </div>
      </body>
      </html>
    `,
  }),
};

const sendEmail = async (to, template, data) => {
  try {
    const emailContent = emailTemplates[template](data);
    await resend.emails.send({
      from: FROM_EMAIL,
      to,
      subject: emailContent.subject,
      html: emailContent.html,
    });
    logger.info(`Email sent to ${to}: ${template}`);
  } catch (error) {
    logger.error(`Email send failed:`, error);
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
    try {
      const auth = Buffer.from(
        `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
      ).toString('base64');
      
      const response = await axios.get(
        `${MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
        { headers: { Authorization: `Basic ${auth}` } }
      );
      return response.data.access_token;
    } catch (error) {
      logger.error('M-Pesa token error:', error.response?.data || error.message);
      throw new Error('Failed to get M-Pesa token');
    }
  }

  generatePassword() {
    const timestamp = new Date()
      .toISOString()
      .replace(/[^0-9]/g, '')
      .slice(0, 14);
    const password = Buffer.from(
      `${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`
    ).toString('base64');
    return { password, timestamp };
  }

  async initiateSTKPush(orderId, phoneNumber, amount) {
    try {
      const accessToken = await this.getAccessToken();
      const { password, timestamp } = this.generatePassword();

      let formattedPhone = phoneNumber.replace(/^0/, '254').replace(/^\+/, '');
      if (!formattedPhone.startsWith('254')) {
        formattedPhone = '254' + formattedPhone;
      }

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
        TransactionDesc: `Payment for Order ${orderId}`,
      };

      const response = await axios.post(
        `${MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
        payload,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      await prisma.payment.update({
        where: { orderId },
        data: {
          providerRef: response.data.CheckoutRequestID,
          metadata: {
            merchantRequestID: response.data.MerchantRequestID,
            checkoutRequestID: response.data.CheckoutRequestID,
          },
        },
      });

      return {
        success: true,
        checkoutRequestId: response.data.CheckoutRequestID,
        merchantRequestId: response.data.MerchantRequestID,
      };
    } catch (error) {
      logger.error('M-Pesa STK Push failed:', error.response?.data || error.message);
      
      await prisma.payment.update({
        where: { orderId },
        data: {
          status: 'FAILED',
          failureReason: error.response?.data?.errorMessage || error.message,
        },
      });

      throw new Error(error.response?.data?.errorMessage || 'M-Pesa payment failed');
    }
  }

  async handleCallback(callbackData) {
    try {
      const { Body } = callbackData;
      const resultCode = Body.stkCallback.ResultCode;
      const checkoutRequestID = Body.stkCallback.CheckoutRequestID;

      const payment = await prisma.payment.findFirst({
        where: { providerRef: checkoutRequestID },
        include: { order: true },
      });

      if (!payment) {
        logger.error(`Payment not found for: ${checkoutRequestID}`);
        return { success: false };
      }

      if (resultCode === 0) {
        const callbackMetadata = Body.stkCallback.CallbackMetadata.Item;
        const mpesaReceiptNumber = callbackMetadata.find(
          item => item.Name === 'MpesaReceiptNumber'
        )?.Value;

        await prisma.payment.update({
          where: { id: payment.id },
          data: {
            status: 'COMPLETED',
            transactionRef: mpesaReceiptNumber,
            paidAt: new Date(),
          },
        });

        await prisma.order.update({
          where: { id: payment.orderId },
          data: { status: 'PAID' },
        });

        // Reduce stock
        const orderItems = await prisma.orderItem.findMany({
          where: { orderId: payment.orderId },
        });

        for (const item of orderItems) {
          await prisma.product.update({
            where: { id: item.productId },
            data: {
              stock: { decrement: item.quantity },
              totalSales: { increment: item.quantity },
            },
          });
        }

        // Send confirmation email
        sendEmail(payment.order.email, 'orderConfirmation', payment.order);

        return { success: true };
      } else {
        await prisma.payment.update({
          where: { id: payment.id },
          data: { status: 'FAILED', failureReason: Body.stkCallback.ResultDesc },
        });

        await prisma.order.update({
          where: { id: payment.orderId },
          data: { status: 'CANCELLED' },
        });

        return { success: false };
      }
    } catch (error) {
      logger.error('M-Pesa callback error:', error);
      throw error;
    }
  }
}

const mpesaService = new MpesaService();

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

const protect = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    throw new ApiError(401, 'Not authorized');
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  const user = await prisma.user.findUnique({
    where: { id: decoded.id },
    select: { id: true, email: true, name: true, role: true, phone: true },
  });

  if (!user) {
    throw new ApiError(401, 'User not found');
  }

  req.user = user;
  next();
});

const optionalAuth = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.token) {
    token = req.cookies.token;
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
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

const adminOnly = asyncHandler(async (req, res, next) => {
  if (!req.user) {
    throw new ApiError(401, 'Not authorized');
  }
  if (!['ADMIN', 'SUPER_ADMIN'].includes(req.user.role)) {
    throw new ApiError(403, 'Admin access required');
  }
  next();
});

// ==========================================
// VALIDATION SCHEMAS
// ==========================================

const schemas = {
  register: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
    phone: z.string().optional(),
  }),

  login: z.object({
    email: z.string().email(),
    password: z.string().min(1),
  }),

  addToCart: z.object({
    productId: z.string().uuid(),
    quantity: z.number().int().positive().default(1),
  }),

  createOrder: z.object({
    shippingAddress: z.object({
      firstName: z.string().min(2),
      lastName: z.string().min(2),
      phone: z.string().min(10),
      email: z.string().email().optional(),
      address1: z.string().min(5),
      address2: z.string().optional(),
      city: z.string().min(2),
      state: z.string().optional(),
      postalCode: z.string().optional(),
      country: z.string().default('Kenya'),
    }),
    paymentMethod: z.enum(['MPESA', 'FLUTTERWAVE', 'PAYSTACK', 'PESAPAL', 'STRIPE', 'CASH_ON_DELIVERY']),
    couponCode: z.string().optional(),
  }),

  mpesaPayment: z.object({
    orderId: z.string().uuid(),
    phoneNumber: z.string().regex(/^254\d{9}$/),
  }),
};

const validate = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        status: 'error',
        message: 'Validation failed',
        errors: error.errors.map(e => ({ field: e.path.join('.'), message: e.message })),
      });
    }
    next(error);
  }
};

// ==========================================
// CART HELPER FUNCTIONS
// ==========================================

const getCartIdentifier = (req) => {
  return req.user ? `user:${req.user.id}` : `session:${req.cookies.sessionId || crypto.randomUUID()}`;
};

const getCart = async (identifier) => {
  // Try Redis first
  const cached = await cacheGet(`cart:${identifier}`);
  if (cached) return cached;

  // Try database
  const cart = await prisma.cart.findFirst({
    where: identifier.startsWith('user:') 
      ? { userId: identifier.split(':')[1] }
      : { sessionId: identifier.split(':')[1] },
    include: {
      items: {
        include: { product: true },
      },
    },
  });

  if (cart) {
    await cacheSet(`cart:${identifier}`, cart);
  }

  return cart;
};

// ==========================================
// ROUTES - AUTHENTICATION
// ==========================================

// Register
app.post('/api/auth/register', authLimiter, validate(schemas.register), asyncHandler(async (req, res) => {
  const { name, email, password, phone } = req.body;

  const existing = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  if (existing) {
    throw new ApiError(400, 'Email already registered');
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      name,
      email: email.toLowerCase(),
      passwordHash: hashedPassword,
      phone,
    },
    select: { id: true, name: true, email: true, role: true },
  });

  sendEmail(user.email, 'welcome', user.name);

  sendTokenResponse(user, 201, res);
}));


// Login
app.post('/api/auth/login', authLimiter, validate(schemas.login), asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  if (!user) {
    throw new ApiError(401, 'Invalid credentials');
  }

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    throw new ApiError(401, 'Invalid credentials');
  }

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLogin: new Date() },
  });

  sendTokenResponse(user, 200, res);
}));

// Get current user
app.get('/api/auth/me', protect, asyncHandler(async (req, res) => {
  res.json({
    status: 'success',
    data: { user: req.user },
  });
}));

// Logout
app.post('/api/auth/logout', asyncHandler(async (req, res) => {
  res
    .status(200)
    .cookie('token', 'none', { expires: new Date(Date.now() + 10 * 1000), httpOnly: true })
    .cookie('refreshToken', 'none', { expires: new Date(Date.now() + 10 * 1000), httpOnly: true })
    .json({ status: 'success', message: 'Logged out' });
}));

// Forgot password
app.post('/api/auth/forgot-password', authLimiter, asyncHandler(async (req, res) => {
  const { email } = req.body;
  
  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  
  if (user) {
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordToken: hashedToken,
        resetPasswordExpires: new Date(Date.now() + 60 * 60 * 1000),
      },
    });

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    // Send email with resetUrl
  }

  res.json({ status: 'success', message: 'If account exists, reset email sent' });
}));

// Reset password
app.post('/api/auth/reset-password/:token', authLimiter, asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await prisma.user.findFirst({
    where: {
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { gt: new Date() },
    },
  });

  if (!user) {
    throw new ApiError(400, 'Invalid or expired token');
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash: hashedPassword,
      resetPasswordToken: null,
      resetPasswordExpires: null,
    },
  });

  res.json({ status: 'success', message: 'Password reset successful' });
}));

// Update profile
app.put('/api/auth/profile', protect, asyncHandler(async (req, res) => {
  const { name, phone } = req.body;

  const user = await prisma.user.update({
    where: { id: req.user.id },
    data: { ...(name && { name }), ...(phone && { phone }) },
    select: { id: true, name: true, email: true, phone: true, role: true },
  });

  res.json({ status: 'success', data: { user } });
}));

// ==========================================
// ROUTES - PRODUCTS
// ==========================================

// Get all products
app.get('/api/products', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 20,
    category,
    search,
    minPrice,
    maxPrice,
    sortBy = 'createdAt',
    order = 'desc',
  } = req.query;

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
    ...(minPrice && { price: { gte: parseFloat(minPrice) } }),
    ...(maxPrice && { price: { lte: parseFloat(maxPrice) } }),
  };

  const [products, total] = await Promise.all([
    prisma.product.findMany({
      where,
      skip,
      take: parseInt(limit),
      orderBy: { [sortBy]: order },
    }),
    prisma.product.count({ where }),
  ]);

  res.json({
    status: 'success',
    data: { products },
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      totalPages: Math.ceil(total / parseInt(limit)),
    },
  });
}));

// Get single product
app.get('/api/products/:id', asyncHandler(async (req, res) => {
  const product = await prisma.product.findUnique({
    where: { id: req.params.id },
    include: {
      reviews: {
        where: { isApproved: true },
        include: { user: { select: { name: true } } },
        orderBy: { createdAt: 'desc' },
        take: 10,
      },
    },
  });

  if (!product) {
    throw new ApiError(404, 'Product not found');
  }

  res.json({ status: 'success', data: { product } });
}));

// Create product (Admin)
app.post('/api/admin/products', protect, adminOnly, asyncHandler(async (req, res) => {
  const {
    name,
    description,
    price,
    originalPrice,
    category,
    stock = 0,
    badge,
    image,
    images = [],
  } = req.body;

  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

  const product = await prisma.product.create({
    data: {
      name,
      slug,
      description,
      price,
      originalPrice,
      category,
      stock,
      badge,
      image,
      images,
    },
  });

  await cacheDel('products:*');

  res.status(201).json({ status: 'success', data: { product } });
}));

// Update product (Admin)
app.put('/api/admin/products/:id', protect, adminOnly, asyncHandler(async (req, res) => {
  const product = await prisma.product.update({
    where: { id: req.params.id },
    data: req.body,
  });

  await cacheDel('products:*');

  res.json({ status: 'success', data: { product } });
}));

// Delete product (Admin)
app.delete('/api/admin/products/:id', protect, adminOnly, asyncHandler(async (req, res) => {
  await prisma.product.delete({ where: { id: req.params.id } });

  await cacheDel('products:*');

  res.json({ status: 'success', message: 'Product deleted' });
}));

// ==========================================
// ROUTES - CART
// ==========================================

// Get cart
app.get('/api/cart', optionalAuth, asyncHandler(async (req, res) => {
  const identifier = getCartIdentifier(req);
  
  let cart = await getCart(identifier);

  if (!cart) {
    cart = { items: [] };
  }

  const subtotal = cart.items?.reduce((sum, item) => 
    sum + (parseFloat(item.price) * item.quantity), 0
  ) || 0;

  res.json({
    status: 'success',
    data: {
      cart: {
        items: cart.items || [],
        subtotal,
        total: subtotal,
      },
    },
  });
}));

// Add to cart
app.post('/api/cart/add', optionalAuth, validate(schemas.addToCart), asyncHandler(async (req, res) => {
  const { productId, quantity } = req.body;
  const identifier = getCartIdentifier(req);

  const product = await prisma.product.findUnique({ where: { id: productId } });
  if (!product) {
    throw new ApiError(404, 'Product not found');
  }

  if (product.stock < quantity) {
    throw new ApiError(400, 'Insufficient stock');
  }

  const [userId, sessionId] = identifier.startsWith('user:')
    ? [identifier.split(':')[1], null]
    : [null, identifier.split(':')[1]];

  let cart = await prisma.cart.findFirst({
    where: userId ? { userId } : { sessionId },
  });

  if (!cart) {
    cart = await prisma.cart.create({
      data: {
        userId,
        sessionId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
  }

  const existingItem = await prisma.cartItem.findFirst({
    where: { cartId: cart.id, productId },
  });

  if (existingItem) {
    await prisma.cartItem.update({
      where: { id: existingItem.id },
      data: { quantity: existingItem.quantity + quantity },
    });
  } else {
    await prisma.cartItem.create({
      data: {
        cartId: cart.id,
        productId,
        quantity,
        price: product.price,
      },
    });
  }

  await cacheDel(`cart:${identifier}`);

  res.json({ status: 'success', message: 'Item added to cart' });
}));

// Update cart item
app.put('/api/cart/update', optionalAuth, asyncHandler(async (req, res) => {
  const { productId, quantity } = req.body;
  const identifier = getCartIdentifier(req);

  const [userId, sessionId] = identifier.startsWith('user:')
    ? [identifier.split(':')[1], null]
    : [null, identifier.split(':')[1]];

  const cart = await prisma.cart.findFirst({
    where: userId ? { userId } : { sessionId },
  });

  if (!cart) {
    throw new ApiError(404, 'Cart not found');
  }

  if (quantity === 0) {
    await prisma.cartItem.deleteMany({
      where: { cartId: cart.id, productId },
    });
  } else {
    await prisma.cartItem.updateMany({
      where: { cartId: cart.id, productId },
      data: { quantity },
    });
  }

  await cacheDel(`cart:${identifier}`);

  res.json({ status: 'success', message: 'Cart updated' });
}));

// Remove from cart
app.delete('/api/cart/remove/:productId', optionalAuth, asyncHandler(async (req, res) => {
  const { productId } = req.params;
  const identifier = getCartIdentifier(req);

  const [userId, sessionId] = identifier.startsWith('user:')
    ? [identifier.split(':')[1], null]
    : [null, identifier.split(':')[1]];

  const cart = await prisma.cart.findFirst({
    where: userId ? { userId } : { sessionId },
  });

  if (cart) {
    await prisma.cartItem.deleteMany({
      where: { cartId: cart.id, productId },
    });
    await cacheDel(`cart:${identifier}`);
  }

  res.json({ status: 'success', message: 'Item removed' });
}));

// Clear cart
app.delete('/api/cart/clear', optionalAuth, asyncHandler(async (req, res) => {
  const identifier = getCartIdentifier(req);

  const [userId, sessionId] = identifier.startsWith('user:')
    ? [identifier.split(':')[1], null]
    : [null, identifier.split(':')[1]];

  const cart = await prisma.cart.findFirst({
    where: userId ? { userId } : { sessionId },
  });

  if (cart) {
    await prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
    await cacheDel(`cart:${identifier}`);
  }

  res.json({ status: 'success', message: 'Cart cleared' });
}));

// ==========================================
// ROUTES - CHECKOUT & ORDERS
// ==========================================

// Create order
app.post('/api/checkout/confirm', protect, validate(schemas.createOrder), asyncHandler(async (req, res) => {
  const { shippingAddress, paymentMethod, couponCode } = req.body;

  // Get cart
  const cart = await prisma.cart.findFirst({
    where: { userId: req.user.id },
    include: { items: { include: { product: true } } },
  });

  if (!cart || cart.items.length === 0) {
    throw new ApiError(400, 'Cart is empty');
  }

  // Verify stock
  for (const item of cart.items) {
    if (item.product.stock < item.quantity) {
      throw new ApiError(400, `Insufficient stock for ${item.product.name}`);
    }
  }

  // Calculate totals
  const subtotal = cart.items.reduce((sum, item) => 
    sum + (parseFloat(item.price) * item.quantity), 0
  );
  
  const shippingCost = subtotal >= 5000 ? 0 : 500;
  const tax = subtotal * 0.16;
  let discount = 0;

  if (couponCode) {
    const coupon = await prisma.coupon.findUnique({
      where: { code: couponCode, isActive: true },
    });

    if (coupon && (!coupon.expiresAt || coupon.expiresAt > new Date())) {
      if (coupon.discountType === 'PERCENTAGE') {
        discount = (subtotal * parseFloat(coupon.discountValue)) / 100;
        if (coupon.maxDiscount) {
          discount = Math.min(discount, parseFloat(coupon.maxDiscount));
        }
      } else {
        discount = parseFloat(coupon.discountValue);
      }

      await prisma.coupon.update({
        where: { id: coupon.id },
        data: { usageCount: { increment: 1 } },
      });
    }
  }

  const total = subtotal + shippingCost + tax - discount;

  // Create shipping address
  const address = await prisma.address.create({
    data: {
      userId: req.user.id,
      ...shippingAddress,
    },
  });

  // Generate order number
  const orderNumber = `ORD-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

  // Create order
  const order = await prisma.order.create({
    data: {
      orderNumber,
      userId: req.user.id,
      email: req.user.email,
      subtotal,
      shippingCost,
      tax,
      discount,
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

  // Create payment record
  await prisma.payment.create({
    data: {
      orderId: order.id,
      provider: paymentMethod,
      amount: total,
      currency: 'KES',
    },
  });

  // Clear cart
  await prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
  await cacheDel(`cart:user:${req.user.id}`);

  res.status(201).json({
    status: 'success',
    data: { order },
  });
}));

// Get user orders
app.get('/api/orders/user', protect, asyncHandler(async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { userId: req.user.id },
    include: {
      items: true,
      payment: true,
    },
    orderBy: { createdAt: 'desc' },
  });

  res.json({ status: 'success', data: { orders } });
}));

// Get order details
app.get('/api/orders/:id', protect, asyncHandler(async (req, res) => {
  const order = await prisma.order.findFirst({
    where: {
      id: req.params.id,
      userId: req.user.id,
    },
    include: {
      items: true,
      payment: true,
      shippingAddress: true,
    },
  });

  if (!order) {
    throw new ApiError(404, 'Order not found');
  }

  res.json({ status: 'success', data: { order } });
}));

// ==========================================
// ROUTES - PAYMENTS
// ==========================================

// M-Pesa STK Push
app.post('/api/payments/mpesa/stk-push', protect, paymentLimiter, validate(schemas.mpesaPayment), asyncHandler(async (req, res) => {
  const { orderId, phoneNumber } = req.body;

  const order = await prisma.order.findFirst({
    where: { id: orderId, userId: req.user.id },
    include: { payment: true },
  });

  if (!order) {
    throw new ApiError(404, 'Order not found');
  }

  if (order.payment.status === 'COMPLETED') {
    throw new ApiError(400, 'Order already paid');
  }

  const result = await mpesaService.initiateSTKPush(orderId, phoneNumber, order.total);

  res.json({
    status: 'success',
    message: 'STK push sent to phone',
    data: result,
  });
}));

// M-Pesa Callback
app.post('/api/payments/mpesa/callback', express.raw({ type: 'application/json' }), asyncHandler(async (req, res) => {
  const callbackData = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  
  await mpesaService.handleCallback(callbackData);

  res.json({ ResultCode: 0, ResultDesc: 'Success' });
}));

// Flutterwave initiate (placeholder)
app.post('/api/payments/flutterwave/initiate', protect, paymentLimiter, asyncHandler(async (req, res) => {
  // Implement Flutterwave payment initiation
  res.json({ status: 'success', message: 'Flutterwave payment initiated' });
}));

// Paystack initiate (placeholder)
app.post('/api/payments/paystack/initiate', protect, paymentLimiter, asyncHandler(async (req, res) => {
  // Implement Paystack payment initiation
  res.json({ status: 'success', message: 'Paystack payment initiated' });
}));

// ==========================================
// ROUTES - ADMIN
// ==========================================

// Get all orders (Admin)
app.get('/api/admin/orders', protect, adminOnly, asyncHandler(async (req, res) => {
  const { status, page = 1, limit = 20 } = req.query;

  const where = status ? { status } : {};
  const skip = (parseInt(page) - 1) * parseInt(limit);

  const [orders, total] = await Promise.all([
    prisma.order.findMany({
      where,
      include: {
        user: { select: { name: true, email: true } },
        items: true,
        payment: true,
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: parseInt(limit),
    }),
    prisma.order.count({ where }),
  ]);

  res.json({
    status: 'success',
    data: { orders },
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      totalPages: Math.ceil(total / parseInt(limit)),
    },
  });
}));

// Update order status (Admin)
app.put('/api/admin/orders/:id/status', protect, adminOnly, asyncHandler(async (req, res) => {
  const { status, trackingNumber } = req.body;

  const order = await prisma.order.update({
    where: { id: req.params.id },
    data: {
      status,
      ...(trackingNumber && { trackingNumber }),
      ...(status === 'SHIPPED' && { shippedAt: new Date() }),
      ...(status === 'DELIVERED' && { deliveredAt: new Date() }),
    },
  });

  res.json({ status: 'success', data: { order } });
}));

// Get analytics (Admin)
app.get('/api/admin/analytics', protect, adminOnly, asyncHandler(async (req, res) => {
  const [
    totalOrders,
    totalRevenue,
    totalCustomers,
    pendingOrders,
    topProducts,
  ] = await Promise.all([
    prisma.order.count(),
    prisma.order.aggregate({ _sum: { total: true }, where: { status: { not: 'CANCELLED' } } }),
    prisma.user.count({ where: { role: 'USER' } }),
    prisma.order.count({ where: { status: 'PENDING' } }),
    prisma.product.findMany({
      orderBy: { totalSales: 'desc' },
      take: 10,
      select: { id: true, name: true, totalSales: true, price: true },
    }),
  ]);

  res.json({
    status: 'success',
    data: {
      totalOrders,
      totalRevenue: totalRevenue._sum.total || 0,
      totalCustomers,
      pendingOrders,
      topProducts,
    },
  });
}));

// ==========================================
// ROUTES - COUPONS
// ==========================================

// Validate coupon
app.post('/api/coupons/validate', asyncHandler(async (req, res) => {
  const { code, orderTotal } = req.body;

  const coupon = await prisma.coupon.findUnique({
    where: { code, isActive: true },
  });

  if (!coupon || (coupon.expiresAt && coupon.expiresAt < new Date())) {
    throw new ApiError(400, 'Invalid or expired coupon');
  }

  if (coupon.minOrderAmount && orderTotal < parseFloat(coupon.minOrderAmount)) {
    throw new ApiError(400, `Minimum order amount is ${coupon.minOrderAmount}`);
  }

  let discount = 0;
  if (coupon.discountType === 'PERCENTAGE') {
    discount = (orderTotal * parseFloat(coupon.discountValue)) / 100;
    if (coupon.maxDiscount) {
      discount = Math.min(discount, parseFloat(coupon.maxDiscount));
    }
  } else {
    discount = parseFloat(coupon.discountValue);
  }

  res.json({
    status: 'success',
    data: {
      discount,
      finalTotal: orderTotal - discount,
    },
  });
}));

// Create coupon (Admin)
app.post('/api/admin/coupons', protect, adminOnly, asyncHandler(async (req, res) => {
  const coupon = await prisma.coupon.create({ data: req.body });
  res.status(201).json({ status: 'success', data: { coupon } });
}));

// ==========================================
// ROUTES - NEWSLETTER
// ==========================================


app.post('/api/newsletter/subscribe', asyncHandler(async (req, res) => {
  const { email } = req.body;

  const existing = await prisma.newsletter.findUnique({ where: { email } });

  if (existing) {
    if (existing.isSubscribed) {
      throw new ApiError(400, 'Already subscribed');
    } else {
      await prisma.newsletter.update({
        where: { email },
        data: { isSubscribed: true, unsubscribedAt: null },
      });
    }
  } else {
    await prisma.newsletter.create({ data: { email } });
  }

  res.json({ status: 'success', message: 'Subscribed successfully' });
}));

// ==========================================
// ROUTES - SEARCH
// ==========================================

app.get('/api/search', asyncHandler(async (req, res) => {
  const { q } = req.query;

  const products = await prisma.product.findMany({
    where: {
      isActive: true,
      OR: [
        { name: { contains: q, mode: 'insensitive' } },
        { description: { contains: q, mode: 'insensitive' } },
        { tags: { has: q } },
      ],
    },
    take: 20,
  });

  res.json({ status: 'success', data: { results: products } });
}));

// ==========================================
// ROUTES - REVIEWS
// ==========================================

app.post('/api/reviews', protect, asyncHandler(async (req, res) => {
  const { productId, rating, comment } = req.body;

  const existing = await prisma.review.findUnique({
    where: {
      userId_productId: {
        userId: req.user.id,
        productId,
      },
    },
  });

  if (existing) {
    throw new ApiError(400, 'Already reviewed this product');
  }

  const review = await prisma.review.create({
    data: {
      userId: req.user.id,
      productId,
      rating,
      comment,
    },
  });

  // Update product average rating
  const reviews = await prisma.review.findMany({
    where: { productId, isApproved: true },
  });
  
  const avgRating = reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length;

  await prisma.product.update({
    where: { id: productId },
    data: {
      averageRating: avgRating,
      totalReviews: reviews.length,
    },
  });

  res.status(201).json({ status: 'success', data: { review } });
}));

// ==========================================
// HEALTH CHECK
// ==========================================

app.get('/health', (req, res) => {
  res.json({
    status: 'success',
    message: 'Classic Closet API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
  });
});

// ==========================================
// ERROR HANDLING
// ==========================================

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    status: 'error',
    message: `Route ${req.originalUrl} not found`,
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  logger.error(err);

  let error = { ...err };
  error.message = err.message;

  // Prisma errors
  if (err.code === 'P2002') {
    error = new ApiError(400, 'Duplicate field value');
  }
  if (err.code === 'P2025') {
    error = new ApiError(404, 'Record not found');
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = new ApiError(401, 'Invalid token');
  }
  if (err.name === 'TokenExpiredError') {
    error = new ApiError(401, 'Token expired');
  }

  res.status(error.statusCode || 500).json({
    status: 'error',
    message: error.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// ==========================================
// DATABASE & REDIS CONNECTION
// ==========================================

prisma.$connect()
  .then(() => logger.info('✅ Database connected'))
  .catch((err) => {
    logger.error('❌ Database connection failed:', err);
    process.exit(1);
  });

// ==========================================
// START SERVER
// ==========================================

const server = app.listen(PORT, () => {
  logger.info(`Classic Closet API running on port ${PORT}`);
  logger.info(`📍 Environment: ${process.env.NODE_ENV}`);
  logger.info(`🌐 Frontend: ${process.env.FRONTEND_URL}`);
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection:', err);
  server.close(() => process.exit(1));
});

export default app;

