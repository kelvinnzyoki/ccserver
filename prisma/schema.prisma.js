// ==========================================
// PREMIUM CLOSET - PRISMA DATABASE SCHEMA
// Complete E-Commerce Database Schema
// ==========================================

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// ==========================================
// ENUMS
// ==========================================

enum UserRole {
  USER
  ADMIN
  SUPER_ADMIN
}

enum OrderStatus {
  PENDING
  PAID
  PROCESSING
  SHIPPED
  DELIVERED
  CANCELLED
  REFUNDED
}

enum PaymentStatus {
  PENDING
  COMPLETED
  FAILED
  REFUNDED
}

enum PaymentProvider {
  MPESA
  FLUTTERWAVE
  PAYSTACK
  PESAPAL
  STRIPE
  CASH_ON_DELIVERY
}

// ==========================================
// USER MANAGEMENT
// ==========================================

model User {
  id                    String    @id @default(uuid())
  email                 String    @unique
  name                  String
  passwordHash          String
  phone                 String?
  role                  UserRole  @default(USER)
  isEmailVerified       Boolean   @default(false)
  emailVerifyToken      String?
  resetPasswordToken    String?
  resetPasswordExpires  DateTime?
  lastLogin             DateTime?
  createdAt             DateTime  @default(now())
  updatedAt             DateTime  @updatedAt

  // Relations
  orders                Order[]
  reviews               Review[]
  addresses             Address[]
  wishlist              WishlistItem[]
  carts                 Cart[]

  @@index([email])
  @@map("users")
}

// ==========================================
// PRODUCT CATALOG
// ==========================================

model Product {
  id                String    @id @default(uuid())
  name              String
  slug              String    @unique
  description       String    @db.Text
  price             Decimal   @db.Decimal(10, 2)
  originalPrice     Decimal?  @db.Decimal(10, 2)
  image             String
  images            String[]  @default([])
  category          String
  badge             String?
  stock             Int       @default(0)
  sku               String?   @unique
  weight            Decimal?  @db.Decimal(10, 2)
  dimensions        Json?
  isActive          Boolean   @default(true)
  isFeatured        Boolean   @default(false)
  seoTitle          String?
  seoDescription    String?
  tags              String[]  @default([])
  averageRating     Decimal   @default(0) @db.Decimal(3, 2)
  totalReviews      Int       @default(0)
  totalSales        Int       @default(0)
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt

  // Relations
  cartItems         CartItem[]
  orderItems        OrderItem[]
  reviews           Review[]
  wishlistItems     WishlistItem[]
  inventoryLogs     InventoryLog[]

  @@index([category])
  @@index([slug])
  @@index([isActive])
  @@index([isFeatured])
  @@map("products")
}

// ==========================================
// SHOPPING CART
// ==========================================

model Cart {
  id                String    @id @default(uuid())
  userId            String?
  sessionId         String?
  expiresAt         DateTime?
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt

  // Relations
  user              User?     @relation(fields: [userId], references: [id], onDelete: Cascade)
  items             CartItem[]

  @@index([userId])
  @@index([sessionId])
  @@index([expiresAt])
  @@map("carts")
}

model CartItem {
  id                String    @id @default(uuid())
  cartId            String
  productId         String
  quantity          Int       @default(1)
  price             Decimal   @db.Decimal(10, 2)
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt

  // Relations
  cart              Cart      @relation(fields: [cartId], references: [id], onDelete: Cascade)
  product           Product   @relation(fields: [productId], references: [id], onDelete: Cascade)

  @@unique([cartId, productId])
  @@index([cartId])
  @@index([productId])
  @@map("cart_items")
}

// ==========================================
// ORDERS
// ==========================================

model Order {
  id                    String        @id @default(uuid())
  orderNumber           String        @unique
  userId                String
  email                 String
  status                OrderStatus   @default(PENDING)
  subtotal              Decimal       @db.Decimal(10, 2)
  shippingCost          Decimal       @default(0) @db.Decimal(10, 2)
  tax                   Decimal       @default(0) @db.Decimal(10, 2)
  discount              Decimal       @default(0) @db.Decimal(10, 2)
  total                 Decimal       @db.Decimal(10, 2)
  couponCode            String?
  paymentMethod         PaymentProvider
  shippingAddressId     String
  billingAddressId      String?
  notes                 String?       @db.Text
  trackingNumber        String?
  shippedAt             DateTime?
  deliveredAt           DateTime?
  cancelledAt           DateTime?
  cancellationReason    String?       @db.Text
  createdAt             DateTime      @default(now())
  updatedAt             DateTime      @updatedAt

  // Relations
  user                  User          @relation(fields: [userId], references: [id])
  items                 OrderItem[]
  payment               Payment?
  shippingAddress       Address       @relation("ShippingAddress", fields: [shippingAddressId], references: [id])
  billingAddress        Address?      @relation("BillingAddress", fields: [billingAddressId], references: [id])

  @@index([userId])
  @@index([orderNumber])
  @@index([status])
  @@index([createdAt])
  @@index([email])
  @@map("orders")
}

model OrderItem {
  id                String    @id @default(uuid())
  orderId           String
  productId         String
  productName       String
  productImage      String
  price             Decimal   @db.Decimal(10, 2)
  quantity          Int
  total             Decimal   @db.Decimal(10, 2)
  createdAt         DateTime  @default(now())

  // Relations
  order             Order     @relation(fields: [orderId], references: [id], onDelete: Cascade)
  product           Product   @relation(fields: [productId], references: [id])

  @@index([orderId])
  @@index([productId])
  @@map("order_items")
}

// ==========================================
// PAYMENTS
// ==========================================

model Payment {
  id                String          @id @default(uuid())
  orderId           String          @unique
  provider          PaymentProvider
  status            PaymentStatus   @default(PENDING)
  amount            Decimal         @db.Decimal(10, 2)
  currency          String          @default("KES")
  transactionRef    String?         @unique
  providerRef       String?
  phoneNumber       String?
  metadata          Json?
  failureReason     String?         @db.Text
  paidAt            DateTime?
  createdAt         DateTime        @default(now())
  updatedAt         DateTime        @updatedAt

  // Relations
  order             Order           @relation(fields: [orderId], references: [id], onDelete: Cascade)

  @@index([orderId])
  @@index([transactionRef])
  @@index([status])
  @@index([provider])
  @@map("payments")
}

// ==========================================
// ADDRESSES
// ==========================================

model Address {
  id                String    @id @default(uuid())
  userId            String
  firstName         String
  lastName          String
  phone             String
  email             String?
  address1          String
  address2          String?
  city              String
  state             String?
  postalCode        String?
  country           String    @default("Kenya")
  isDefault         Boolean   @default(false)
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt

  // Relations
  user              User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  shippingOrders    Order[]   @relation("ShippingAddress")
  billingOrders     Order[]   @relation("BillingAddress")

  @@index([userId])
  @@map("addresses")
}

// ==========================================
// REVIEWS & RATINGS
// ==========================================

model Review {
  id                    String    @id @default(uuid())
  userId                String
  productId             String
  rating                Int
  comment               String?   @db.Text
  isVerifiedPurchase    Boolean   @default(false)
  isApproved            Boolean   @default(false)
  createdAt             DateTime  @default(now())
  updatedAt             DateTime  @updatedAt

  // Relations
  user                  User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  product               Product   @relation(fields: [productId], references: [id], onDelete: Cascade)

  @@unique([userId, productId])
  @@index([productId])
  @@index([rating])
  @@index([isApproved])
  @@map("reviews")
}

// ==========================================
// COUPONS & DISCOUNTS
// ==========================================

model Coupon {
  id                String    @id @default(uuid())
  code              String    @unique
  description       String?
  discountType      String    // PERCENTAGE, FIXED
  discountValue     Decimal   @db.Decimal(10, 2)
  minOrderAmount    Decimal?  @db.Decimal(10, 2)
  maxDiscount       Decimal?  @db.Decimal(10, 2)
  usageLimit        Int?
  usageCount        Int       @default(0)
  expiresAt         DateTime?
  isActive          Boolean   @default(true)
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt

  @@index([code])
  @@index([isActive])
  @@index([expiresAt])
  @@map("coupons")
}

// ==========================================
// NEWSLETTER
// ==========================================

model Newsletter {
  id                String    @id @default(uuid())
  email             String    @unique
  isSubscribed      Boolean   @default(true)
  subscribedAt      DateTime  @default(now())
  unsubscribedAt    DateTime?

  @@index([email])
  @@index([isSubscribed])
  @@map("newsletters")
}

// ==========================================
// INVENTORY TRACKING
// ==========================================

model InventoryLog {
  id                String    @id @default(uuid())
  productId         String
  previousStock     Int
  newStock          Int
  changeAmount      Int
  reason            String
  referenceId       String?
  performedBy       String?
  createdAt         DateTime  @default(now())

  // Relations
  product           Product   @relation(fields: [productId], references: [id], onDelete: Cascade)

  @@index([productId])
  @@index([createdAt])
  @@index([reason])
  @@map("inventory_logs")
}

// ==========================================
// WISHLIST
// ==========================================

model WishlistItem {
  id                String    @id @default(uuid())
  userId            String
  productId         String
  createdAt         DateTime  @default(now())

  // Relations
  user              User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  product           Product   @relation(fields: [productId], references: [id], onDelete: Cascade)

  @@unique([userId, productId])
  @@index([userId])
  @@index([productId])
  @@map("wishlist_items")
}

// ==========================================
// ANALYTICS
// ==========================================

model Analytics {
  id                    String    @id @default(uuid())
  date                  DateTime  @db.Date
  totalOrders           Int       @default(0)
  totalRevenue          Decimal   @default(0) @db.Decimal(10, 2)
  totalCustomers        Int       @default(0)
  conversionRate        Decimal   @default(0) @db.Decimal(5, 2)
  averageOrderValue     Decimal   @default(0) @db.Decimal(10, 2)
  metadata              Json?
  createdAt             DateTime  @default(now())

  @@unique([date])
  @@index([date])
  @@map("analytics")
}

// ==========================================
// DATABASE NOTES
// ==========================================

// This schema includes:
// - User authentication & authorization
// - Product catalog with inventory
// - Shopping cart (session & user-based)
// - Order management with full lifecycle
// - Payment tracking (multi-gateway support)
// - Address management
// - Product reviews & ratings
// - Coupon/discount system
// - Newsletter subscriptions
// - Inventory logging
// - Wishlist functionality
// - Analytics & reporting

// Features:
// - UUIDs for all primary keys
// - Proper indexes for performance
// - Cascading deletes where appropriate
// - Default values
// - Timestamps (createdAt, updatedAt)
// - Decimal types for money
// - Text types for long content
// - JSON for flexible metadata
// - Unique constraints
// - Enums for status fields

// To use this schema:
// 1. Copy to prisma/schema.prisma
// 2. Run: npx prisma generate
// 3. Run: npx prisma db push
// 4. (Optional) Run: npx prisma studio
