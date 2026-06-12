import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(4000),
  DATABASE_URL: z.string().min(1),
  FRONTEND_URL: z.string().url(),
  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),

  // Strip any accidental protocol/path/port so a misconfigured
  // env var never crashes the cookie serializer.
  COOKIE_DOMAIN: z
    .string()
    .optional()
    .transform((val) => {
      if (!val || !val.trim()) return undefined;
      let domain = val.trim().replace(/^https?:\/\//i, '');
      domain = domain.split('/')[0];
      domain = domain.split(':')[0];
      return domain || undefined;
    }),

  PAYSTACK_SECRET_KEY: z.string().optional(),
  PAYSTACK_CALLBACK_URL: z.string().url().optional(),
  MPESA_ENVIRONMENT: z.enum(['sandbox', 'production']).default('sandbox'),
  MPESA_CONSUMER_KEY: z.string().optional(),
  MPESA_CONSUMER_SECRET: z.string().optional(),
  MPESA_SHORTCODE: z.string().optional(),
  MPESA_PASSKEY: z.string().optional(),
  MPESA_CALLBACK_URL: z.string().url().optional(),
  RESEND_API_KEY: z.string().optional(),
  RESEND_FROM_EMAIL: z
    .string()
    .email()
    .default('Classic Closet <noreply@cctamcc.site>'),

  // FIX: renamed from AFRICASTALKING_* to AT_* to match sms.service.ts usage.
  // Update your .env accordingly: AT_API_KEY, AT_USERNAME, AT_SENDER_ID (optional).
  AT_API_KEY: z.string().optional(),
  AT_USERNAME: z.string().default('sandbox'),
  AT_SENDER_ID: z.string().optional(),

  CURRENCY: z.string().default('KES'),
});

export const env = schema.parse(process.env);
export const isProd = env.NODE_ENV === 'production';
