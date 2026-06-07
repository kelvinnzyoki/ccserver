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

  // Cookie domains must be bare hostnames — no protocol, no path, no port.
  // e.g. ".cctamcc.site"  NOT  "https://cctamcc.site"
  // The transform strips any accidental protocol/path so a misconfigured
  // env var ("https://cctamcc.site") never crashes the cookie serializer.
  COOKIE_DOMAIN: z
    .string()
    .optional()
    .transform((val) => {
      if (!val || !val.trim()) return undefined;
      // Strip protocol (http:// or https://)
      let domain = val.trim().replace(/^https?:\/\//i, '');
      // Strip any path after the hostname
      domain = domain.split('/')[0];
      // Strip port if present
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
  AFRICASTALKING_API_KEY: z.string().optional(),
  AFRICASTALKING_USERNAME: z.string().default('sandbox'),
  CURRENCY: z.string().default('KES'),
});

export const env = schema.parse(process.env);
export const isProd = env.NODE_ENV === 'production';
