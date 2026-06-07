import { PrismaClient } from '@prisma/client';

// ─── Serverless singleton ─────────────────────────────────────────────────────
//
// On Vercel each serverless invocation can evaluate this module fresh, creating
// a new PrismaClient that opens its own connection(s) to Neon.  Neon's free
// tier allows only ~10 concurrent connections.  Without this guard, a burst of
// a few simultaneous requests exhausts the pool and every DB call throws
// PrismaClientInitializationError → 500.
//
// globalThis persists across hot-reloads in dev and across module re-evaluations
// within the SAME Vercel instance in production.  For cross-instance connection
// pooling, use Neon's pooled endpoint (pgBouncer URL from the Neon dashboard)
// as your DATABASE_URL instead of the direct connection string.
//
// Neon pooled URL format:
//   postgresql://user:pass@ep-xxx-pooler.region.aws.neon.tech/dbname?sslmode=require
//
// If you must use the direct URL, append: ?connection_limit=1&pool_timeout=20

declare global {
  // eslint-disable-next-line no-var
  var __prisma: PrismaClient | undefined;
}

function createPrismaClient(): PrismaClient {
  return new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['query', 'warn', 'error']
        : ['error'],
  });
}

export const prisma: PrismaClient =
  globalThis.__prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== 'production') {
  globalThis.__prisma = prisma;
}
