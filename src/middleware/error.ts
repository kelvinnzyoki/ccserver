import type { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/apiError.js';

export const notFound = (_req: Request, res: Response): void => {
  res.status(404).json({ status: 'error', message: 'Route not found' });
};

export const errorHandler = (
  err: unknown,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
): void => {
  // ── Always log the real error ─────────────────────────────────────────────
  // Previously this was missing — every 500 was invisible in Vercel logs.
  // Now you can see the actual Prisma / JWT / validation error.
  if (!(err instanceof ApiError) || (err as ApiError).statusCode >= 500) {
    console.error('[error]', err);
  }

  if (err instanceof ApiError) {
    res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
    });
    return;
  }

  // Prisma known request errors (e.g. unique constraint violation)
  if (isObject(err) && err.code && typeof err.code === 'string' && err.code.startsWith('P')) {
    const prismaMessage = getPrismaMessage(err.code as string);
    res.status(prismaMessage.status).json({
      status: 'error',
      message: prismaMessage.message,
    });
    return;
  }

  // Zod validation errors that escaped the validate() middleware
  if (isObject(err) && err.name === 'ZodError') {
    res.status(400).json({
      status: 'error',
      message: 'Validation failed',
    });
    return;
  }

  // JWT errors
  if (isObject(err) && err.name === 'JsonWebTokenError') {
    res.status(401).json({ status: 'error', message: 'Invalid token' });
    return;
  }
  if (isObject(err) && err.name === 'TokenExpiredError') {
    res.status(401).json({ status: 'error', message: 'Token expired' });
    return;
  }

  // Fallback
  res.status(500).json({
    status: 'error',
    message:
      process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : (err instanceof Error ? err.message : 'Internal server error'),
  });
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isObject(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null;
}

function getPrismaMessage(code: string): { status: number; message: string } {
  const map: Record<string, { status: number; message: string }> = {
    P2002: { status: 409, message: 'A record with these details already exists' },
    P2025: { status: 404, message: 'Record not found' },
    P2003: { status: 400, message: 'Invalid reference — related record not found' },
    P1001: { status: 503, message: 'Database unreachable — check DATABASE_URL and Neon connection limit' },
    P2024: { status: 503, message: 'Database connection pool exhausted — use Neon pooled endpoint' },
  };
  return map[code] ?? { status: 500, message: 'Database error' };
}
