import type { Request, Response, NextFunction } from 'express';

type AsyncFn = (req: Request, res: Response, next: NextFunction) => Promise<unknown>;

/**
 * Wraps an async route handler so that any thrown error or rejected promise
 * is forwarded to Express's next(error) — which hands it to your error
 * middleware — instead of becoming an unhandled rejection that silently
 * hangs the request or crashes the process.
 *
 * The critical detail: Promise.resolve().catch(next) is the ONLY safe pattern.
 * Using try/catch inside the wrapper itself can miss synchronous throws that
 * happen before the first `await`.
 */
export const asyncHandler =
  (fn: AsyncFn) =>
  (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
