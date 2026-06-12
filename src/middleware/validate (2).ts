import type { ZodSchema } from 'zod';

export const validate = (schema: ZodSchema) => (req: any, res: any, next: any) => {
  const result = schema.safeParse({
    body: req.body,
    query: req.query,
    params: req.params,
  });

  if (!result.success) {
    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors: result.error.flatten(),
    });
  }

  // FIX: write coerced/defaulted values back onto req so routes
  // can keep reading req.body/query/params normally and still get
  // transformed values (e.g. z.coerce.number(), z.string().default('Kenya')).
  if (result.data.body !== undefined)   req.body   = result.data.body;
  if (result.data.query !== undefined)  req.query  = result.data.query;
  if (result.data.params !== undefined) req.params = result.data.params;

  req.validated = result.data;
  next();
};
