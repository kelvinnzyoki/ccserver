import type { ZodSchema } from 'zod';

export const validate = (schema: ZodSchema) => (req: any, res: any, next: any) => {
  const result = schema.safeParse({
    body: req.body,
    query: req.query,
    params: req.params,
  });

  if (!result.success) {
    // FIX: result.error.flatten() only inspects the FIRST level of the
    // schema. Because every route wraps its real shape one level deeper
    // — z.object({ body: z.object({ image: z.string().url(), ... }) }) —
    // a failure on a nested field like `body.image` gets attributed by
    // flatten() to the top-level key "body" itself, not to "image". That's
    // why the frontend was showing the unhelpful "body: Invalid url"
    // instead of "image: Invalid url".
    //
    // result.error.issues is the raw, ungrouped list of every failure,
    // each with its own exact `path` array (e.g. ['body', 'image']) and
    // `message`. Mapping over that directly gives precise, per-field
    // errors regardless of nesting depth.
    const errors = result.error.issues.map((issue) => ({
      path: issue.path.join('.'),
      message: issue.message,
    }));

    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors,
    });
  }

  // Write coerced/defaulted values back onto req so routes can keep
  // reading req.body/query/params normally and still get transformed
  // values (e.g. z.coerce.number(), z.string().default('Kenya')).
  if (result.data.body !== undefined)   req.body   = result.data.body;
  if (result.data.query !== undefined)  req.query  = result.data.query;
  if (result.data.params !== undefined) req.params = result.data.params;

  req.validated = result.data;
  next();
};
