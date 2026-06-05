import type { ZodSchema } from 'zod';
export const validate = (schema: ZodSchema) => (req:any,res:any,next:any) => {
  const result = schema.safeParse({ body:req.body, query:req.query, params:req.params });
  if (!result.success) return res.status(400).json({ status:'error', message:'Validation failed', errors: result.error.flatten() });
  req.validated = result.data; next();
};
