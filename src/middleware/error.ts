import { ApiError } from '../utils/apiError.js';
export const notFound = (_req:any,res:any) => res.status(404).json({ status:'error', message:'Route not found' });
export const errorHandler = (err:any,_req:any,res:any,_next:any) => {
  const status = err instanceof ApiError ? err.statusCode : 500;
  res.status(status).json({ status:'error', message: status === 500 ? 'Internal server error' : err.message });
};
