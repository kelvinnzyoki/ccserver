import type { UserRole } from '@prisma/client';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        name: string;
        role: UserRole;
        phone?: string | null;
        emailVerified?: boolean;
        phoneVerified?: boolean;
      };
    }
  }
}

export {};
