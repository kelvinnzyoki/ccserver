import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { prisma } from '../config/prisma.js';

const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
const OTP_LENGTH = 6;

/** Cryptographically random 6-digit string — no Math.random() */
export function generateOtpCode(length = OTP_LENGTH): string {
  const bytes = crypto.randomBytes(length);
  let code = '';
  for (let i = 0; i < length; i++) {
    code += bytes[i] % 10;
  }
  return code;
}

/**
 * Invalidates all prior unused codes for the same target+type,
 * then creates and stores a fresh hashed OTP.
 * Returns the plaintext code (only time it exists in memory).
 */
export async function createOtp(target: string, type: string): Promise<string> {
  await prisma.verificationCode.updateMany({
    where: { target, type, consumedAt: null },
    data: { consumedAt: new Date() },
  });

  const code = generateOtpCode();
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

  await prisma.verificationCode.create({
    data: { target, type, codeHash, expiresAt },
  });

  return code;
}

/**
 * Finds the most recent valid code for target+type, timing-safely compares it,
 * and marks it consumed on success.
 * Returns true if valid and consumed, false otherwise.
 */
export async function verifyOtp(
  target: string,
  type: string,
  code: string
): Promise<boolean> {
  const record = await prisma.verificationCode.findFirst({
    where: {
      target,
      type,
      consumedAt: null,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
  });

  if (!record) return false;

  const valid = await bcrypt.compare(code, record.codeHash);

  if (valid) {
    await prisma.verificationCode.update({
      where: { id: record.id },
      data: { consumedAt: new Date() },
    });
  }

  return valid;
}
