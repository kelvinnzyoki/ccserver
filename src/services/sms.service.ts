import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';

export async function sendPhoneVerificationCode(phone: string, code: string) {
  if (!env.AFRICASTALKING_API_KEY) {
    throw new ApiError(500, 'AFRICASTALKING_API_KEY is not configured');
  }

  const body = new URLSearchParams({
    username: env.AFRICASTALKING_USERNAME,
    to: phone,
    message: `Your Classic Closet verification code is ${code}. It expires in 10 minutes.`,
  });

  const response = await fetch('https://api.africastalking.com/version1/messaging', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      apiKey: env.AFRICASTALKING_API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  if (!response.ok) {
    throw new ApiError(502, 'Failed to send SMS verification code');
  }
}
