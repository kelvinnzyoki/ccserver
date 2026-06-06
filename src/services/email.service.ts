import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';

export async function sendEmailVerificationCode(email: string, code: string) {
  if (!env.RESEND_API_KEY) {
    throw new ApiError(500, 'RESEND_API_KEY is not configured');
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.RESEND_FROM_EMAIL,
      to: [email],
      subject: 'Your Classic Closet verification code',
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Verify your email</h2>
          <p>Your verification code is:</p>
          <p style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</p>
          <p>This code expires in 10 minutes.</p>
        </div>
      `,
    }),
  });

  if (!response.ok) {
    throw new ApiError(502, 'Failed to send email verification code');
  }
}
