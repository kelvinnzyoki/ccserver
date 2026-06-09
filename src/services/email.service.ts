/**
 * Email delivery via Resend (https://resend.com)
 * Required env vars: RESEND_API_KEY, RESEND_FROM_EMAIL
 */

import { env } from '../config/env.js';

interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
}

export async function sendEmail({ to, subject, html }: SendEmailOptions): Promise<void> {
  if (!env.RESEND_API_KEY) {
    console.warn('[email] RESEND_API_KEY not set — email not sent to:', to);
    return;
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.RESEND_FROM_EMAIL,
      to,
      subject,
      html,
    }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Resend error (${response.status}): ${body}`);
  }
}

export async function sendOtpEmail(to: string, code: string): Promise<void> {
  await sendEmail({
    to,
    subject: 'Verify your Classic Closet account',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h1 style="font-size:24px;margin-bottom:8px">Classic Closet</h1>
        <p style="color:#555;margin-bottom:24px">Enter this code to verify your account:</p>
        <div style="background:#f4f4f5;border-radius:12px;padding:24px;text-align:center;
                    font-size:36px;font-weight:bold;letter-spacing:12px;font-family:monospace">
          ${code}
        </div>
        <p style="color:#999;font-size:13px;margin-top:20px">
          Expires in 10 minutes. If you didn't request this, ignore this email.
        </p>
      </div>
    `,
  });
}
