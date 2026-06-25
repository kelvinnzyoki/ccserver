/**
 * Email delivery via Resend.
 * Required env vars: RESEND_API_KEY, RESEND_FROM_EMAIL
 */

import { env } from '../config/env.js';

interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
}

function readEnv(name: string): string | undefined {
  return ((env as any)?.[name] || process.env[name] || '').trim() || undefined;
}

export async function sendEmail({ to, subject, html }: SendEmailOptions): Promise<void> {
  const apiKey = readEnv('RESEND_API_KEY');
  const from = readEnv('RESEND_FROM_EMAIL');

  if (!apiKey) throw new Error('RESEND_API_KEY is not set');
  if (!from) throw new Error('RESEND_FROM_EMAIL is not set');

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from, to, subject, html }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Resend error (${response.status}): ${body || response.statusText}`);
  }
}

export async function sendOtpEmail(to: string, code: string): Promise<void> {
  await sendEmail({
    to,
    subject: 'Verify your ClasicCloset account',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h1 style="font-size:24px;margin-bottom:8px">ClasicCloset</h1>
        <p style="color:#555;margin-bottom:24px">Enter this code to verify your account:</p>
        <div style="background:#f4f4f5;border-radius:12px;padding:24px;text-align:center;font-size:36px;font-weight:bold;letter-spacing:12px;font-family:monospace">
          ${code}
        </div>
        <p style="color:#999;font-size:13px;margin-top:20px">
          Expires in 10 minutes. If you did not request this, ignore this email.
        </p>
      </div>
    `,
  });
}
