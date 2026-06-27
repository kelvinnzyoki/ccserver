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

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function clean(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value == null ? '' : String(value).trim();
}

function joinParts(parts: unknown[]): string {
  return parts.map(clean).filter(Boolean).join(', ');
}

export async function sendOrderPaidEmail(params: {
  to: string;
  orderNumber: string;
  customerName?: string | null;
  total: number;
  paymentMethod: string;
  transactionRef?: string | null;
  billing?: {
    firstName?: string | null;
    lastName?: string | null;
    phone?: string | null;
    email?: string | null;
    address1?: string | null;
    address2?: string | null;
    city?: string | null;
    county?: string | null;
    postalCode?: string | null;
    country?: string | null;
  } | null;
  items?: Array<{
    name?: string | null;
    quantity?: number | null;
    price?: number | string | null;
    size?: string | null;
  }>;
}): Promise<void> {
  const billing = params.billing ?? {};
  const customerName = clean(params.customerName)
    || joinParts([billing.firstName, billing.lastName]).replace(', ', ' ')
    || 'Customer';

  const address = joinParts([
    billing.address1,
    billing.address2,
    billing.city,
    billing.county,
    billing.postalCode,
    billing.country,
  ]);

  const paymentMethod = params.paymentMethod === 'PAYSTACK'
    ? 'Card / Paystack'
    : params.paymentMethod === 'MPESA'
      ? 'M-Pesa'
      : params.paymentMethod;

  const itemsHtml = params.items?.length
    ? params.items.map((item) => {
        const qty = Number(item.quantity ?? 1);
        const price = Number(item.price ?? 0);
        const lineTotal = qty * price;
        const size = clean(item.size);
        return `
          <tr>
            <td style="padding:10px 0;border-bottom:1px solid #eee">
              ${escapeHtml(item.name || 'Product')}${size ? ` <span style="color:#777">(${escapeHtml(size)})</span>` : ''}
            </td>
            <td style="padding:10px 0;border-bottom:1px solid #eee;text-align:center">${qty}</td>
            <td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right">KES ${Math.round(lineTotal).toLocaleString('en-KE')}</td>
          </tr>`;
      }).join('')
    : `<tr><td colspan="3" style="padding:10px 0;color:#777">Your paid items are being processed.</td></tr>`;

  await sendEmail({
    to: params.to,
    subject: `Payment received - Order ${params.orderNumber}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;padding:28px;color:#111827;line-height:1.5">
        <h1 style="margin:0 0 8px;font-size:24px">ClasicCloset</h1>
        <h2 style="margin:0 0 16px;font-size:20px">Payment received ✓</h2>

        <p>Hello <strong>${escapeHtml(customerName)}</strong>,</p>
        <p>Thank you for shopping with ClasicCloset. We have received your payment and your order is now being processed.</p>

        <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:14px;padding:16px;margin:20px 0">
          <p style="margin:0 0 6px"><strong>Order:</strong> ${escapeHtml(params.orderNumber)}</p>
          <p style="margin:0 0 6px"><strong>Amount paid:</strong> KES ${Math.round(params.total).toLocaleString('en-KE')}</p>
          <p style="margin:0 0 6px"><strong>Payment method:</strong> ${escapeHtml(paymentMethod)}</p>
          ${params.transactionRef ? `<p style="margin:0"><strong>Reference:</strong> ${escapeHtml(params.transactionRef)}</p>` : ''}
        </div>

        <h3 style="font-size:16px;margin:22px 0 8px">Order items</h3>
        <table style="width:100%;border-collapse:collapse;font-size:14px">
          <thead>
            <tr>
              <th style="text-align:left;padding-bottom:8px;border-bottom:1px solid #ddd">Item</th>
              <th style="text-align:center;padding-bottom:8px;border-bottom:1px solid #ddd">Qty</th>
              <th style="text-align:right;padding-bottom:8px;border-bottom:1px solid #ddd">Total</th>
            </tr>
          </thead>
          <tbody>${itemsHtml}</tbody>
        </table>

        <h3 style="font-size:16px;margin:22px 0 8px">Billing / delivery details</h3>
        <p style="margin:0 0 4px"><strong>Name:</strong> ${escapeHtml(joinParts([billing.firstName, billing.lastName]).replace(', ', ' ') || customerName)}</p>
        ${billing.phone ? `<p style="margin:0 0 4px"><strong>Phone:</strong> ${escapeHtml(billing.phone)}</p>` : ''}
        ${billing.email ? `<p style="margin:0 0 4px"><strong>Email:</strong> ${escapeHtml(billing.email)}</p>` : ''}
        ${address ? `<p style="margin:0 0 4px"><strong>Address:</strong> ${escapeHtml(address)}</p>` : ''}

        <p style="margin-top:22px">We will notify you once your order is dispatched.</p>
        <p style="color:#6b7280;font-size:13px;margin-top:24px">If you did not make this order, please contact ClasicCloset support immediately.</p>
      </div>
    `,
  });
}

