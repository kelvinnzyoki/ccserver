/**
 * Owner notification service — SMS alerts to the shop owner via
 * Africa's Talking whenever a payment is confirmed.
 *
 * Required Vercel environment variables:
 *   AT_API_KEY     — Africa's Talking API key (from africastalking.com dashboard)
 *   AT_USERNAME    — Africa's Talking username (your app name or 'sandbox')
 *   OWNER_PHONE    — Your phone number in any Kenyan format:
 *                    0141756253 / +254141756253 / 254141756253
 *
 * The SMS arrives even when you're completely offline — Safaricom delivers
 * it as soon as your phone has any signal, exactly like a regular text.
 */

import { sendSms } from './sms.service.js';

// Normalise any Kenyan phone format to E.164.
// Works for Safaricom/Airtel/Telkom Kenyan mobile numbers when supplied as:
//   07XXXXXXXX / 01XXXXXXXX / 254XXXXXXXXX / +254XXXXXXXXX
function normalizeOwnerPhone(raw: string): string {
  let v = raw.trim().replace(/[\s\-()]/g, '');
  if (v.startsWith('07') || v.startsWith('01')) v = `254${v.slice(1)}`;
  if (!v.startsWith('+')) v = `+${v}`;
  if (!/^\+254(7|1)\d{8}$/.test(v)) {
    throw new Error(`OWNER_PHONE must be a valid Kenyan mobile number, got: ${raw}`);
  }
  return v;
}

/**
 * Sends an SMS to the shop owner when a payment is confirmed.
 * Non-fatal — a failed SMS never blocks the payment flow.
 */
export async function notifyOwnerPaymentReceived(params: {
  orderNumber: string;
  customerName: string;
  total: number;
  method: string;
  transactionRef?: string | null;
}): Promise<void> {
  const ownerPhone = (process.env.OWNER_PHONE || '').trim();

  if (!ownerPhone) {
    console.warn('[notify] OWNER_PHONE not set — skipping owner SMS');
    return;
  }

  let phone: string;
  try {
    phone = normalizeOwnerPhone(ownerPhone);
  } catch (err) {
    console.error('[notify] invalid OWNER_PHONE:', err);
    return;
  }

  const method = params.method === 'MPESA' ? 'M-Pesa'
    : params.method === 'PAYSTACK' ? 'Card'
    : params.method;

  const ref = params.transactionRef ? ` Ref: ${params.transactionRef}` : '';
  const message =
    `ClasicCloset: Order #${params.orderNumber} PAID ✓\n` +
    `KES ${Math.round(params.total).toLocaleString('en-KE')} via ${method}\n` +
    `Customer: ${params.customerName}` +
    ref;

  try {
    await sendSms(phone, message);
    console.info(`[notify] owner SMS sent to ${phone} for order ${params.orderNumber}`);
  } catch (err) {
    // Owner notifications must never break a confirmed payment.
    console.error('[notify] owner SMS failed:', err);
  }
}
