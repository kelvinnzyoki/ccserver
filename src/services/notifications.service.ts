/**
 * Owner notification service — SMS alerts to the shop owner via
 * Africa's Talking whenever a payment is confirmed.
 *
 * Required Vercel environment variables:
 *   AT_API_KEY     — Africa's Talking API key (from africastalking.com dashboard)
 *   AT_USERNAME    — Africa's Talking username (your app name or 'sandbox')
 *   OWNER_PHONE    — Your phone number in any Kenyan format:
 *                    0789574634 / +254789574634 / 254789574634
 *
 * The SMS arrives even when you're completely offline — Safaricom/Airtel delivers
 * it as soon as your phone has any signal, exactly like a regular text.
 */

import { trySendSms } from './sms.service.js';

type BillingInfo = {
  name?: string | null;
  email?: string | null;
  phone?: string | null;
  address?: string | null;
  apartment?: string | null;
  city?: string | null;
  county?: string | null;
  country?: string | null;
  postalCode?: string | null;
  notes?: string | null;
};

// Normalise any Kenyan phone format to 254XXXXXXXXX for Africa's Talking.
// Airtel numbers are fine as long as they are valid Kenyan mobile numbers.
function normalizeOwnerPhone(raw: string): string {
  let v = raw.trim().replace(/[\s\-()+]/g, '');
  if (v.startsWith('07') || v.startsWith('01')) v = `254${v.slice(1)}`;
  if (v.startsWith('254') && /^254(7|1)\d{8}$/.test(v)) return v;
  throw new Error(`OWNER_PHONE must be a valid Kenyan mobile number, got: ${raw}`);
}

function clean(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value == null ? '' : String(value).trim();
}

function joinParts(parts: Array<unknown>): string {
  return parts.map(clean).filter(Boolean).join(', ');
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
  billing?: BillingInfo | null;
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

  const billing = params.billing ?? {};
  const billingName = clean(billing.name) || clean(params.customerName) || 'Customer';
  const billingPhone = clean(billing.phone);
  const billingEmail = clean(billing.email);
  const billingAddress = joinParts([
    billing.address,
    billing.apartment,
    billing.city,
    billing.county,
    billing.country,
    billing.postalCode,
  ]);
  const notes = clean(billing.notes);

  const lines = [
    `ClasicCloset: Order #${params.orderNumber} PAID ✓`,
    `KES ${Math.round(params.total).toLocaleString('en-KE')} via ${method}`,
    `Billing name: ${billingName}`,
    billingPhone ? `Billing phone: ${billingPhone}` : '',
    billingEmail ? `Billing email: ${billingEmail}` : '',
    billingAddress ? `Billing address: ${billingAddress}` : '',
    notes ? `Notes: ${notes}` : '',
    params.transactionRef ? `Ref: ${params.transactionRef}` : '',
  ].filter(Boolean);

  await trySendSms(phone, lines.join('\n'));
}
