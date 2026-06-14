import crypto from 'crypto';
import axios from 'axios';
import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';

export class PaystackService {
  private headers() {
    if (!env.PAYSTACK_SECRET_KEY) throw new ApiError(500, 'Paystack is not configured');
    return { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` };
  }

  async initialize(orderId: string, email: string, amountKes: number) {
    // FIX: generate a fresh reference on every call instead of reusing orderId.
    //
    // Paystack treats each `reference` as a one-time-use token — once it has
    // been submitted (even if payment never completed), passing the same value
    // again returns 400 "Duplicate Transaction Reference".
    //
    // The order ID was previously used as the reference, which meant any
    // attempt to resume payment on a PENDING order would always fail on the
    // second call. Using a fresh UUID per attempt fixes this.
    //
    // The order association is preserved via metadata.orderId, which is what
    // the webhook and verify endpoints use to look up the correct payment
    // record — not the reference itself.
    const reference = crypto.randomUUID();

    const amount = Math.round(amountKes * 100); // Paystack expects kobo/cents

    const { data } = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email,
        amount,
        currency: env.CURRENCY,
        reference,
        callback_url: env.PAYSTACK_CALLBACK_URL,
        metadata: { orderId },
      },
      { headers: this.headers() }
    );

    return data.data as {
      authorization_url: string;
      reference: string;
      access_code: string;
    };
  }

  async verify(reference: string) {
    const { data } = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      { headers: this.headers() }
    );
    return data.data;
  }
}

export const paystack = new PaystackService();
