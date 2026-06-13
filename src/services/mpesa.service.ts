import axios from 'axios';
import { env } from '../config/env.js';
import { ApiError } from '../utils/apiError.js';

const base = () =>
  env.MPESA_ENVIRONMENT === 'production'
    ? 'https://api.safaricom.co.ke'
    : 'https://sandbox.safaricom.co.ke';

const formatPhone = (phone: string) =>
  phone.replace(/^\+/, '').replace(/^0/, '254');

export class MpesaService {
  async token() {
    if (!env.MPESA_CONSUMER_KEY || !env.MPESA_CONSUMER_SECRET)
      throw new ApiError(500, 'M-Pesa is not configured');
    const auth = Buffer.from(
      `${env.MPESA_CONSUMER_KEY}:${env.MPESA_CONSUMER_SECRET}`
    ).toString('base64');
    const { data } = await axios.get(
      `${base()}/oauth/v1/generate?grant_type=client_credentials`,
      { headers: { Authorization: `Basic ${auth}` } }
    );
    return data.access_token as string;
  }

  password() {
    const timestamp = new Date()
      .toISOString()
      .replace(/[^0-9]/g, '')
      .slice(0, 14);
    const password = Buffer.from(
      `${env.MPESA_SHORTCODE}${env.MPESA_PASSKEY}${timestamp}`
    ).toString('base64');
    return { password, timestamp };
  }

  async stkPush(orderId: string, phone: string, amount: number) {
    if (!env.MPESA_SHORTCODE || !env.MPESA_PASSKEY || !env.MPESA_CALLBACK_URL)
      throw new ApiError(500, 'M-Pesa is not configured');
    const accessToken = await this.token();
    const { password, timestamp } = this.password();
    const msisdn = formatPhone(phone);
    const payload = {
      BusinessShortCode: env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.round(amount),
      PartyA: msisdn,
      PartyB: env.MPESA_SHORTCODE,
      PhoneNumber: msisdn,
      CallBackURL: env.MPESA_CALLBACK_URL,
      AccountReference: orderId,
      TransactionDesc: `Classic Closet order ${orderId}`,
    };
    const { data } = await axios.post(
      `${base()}/mpesa/stkpush/v1/processrequest`,
      payload,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    return data as { CheckoutRequestID: string; ResponseCode: string };
  }

  /**
   * Independently asks Safaricom whether a given STK push actually
   * succeeded, using OUR OWN API credentials (not anything the client sent).
   *
   * SECURITY: this is the defense-in-depth check for the M-Pesa callback.
   * Safaricom does not sign STK callbacks — anyone who knows a
   * CheckoutRequestID (which is returned to the paying user's own browser
   * by stkPush above) could POST a forged callback body claiming
   * ResultCode: 0. This method asks Safaricom directly, which cannot be
   * forged by a client since it requires our OAuth token + shortcode
   * credentials.
   *
   * ResultCode "0" (string, in this response) = transaction completed.
   * Any other value, or a thrown error (still processing / not found),
   * means the callback's claim of success must NOT be trusted yet.
   */
  async stkQuery(checkoutRequestId: string) {
    if (!env.MPESA_SHORTCODE || !env.MPESA_PASSKEY)
      throw new ApiError(500, 'M-Pesa is not configured');
    const accessToken = await this.token();
    const { password, timestamp } = this.password();
    const payload = {
      BusinessShortCode: env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      CheckoutRequestID: checkoutRequestId,
    };
    const { data } = await axios.post(
      `${base()}/mpesa/stkpushquery/v1/query`,
      payload,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    return data as {
      ResponseCode: string;
      ResponseDescription: string;
      MerchantRequestID: string;
      CheckoutRequestID: string;
      ResultCode: string;
      ResultDesc: string;
    };
  }
}

export const mpesa = new MpesaService();
