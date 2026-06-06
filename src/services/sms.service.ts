/**
 * SMS dispatch via Africa's Talking — the standard Kenyan SMS gateway.
 *
 * Required env vars:
 *   AT_API_KEY     — from africastalking.com dashboard
 *   AT_USERNAME    — usually your app name or 'sandbox' for testing
 *   AT_SENDER_ID   — optional; registered alphanumeric sender ID (e.g. "ClassicCloset")
 *
 * Phone numbers must be E.164 (e.g. 254712345678).
 * This service prepends '+' automatically if missing.
 */

import { env } from '../config/env.js';

interface AtRecipient {
  statusCode: number;
  status: string;
  number: string;
  cost: string;
  messageId: string;
}

interface AtResponse {
  SMSMessageData: {
    Message: string;
    Recipients: AtRecipient[];
  };
}

export async function sendSms(to: string, message: string): Promise<void> {
  const phone = to.startsWith('+') ? to : `+${to}`;

  const params = new URLSearchParams({
    username: env.AT_USERNAME,
    to: phone,
    message,
  });

  if (env.AT_SENDER_ID) {
    params.set('from', env.AT_SENDER_ID);
  }

  let response: Response;
  try {
    response = await fetch('https://api.africastalking.com/version1/messaging', {
      method: 'POST',
      headers: {
        apiKey: env.AT_API_KEY,
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });
  } catch (networkError) {
    throw new Error(`SMS network error: ${(networkError as Error).message}`);
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`SMS gateway error (${response.status}): ${body}`);
  }

  const data: AtResponse = await response.json();
  const recipient = data.SMSMessageData?.Recipients?.[0];

  // statusCode 101 = Success, 102 = Sent (AT sandbox sometimes returns 102)
  if (recipient && recipient.statusCode !== 101 && recipient.statusCode !== 102) {
    throw new Error(`SMS rejected by carrier: ${recipient.status}`);
  }
}

/**
 * Non-fatal wrapper — logs SMS errors but does not propagate them.
 * Use for notifications where a failed SMS should not fail the HTTP request.
 */
export async function trySendSms(to: string, message: string): Promise<void> {
  try {
    await sendSms(to, message);
  } catch (error) {
    console.error('[SMS] Non-fatal send failure:', error);
  }
}
