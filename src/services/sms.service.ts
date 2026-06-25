/** SMS dispatch via Africa's Talking. */

import { env } from '../config/env.js';

interface AtRecipient {
  statusCode: number;
  status: string;
  number: string;
  cost?: string;
  messageId?: string;
}

interface AtResponse {
  SMSMessageData?: {
    Message?: string;
    Recipients?: AtRecipient[];
  };
}

function readEnv(name: string): string | undefined {
  return ((env as any)?.[name] || process.env[name] || '').trim() || undefined;
}

function normalizePhone(to: string): string {
  let phone = to.trim().replace(/[\s\-()]/g, '');
  if (phone.startsWith('07') || phone.startsWith('01')) phone = `254${phone.slice(1)}`;
  if (!phone.startsWith('+')) phone = `+${phone}`;
  if (!/^\+\d{7,15}$/.test(phone)) throw new Error(`Invalid SMS phone number: ${to}`);
  return phone;
}

export async function sendSms(to: string, message: string): Promise<void> {
  const apiKey = readEnv('AT_API_KEY');
  const username = readEnv('AT_USERNAME');
  const senderId = readEnv('AT_SENDER_ID');

  if (!apiKey) throw new Error('AT_API_KEY is not set');
  if (!username) throw new Error('AT_USERNAME is not set');

  const params = new URLSearchParams({
    username,
    to: normalizePhone(to),
    message,
  });

  // Africa's Talking sandbox commonly rejects custom sender IDs. Only send
  // `from` when it is configured and the username is not sandbox.
  if (senderId && username.toLowerCase() !== 'sandbox') params.set('from', senderId);

  const response = await fetch('https://api.africastalking.com/version1/messaging', {
    method: 'POST',
    headers: {
      apiKey,
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  const text = await response.text().catch(() => '');
  if (!response.ok) throw new Error(`SMS gateway error (${response.status}): ${text || response.statusText}`);

  let data: AtResponse = {};
  try { data = text ? JSON.parse(text) : {}; } catch { throw new Error(`SMS gateway returned invalid JSON: ${text}`); }

  const recipient = data.SMSMessageData?.Recipients?.[0];
  if (!recipient) throw new Error(`SMS gateway returned no recipient status: ${text}`);

  // 101 = Success. 102 = Queued/Sent in some AT environments.
  if (![101, 102].includes(Number(recipient.statusCode))) {
    throw new Error(`SMS rejected for ${recipient.number}: ${recipient.status || data.SMSMessageData?.Message || 'Unknown error'}`);
  }
}

export async function trySendSms(to: string, message: string): Promise<boolean> {
  try {
    await sendSms(to, message);
    return true;
  } catch (error) {
    console.error('[SMS] send failure:', error);
    throw error;
  }
}
