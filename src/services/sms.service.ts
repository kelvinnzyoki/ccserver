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
  const senderIdApproved =
    readEnv('AT_SENDER_ID_APPROVED') === 'true' ||
    readEnv('AT_USE_SENDER_ID') === 'true';

  if (!apiKey) throw new Error('AT_API_KEY is not set');
  if (!username) throw new Error('AT_USERNAME is not set');

  const params = new URLSearchParams({
    username,
    to: normalizePhone(to),
    message,
  });

  // IMPORTANT:
  // Do not send `from` just because AT_SENDER_ID exists.
  // Africa's Talking production rejects unapproved sender IDs with:
  //   InvalidSenderId / Recipients:[]
  //
  // Keep AT_SENDER_ID optional. By default this service omits `from`, allowing
  // Africa's Talking to use the account/default sender. Only enable a custom
  // sender after Africa's Talking has approved it by setting either:
  //   AT_SENDER_ID_APPROVED=true
  // or:
  //   AT_USE_SENDER_ID=true
  if (senderId && senderIdApproved && username.toLowerCase() !== 'sandbox') {
    params.set('from', senderId);
  }

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
  if (!recipient) {
    const gatewayMessage = data.SMSMessageData?.Message || text || 'No recipient status returned';
    throw new Error(`SMS gateway returned no recipient status: ${gatewayMessage}`);
  }

  const statusCode = Number(recipient.statusCode);
  const status = String(recipient.status || '').trim().toLowerCase();
  const gatewayMessage = String(data.SMSMessageData?.Message || '').trim().toLowerCase();

  // Africa's Talking can return a delivered/accepted recipient with status
  // "Success" even when statusCode is missing, empty, or not numeric.
  // Treat both the documented numeric success codes and textual Success as OK.
  const accepted =
    [101, 102].includes(statusCode) ||
    status === 'success' ||
    gatewayMessage === 'sent to 1/1 total recipients';

  if (!accepted) {
    throw new Error(
      `SMS rejected for ${recipient.number}: ${recipient.status || data.SMSMessageData?.Message || 'Unknown error'}`
    );
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
