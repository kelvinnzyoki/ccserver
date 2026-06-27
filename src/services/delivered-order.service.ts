type AnyOrder = any;

function env(name: string): string {
  return process.env[name]?.trim() || '';
}

function isRealEmail(value?: string | null): value is string {
  return Boolean(value && value.includes('@') && !value.endsWith('@phone.classic-closet.local'));
}

function money(value: unknown): string {
  const amount = Number(value || 0);
  return `KES ${Math.round(amount).toLocaleString('en-KE')}`;
}

function safe(value: unknown, fallback = '-'): string {
  const text = String(value ?? '').trim();
  return text || fallback;
}

function customerEmail(order: AnyOrder): string | null {
  const shipping = order.shippingAddress || {};
  const candidates = [
    shipping.email,
    order.email,
    order.user?.email,
  ];

  return candidates.find(isRealEmail) || null;
}

function customerName(order: AnyOrder): string {
  const shipping = order.shippingAddress || {};
  const fullName = [shipping.firstName, shipping.lastName].filter(Boolean).join(' ').trim();
  return fullName || order.user?.name || 'Customer';
}

function addressLines(order: AnyOrder): string[] {
  const shipping = order.shippingAddress || {};
  return [
    [shipping.firstName, shipping.lastName].filter(Boolean).join(' ').trim(),
    shipping.phone,
    shipping.email,
    shipping.address1,
    shipping.address2,
    [shipping.city, shipping.county].filter(Boolean).join(', '),
    shipping.postalCode,
    shipping.country,
  ].filter((line) => String(line || '').trim()) as string[];
}

function paymentReference(order: AnyOrder): string {
  return (
    order.payment?.transactionRef ||
    order.payment?.reference ||
    order.payment?.providerRef ||
    order.payment?.id ||
    order.transactionRef ||
    '-'
  );
}

function paymentStatus(order: AnyOrder): string {
  return order.payment?.status || order.paymentStatus || 'PAID';
}

function paymentMethod(order: AnyOrder): string {
  return order.paymentMethod || order.payment?.provider || 'Payment';
}

function escapeHtml(input: unknown): string {
  return String(input ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapePdfText(input: unknown): string {
  return String(input ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/\r?\n/g, ' ');
}

function pdfLine(text: string, x: number, y: number, size = 11): string {
  return `BT /F1 ${size} Tf ${x} ${y} Td (${escapePdfText(text)}) Tj ET\n`;
}

function buildReceiptPdf(order: AnyOrder): Buffer {
  const lines: string[] = [];
  const items = Array.isArray(order.items) ? order.items : [];
  let y = 790;

  lines.push(pdfLine('ClasicCloset', 48, y, 22)); y -= 28;
  lines.push(pdfLine('Official Delivery Confirmation & Payment Receipt', 48, y, 14)); y -= 26;
  lines.push(pdfLine(`Order: #${safe(order.orderNumber || order.id)}`, 48, y)); y -= 18;
  lines.push(pdfLine(`Status: DELIVERED`, 48, y)); y -= 18;
  lines.push(pdfLine(`Amount Paid: ${money(order.total)}`, 48, y)); y -= 18;
  lines.push(pdfLine(`Payment Method: ${paymentMethod(order)}`, 48, y)); y -= 18;
  lines.push(pdfLine(`Payment Status: ${paymentStatus(order)}`, 48, y)); y -= 18;
  lines.push(pdfLine(`Payment Reference: ${paymentReference(order)}`, 48, y)); y -= 28;

  lines.push(pdfLine('Customer / Delivery Address', 48, y, 13)); y -= 20;
  for (const line of addressLines(order)) {
    lines.push(pdfLine(line, 64, y));
    y -= 16;
  }

  y -= 12;
  lines.push(pdfLine('Items Delivered', 48, y, 13)); y -= 20;

  if (items.length === 0) {
    lines.push(pdfLine('No item details available on this receipt.', 64, y));
    y -= 16;
  } else {
    for (const item of items.slice(0, 16)) {
      const name = item.productName || item.name || item.product?.name || 'Item';
      const size = item.size ? ` (${item.size})` : '';
      const quantity = item.quantity || 1;
      const total = money(item.total ?? Number(item.price || 0) * Number(quantity));
      lines.push(pdfLine(`${name}${size} x ${quantity} - ${total}`, 64, y));
      y -= 16;
      if (y < 90) break;
    }
  }

  y = Math.max(y - 20, 80);
  lines.push(pdfLine('This document confirms that the paid order above was marked delivered by ClasicCloset.', 48, y, 9));
  y -= 14;
  lines.push(pdfLine(`Generated: ${new Date().toLocaleString('en-KE')}`, 48, y, 9));

  const content = lines.join('');
  const objects: string[] = [
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n',
    '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n',
    '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n',
    '4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n',
    `5 0 obj << /Length ${Buffer.byteLength(content)} >> stream\n${content}endstream\nendobj\n`,
  ];

  let pdf = '%PDF-1.4\n';
  const offsets = [0];

  for (const object of objects) {
    offsets.push(Buffer.byteLength(pdf));
    pdf += object;
  }

  const xrefOffset = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let i = 1; i < offsets.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;

  return Buffer.from(pdf);
}

function buildEmailHtml(order: AnyOrder): string {
  const address = addressLines(order).map(escapeHtml).join('<br />');
  const items = Array.isArray(order.items) ? order.items : [];

  const itemRows = items.map((item: any) => {
    const name = item.productName || item.name || item.product?.name || 'Item';
    const size = item.size ? ` (${item.size})` : '';
    const quantity = item.quantity || 1;
    const total = money(item.total ?? Number(item.price || 0) * Number(quantity));

    return `
      <tr>
        <td style="padding:10px;border-bottom:1px solid #eee">${escapeHtml(name)}${escapeHtml(size)} × ${quantity}</td>
        <td style="padding:10px;border-bottom:1px solid #eee;text-align:right">${escapeHtml(total)}</td>
      </tr>
    `;
  }).join('');

  return `
    <div style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;padding:28px;color:#111">
      <div style="border:1px solid #eee;border-radius:18px;padding:24px">
        <h1 style="margin:0 0 8px;font-size:24px">Your ClasicCloset order has been delivered</h1>
        <p style="margin:0 0 20px;color:#555">Hello ${escapeHtml(customerName(order))}, your paid order has been marked as delivered.</p>

        <table style="width:100%;border-collapse:collapse;margin-bottom:18px">
          <tr><td style="padding:8px 0;color:#666">Order</td><td style="padding:8px 0;text-align:right;font-weight:bold">#${escapeHtml(order.orderNumber || order.id)}</td></tr>
          <tr><td style="padding:8px 0;color:#666">Amount paid</td><td style="padding:8px 0;text-align:right;font-weight:bold">${escapeHtml(money(order.total))}</td></tr>
          <tr><td style="padding:8px 0;color:#666">Payment method</td><td style="padding:8px 0;text-align:right">${escapeHtml(paymentMethod(order))}</td></tr>
          <tr><td style="padding:8px 0;color:#666">Payment reference</td><td style="padding:8px 0;text-align:right">${escapeHtml(paymentReference(order))}</td></tr>
        </table>

        <h2 style="font-size:16px;margin:20px 0 8px">Delivery / billing details</h2>
        <p style="background:#f7f7f7;border-radius:12px;padding:14px;line-height:1.6;margin:0 0 18px">${address}</p>

        <h2 style="font-size:16px;margin:20px 0 8px">Items</h2>
        <table style="width:100%;border-collapse:collapse">
          ${itemRows || '<tr><td style="padding:10px;color:#666">Item details unavailable</td></tr>'}
        </table>

        <p style="margin-top:22px;color:#555">A PDF receipt/proof document is attached for your records.</p>
        <p style="margin-top:22px;font-size:12px;color:#777">Thank you for shopping with ClasicCloset.</p>
      </div>
    </div>
  `;
}

export async function sendDeliveredOrderConfirmation(order: AnyOrder): Promise<void> {
  const to = customerEmail(order);
  if (!to) {
    throw new Error('Customer has no real email address for delivered-order confirmation.');
  }

  const apiKey = env('RESEND_API_KEY');
  if (!apiKey) {
    throw new Error('RESEND_API_KEY is not configured.');
  }

  const from =
    env('EMAIL_FROM') ||
    env('RESEND_FROM') ||
    env('MAIL_FROM') ||
    'ClasicCloset <onboarding@resend.dev>';

  const pdf = buildReceiptPdf(order);
  const filename = `ClasicCloset-${safe(order.orderNumber || order.id, 'order')}-receipt.pdf`;

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to,
      subject: `Delivery confirmed - Order #${order.orderNumber || order.id}`,
      html: buildEmailHtml(order),
      attachments: [
        {
          filename,
          content: pdf.toString('base64'),
        },
      ],
    }),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Delivered-order email failed: ${response.status} ${text}`);
  }
}
