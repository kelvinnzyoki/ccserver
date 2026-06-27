type AnyOrder = any;

type PdfCommand = string;

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
  const candidates = [shipping.email, order.email, order.user?.email];

  return candidates.find(isRealEmail) || null;
}

function customerName(order: AnyOrder): string {
  const shipping = order.shippingAddress || {};
  const fullName = [shipping.firstName, shipping.lastName].filter(Boolean).join(' ').trim();
  return fullName || order.user?.name || 'Customer';
}

function deliveryAddress(order: AnyOrder): string {
  const shipping = order.shippingAddress || {};
  return [
    shipping.address1,
    shipping.address2,
    shipping.city,
    shipping.county,
    shipping.postalCode,
    shipping.country,
  ]
    .map((line) => String(line || '').trim())
    .filter(Boolean)
    .join(', ');
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

function kenyaDateTime(value?: string | Date | null): string {
  const date = value ? new Date(value) : new Date();
  return new Intl.DateTimeFormat('en-KE', {
    timeZone: 'Africa/Nairobi',
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
    timeZoneName: 'short',
  }).format(date);
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
    .replace(/[\r\n]+/g, ' ');
}

function text(textValue: unknown, x: number, y: number, size = 10, font = 'F1'): PdfCommand {
  return `BT /${font} ${size} Tf ${x} ${y} Td (${escapePdfText(textValue)}) Tj ET\n`;
}

function rect(x: number, y: number, w: number, h: number, stroke = '0.80 0.80 0.80', fill?: string): PdfCommand {
  if (fill) {
    return `q ${fill} rg ${stroke} RG ${x} ${y} ${w} ${h} re B Q\n`;
  }
  return `q ${stroke} RG ${x} ${y} ${w} ${h} re S Q\n`;
}

function line(x1: number, y1: number, x2: number, y2: number, stroke = '0.82 0.82 0.82'): PdfCommand {
  return `q ${stroke} RG ${x1} ${y1} m ${x2} ${y2} l S Q\n`;
}

function wrap(value: unknown, maxChars: number): string[] {
  const words = String(value ?? '').split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    const next = current ? `${current} ${word}` : word;
    if (next.length > maxChars && current) {
      lines.push(current);
      current = word;
    } else {
      current = next;
    }
  }

  if (current) lines.push(current);
  return lines.length ? lines : ['-'];
}

function tableRow(
  label: string,
  value: unknown,
  x: number,
  y: number,
  w: number,
  h = 26,
): PdfCommand {
  const labelW = 145;
  return [
    rect(x, y - h + 6, w, h, '0.86 0.86 0.86'),
    line(x + labelW, y + 6, x + labelW, y - h + 6),
    text(label, x + 10, y - 11, 9, 'F2'),
    text(safe(value), x + labelW + 10, y - 11, 9, 'F1'),
  ].join('');
}

function buildReceiptPdf(order: AnyOrder): Buffer {
  const commands: string[] = [];
  const items = Array.isArray(order.items) ? order.items : [];
  const generatedAt = kenyaDateTime();
  const markedDeliveredAt = kenyaDateTime(order.updatedAt || order.deliveredAt || order.fulfilledAt || order.createdAt);
  const orderNo = safe(order.orderNumber || order.id);
  const address = deliveryAddress(order) || addressLines(order).join(', ');

  // Page background and header
  commands.push(rect(0, 0, 595, 842, '1 1 1', '1 1 1'));
  commands.push(rect(36, 760, 523, 48, '0.08 0.08 0.08', '0.08 0.08 0.08'));
  commands.push(text('CLASICCLOSET', 54, 788, 18, 'F2'));
  commands.push(text('DELIVERY CONFIRMATION & PAYMENT RECEIPT', 54, 770, 10, 'F1'));
  commands.push(text(`Order #${orderNo}`, 390, 783, 12, 'F2'));
  commands.push(text('Status: DELIVERED', 390, 768, 10, 'F1'));

  // Summary panel
  commands.push(rect(36, 642, 523, 102, '0.78 0.78 0.78', '0.98 0.98 0.98'));
  commands.push(text('Receipt Summary', 54, 724, 13, 'F2'));
  commands.push(tableRow('Amount paid', money(order.total), 54, 704, 230));
  commands.push(tableRow('Payment method', paymentMethod(order), 54, 678, 230));
  commands.push(tableRow('Payment status', paymentStatus(order), 54, 652, 230));
  commands.push(tableRow('Payment reference', paymentReference(order), 302, 704, 239));
  commands.push(tableRow('Marked delivered', markedDeliveredAt, 302, 678, 239));
  commands.push(tableRow('Document generated', generatedAt, 302, 652, 239));

  // Customer and delivery details
  commands.push(text('Customer & Delivery Details', 36, 614, 13, 'F2'));
  commands.push(rect(36, 498, 523, 100, '0.82 0.82 0.82'));
  commands.push(tableRow('Customer name', customerName(order), 54, 578, 230));
  commands.push(tableRow('Phone', order.shippingAddress?.phone || order.user?.phone, 54, 552, 230));
  commands.push(tableRow('Email', customerEmail(order) || order.shippingAddress?.email, 54, 526, 230));

  commands.push(text('Delivery address', 310, 566, 9, 'F2'));
  wrap(address, 46).slice(0, 4).forEach((wrappedLine, index) => {
    commands.push(text(wrappedLine, 310, 548 - index * 14, 9, 'F1'));
  });

  // Item table
  commands.push(text('Items Delivered', 36, 470, 13, 'F2'));
  commands.push(rect(36, 444, 523, 22, '0.12 0.12 0.12', '0.12 0.12 0.12'));
  commands.push(text('Item', 50, 451, 9, 'F2'));
  commands.push(text('Size', 310, 451, 9, 'F2'));
  commands.push(text('Qty', 372, 451, 9, 'F2'));
  commands.push(text('Total', 455, 451, 9, 'F2'));

  let y = 422;
  if (!items.length) {
    commands.push(rect(36, y - 8, 523, 24, '0.88 0.88 0.88'));
    commands.push(text('No item details available on this receipt.', 50, y, 9, 'F1'));
    y -= 28;
  } else {
    for (const item of items.slice(0, 10)) {
      const name = item.productName || item.name || item.product?.name || 'Item';
      const size = item.size || '-';
      const quantity = item.quantity || 1;
      const total = money(item.total ?? Number(item.price || 0) * Number(quantity));
      const itemLines = wrap(name, 42).slice(0, 2);
      const rowHeight = itemLines.length > 1 ? 34 : 24;

      commands.push(rect(36, y - rowHeight + 8, 523, rowHeight, '0.88 0.88 0.88'));
      itemLines.forEach((itemLine, index) => commands.push(text(itemLine, 50, y - index * 12, 9, 'F1')));
      commands.push(text(size, 310, y, 9, 'F1'));
      commands.push(text(quantity, 378, y, 9, 'F1'));
      commands.push(text(total, 455, y, 9, 'F1'));
      y -= rowHeight;
      if (y < 170) break;
    }
  }

  // Footer declaration
  commands.push(rect(36, 78, 523, 70, '0.78 0.78 0.78', '0.98 0.98 0.98'));
  commands.push(text('Delivery Declaration', 54, 125, 11, 'F2'));
  commands.push(text('This document confirms that the paid order above was marked as delivered by ClasicCloset.', 54, 108, 9, 'F1'));
  commands.push(text('Keep this PDF as proof of payment, delivery address, and delivery confirmation.', 54, 94, 9, 'F1'));
  commands.push(text('Generated in Kenya time (Africa/Nairobi).', 54, 52, 8, 'F1'));

  const content = commands.join('');
  const objects: string[] = [
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n',
    '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n',
    '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >> endobj\n',
    '4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n',
    '5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj\n',
    `6 0 obj << /Length ${Buffer.byteLength(content)} >> stream\n${content}endstream\nendobj\n`,
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
  const markedDeliveredAt = kenyaDateTime(order.updatedAt || order.deliveredAt || order.fulfilledAt || order.createdAt);
  const generatedAt = kenyaDateTime();

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
          <tr><td style="padding:8px 0;color:#666">Marked delivered</td><td style="padding:8px 0;text-align:right">${escapeHtml(markedDeliveredAt)}</td></tr>
          <tr><td style="padding:8px 0;color:#666">PDF generated</td><td style="padding:8px 0;text-align:right">${escapeHtml(generatedAt)}</td></tr>
        </table>

        <h2 style="font-size:16px;margin:20px 0 8px">Delivery / billing details</h2>
        <p style="background:#f7f7f7;border-radius:12px;padding:14px;line-height:1.6;margin:0 0 18px">${address}</p>

        <h2 style="font-size:16px;margin:20px 0 8px">Items</h2>
        <table style="width:100%;border-collapse:collapse">
          ${itemRows || '<tr><td style="padding:10px;color:#666">Item details unavailable</td></tr>'}
        </table>

        <p style="margin-top:22px;color:#555">A professional PDF receipt/proof document is attached for your records.</p>
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
  const filename = `ClasicCloset-${safe(order.orderNumber || order.id, 'order')}-delivery-receipt.pdf`;

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
