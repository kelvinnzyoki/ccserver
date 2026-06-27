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

function colorText(
  textValue: unknown,
  x: number,
  y: number,
  size = 10,
  font = 'F1',
  color = '0 0 0',
): PdfCommand {
  return `q ${color} rg BT /${font} ${size} Tf ${x} ${y} Td (${escapePdfText(textValue)}) Tj ET Q\n`;
}

function strokeLine(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  stroke = '0.82 0.82 0.82',
  width = 1,
): PdfCommand {
  return `q ${stroke} RG ${width} w ${x1} ${y1} m ${x2} ${y2} l S Q\n`;
}

function goldLogo(x: number, y: number): PdfCommand {
  const gold = '0.83 0.66 0.22';
  return [
    strokeLine(x + 18, y + 22, x + 18, y + 34, gold, 1.6),
    `q ${gold} RG 1.6 w ${x + 18} ${y + 34} m ${x + 18} ${y + 42} ${x + 31} ${y + 42} ${x + 31} ${y + 34} c S Q\n`,
    strokeLine(x + 18, y + 22, x + 2, y + 5, gold, 1.6),
    strokeLine(x + 18, y + 22, x + 34, y + 5, gold, 1.6),
    strokeLine(x, y + 5, x + 36, y + 5, gold, 1.6),
    colorText('CLASIC', x + 48, y + 24, 12, 'F2', gold),
    colorText('CLOSET', x + 48, y + 9, 12, 'F2', gold),
    strokeLine(x + 48, y + 18, x + 154, y + 18, gold, 0.45),
  ].join('');
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
  const markedDeliveredAt = kenyaDateTime(order.updatedAt || order.deliveredAt || order.fulfilledAt || order.createdAt);
  const orderNo = safe(order.orderNumber || order.id);
  const address = deliveryAddress(order) || addressLines(order).join(', ');
  const gold = '0.83 0.69 0.22';
  const black = '0.08 0.08 0.08';
  const muted = '0.35 0.35 0.35';

  // Page background and premium header
  commands.push(rect(0, 0, 595, 842, '1 1 1', '1 1 1'));
  commands.push(rect(36, 750, 523, 62, black, black));
  commands.push(goldLogo(54, 763));
  commands.push(colorText('DELIVERY CONFIRMATION RECEIPT', 260, 787, 15, 'F2', '1 1 1'));
  commands.push(colorText(`Order #${orderNo}`, 260, 768, 10, 'F1', '1 1 1'));
  commands.push(colorText('Status: DELIVERED', 442, 768, 10, 'F2', gold));
  commands.push(line(36, 738, 559, 738, gold));

  // Summary panel - no generated date section
  commands.push(rect(36, 602, 523, 122, '0.78 0.78 0.78', '0.985 0.985 0.985'));
  commands.push(colorText('Receipt Summary', 54, 704, 13, 'F2', black));
  commands.push(tableRow('Amount paid', money(order.total), 54, 684, 230));
  commands.push(tableRow('Payment method', paymentMethod(order), 54, 658, 230));
  commands.push(tableRow('Payment status', paymentStatus(order), 54, 632, 230));
  commands.push(tableRow('Payment reference', paymentReference(order), 302, 684, 239));
  commands.push(tableRow('Marked delivered', markedDeliveredAt, 302, 658, 239));

  // Customer and delivery details
  commands.push(colorText('Customer & Delivery Details', 36, 606, 13, 'F2', black));
  commands.push(rect(36, 490, 523, 100, '0.82 0.82 0.82'));
  commands.push(tableRow('Customer name', customerName(order), 54, 570, 230));
  commands.push(tableRow('Phone', order.shippingAddress?.phone || order.user?.phone, 54, 544, 230));
  commands.push(tableRow('Email', customerEmail(order) || order.shippingAddress?.email, 54, 518, 230));

  commands.push(colorText('Delivery address', 310, 558, 9, 'F2', black));
  wrap(address, 46).slice(0, 4).forEach((wrappedLine, index) => {
    commands.push(colorText(wrappedLine, 310, 540 - index * 14, 9, 'F1', black));
  });

  // Item table with dynamic row heights and fixed column sections
  commands.push(colorText('Items Delivered', 36, 462, 13, 'F2', black));
  commands.push(rect(36, 436, 523, 22, black, black));
  commands.push(colorText('Item', 50, 443, 9, 'F2', '1 1 1'));
  commands.push(colorText('Size', 310, 443, 9, 'F2', '1 1 1'));
  commands.push(colorText('Qty', 372, 443, 9, 'F2', '1 1 1'));
  commands.push(colorText('Total', 455, 443, 9, 'F2', '1 1 1'));

  let y = 414;
  if (!items.length) {
    commands.push(rect(36, y - 8, 523, 24, '0.88 0.88 0.88'));
    commands.push(colorText('No item details available on this receipt.', 50, y, 9, 'F1', muted));
    y -= 28;
  } else {
    for (const item of items.slice(0, 9)) {
      const name = item.productName || item.name || item.product?.name || 'Item';
      const size = item.size || '-';
      const quantity = item.quantity || 1;
      const total = money(item.total ?? Number(item.price || 0) * Number(quantity));
      const itemLines = wrap(name, 40).slice(0, 3);
      const rowHeight = Math.max(30, itemLines.length * 13 + 14);
      const rowBottom = y - rowHeight + 8;
      const centerY = rowBottom + rowHeight / 2 - 3;

      commands.push(rect(36, rowBottom, 523, rowHeight, '0.88 0.88 0.88'));
      commands.push(line(300, rowBottom, 300, rowBottom + rowHeight, '0.88 0.88 0.88'));
      commands.push(line(360, rowBottom, 360, rowBottom + rowHeight, '0.88 0.88 0.88'));
      commands.push(line(430, rowBottom, 430, rowBottom + rowHeight, '0.88 0.88 0.88'));

      itemLines.forEach((itemLine, index) => commands.push(colorText(itemLine, 50, y - index * 13, 9, 'F1', black)));
      commands.push(colorText(size, 310, centerY, 9, 'F1', black));
      commands.push(colorText(quantity, 378, centerY, 9, 'F1', black));
      commands.push(colorText(total, 455, centerY, 9, 'F1', black));
      y -= rowHeight;
      if (y < 188) break;
    }
  }

  // Customer support section
  commands.push(rect(36, 150, 523, 44, '0.78 0.78 0.78', '0.985 0.985 0.985'));
  commands.push(colorText('Need help with this order?', 54, 178, 10, 'F2', black));
  commands.push(colorText('For delivery issues, payment questions, returns, or inquiries, contact ClasicCloset support.', 54, 164, 8.5, 'F1', muted));
  commands.push(colorText('Email: orders@cctamcc.site   |   Support: support@cctamcc.site', 54, 152, 8.5, 'F2', black));

  // Footer declaration
  commands.push(rect(36, 72, 523, 62, '0.78 0.78 0.78', '0.985 0.985 0.985'));
  commands.push(colorText('Delivery Declaration', 54, 113, 11, 'F2', black));
  commands.push(colorText('This receipt confirms that the paid order above was successfully marked as delivered by ClasicCloset.', 54, 97, 8.5, 'F1', black));
  commands.push(colorText('Keep this PDF as proof of payment, delivery details, and delivery confirmation.', 54, 84, 8.5, 'F1', black));
  commands.push(line(36, 58, 559, 58, gold));
  commands.push(colorText('Thank you for shopping with ClasicCloset. Premium Fashion • Kenya', 152, 42, 8.5, 'F2', black));

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
        </table>

        <h2 style="font-size:16px;margin:20px 0 8px">Delivery / billing details</h2>
        <p style="background:#f7f7f7;border-radius:12px;padding:14px;line-height:1.6;margin:0 0 18px">${address}</p>

        <h2 style="font-size:16px;margin:20px 0 8px">Items</h2>
        <table style="width:100%;border-collapse:collapse">
          ${itemRows || '<tr><td style="padding:10px;color:#666">Item details unavailable</td></tr>'}
        </table>

        <div style="margin-top:22px;background:#fff8e1;border:1px solid #e7c75f;border-radius:12px;padding:14px">
          <strong>Customer Support</strong><br />
          For order issues, delivery questions, or inquiries, email
          <strong>orders@cctamcc.site</strong> or <strong>support@cctamcc.site</strong>.
        </div>

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
