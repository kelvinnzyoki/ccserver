type AnyOrder = any;

type PdfCommand = string;

const GOLD = '0.83 0.69 0.22';
const GOLD_DARK = '0.55 0.42 0.10';
const DARK = '0.07 0.07 0.07';
const MUTED = '0.35 0.35 0.35';
const LIGHT_BORDER = '0.86 0.86 0.86';
const LIGHT_FILL = '0.99 0.99 0.99';
const LIGHT_GOLD_FILL = '0.99 0.96 0.86';

function env(name: string): string {
  return process.env[name]?.trim() || '';
}

function supportEmail(): string {
  return env('SUPPORT_EMAIL') || env('ORDERS_EMAIL') || 'support@cctamcc.site';
}

function supportPhone(): string {
  return env('SUPPORT_PHONE') || env('BUSINESS_PHONE') || '+254 748 500 065';
}

function supportWebsite(): string {
  return env('PUBLIC_STORE_URL') || env('PUBLIC_SITE_URL') || env('NEXT_PUBLIC_SITE_URL') || 'https://cctamcc.site';
}

function isRealEmail(value?: string | null): value is string {
  return Boolean(value && value.includes('@') && !value.endsWith('@phone.classic-closet.local'));
}

function money(value: unknown): string {
  const amount = Number(value || 0);
  return `KES ${Math.round(amount).toLocaleString('en-KE')}`;
}

function safe(value: unknown, fallback = '-'): string {
  const textValue = String(value ?? '').trim();
  return textValue || fallback;
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

function pdfKenyaDateTime(value?: string | Date | null): string {
  const date = value ? new Date(value) : new Date();
  return new Intl.DateTimeFormat('en-KE', {
    timeZone: 'Africa/Nairobi',
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
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

function text(textValue: unknown, x: number, y: number, size = 10, font = 'F1', fill = DARK): PdfCommand {
  return `q ${fill} rg BT /${font} ${size} Tf ${x} ${y} Td (${escapePdfText(textValue)}) Tj ET Q\n`;
}

function rect(x: number, y: number, w: number, h: number, stroke = LIGHT_BORDER, fill?: string): PdfCommand {
  if (fill) {
    return `q ${fill} rg ${stroke} RG ${x} ${y} ${w} ${h} re B Q\n`;
  }
  return `q ${stroke} RG ${x} ${y} ${w} ${h} re S Q\n`;
}

function line(x1: number, y1: number, x2: number, y2: number, stroke = LIGHT_BORDER, width = 1): PdfCommand {
  return `q ${stroke} RG ${width} w ${x1} ${y1} m ${x2} ${y2} l S Q\n`;
}

function pdfCircle(cx: number, cy: number, r: number, stroke = GOLD, fill = '1 1 1', width = 1): PdfCommand {
  const c = r * 0.5522847498;
  return `q ${width} w ${fill} rg ${stroke} RG ${cx + r} ${cy} m ${cx + r} ${cy + c} ${cx + c} ${cy + r} ${cx} ${cy + r} c ${cx - c} ${cy + r} ${cx - r} ${cy + c} ${cx - r} ${cy} c ${cx - r} ${cy - c} ${cx - c} ${cy - r} ${cx} ${cy - r} c ${cx + c} ${cy - r} ${cx + r} ${cy - c} ${cx + r} ${cy} c B Q\n`;
}

function drawClasicClosetLogo(x: number, y: number): PdfCommand {
  // Static PDF rendering of the uploaded ClasicCloset SVG/React logo in premium gold.
  // The decorative line from the React wordmark is intentionally removed for a cleaner receipt header.
  return [
    line(x + 22, y + 21, x + 22, y + 31, GOLD, 1.8),
    `q 1.8 w ${GOLD} RG ${x + 22} ${y + 31} m ${x + 22} ${y + 37} ${x + 27} ${y + 39} ${x + 31} ${y + 35} c S Q\n`,
    line(x + 22, y + 21, x + 6, y + 5, GOLD, 1.8),
    line(x + 22, y + 21, x + 38, y + 5, GOLD, 1.8),
    line(x + 4, y + 5, x + 40, y + 5, GOLD, 1.8),
    text('CLASIC', x + 54, y + 25, 11, 'F2', GOLD),
    text('CLOSET', x + 54, y + 10, 11, 'F2', GOLD),
  ].join('');
}

function splitLongWord(word: string, maxChars: number): string[] {
  if (word.length <= maxChars) return [word];
  const parts: string[] = [];
  for (let i = 0; i < word.length; i += maxChars) {
    parts.push(word.slice(i, i + maxChars));
  }
  return parts;
}

function wrap(value: unknown, maxChars: number): string[] {
  const words = String(value ?? '').split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';

  for (const rawWord of words) {
    const pieces = splitLongWord(rawWord, Math.max(6, maxChars));
    for (const word of pieces) {
      const next = current ? `${current} ${word}` : word;
      if (next.length > maxChars && current) {
        lines.push(current);
        current = word;
      } else {
        current = next;
      }
    }
  }

  if (current) lines.push(current);
  return lines.length ? lines : ['-'];
}

function ellipsize(value: unknown, maxChars: number): string {
  const v = safe(value);
  if (v.length <= maxChars) return v;
  return `${v.slice(0, Math.max(0, maxChars - 1))}…`;
}

function fieldBox(label: string, value: unknown, x: number, y: number, w: number, h = 34, maxLines = 2): PdfCommand {
  const labelY = y + h - 13;
  const valueLines = wrap(safe(value), Math.max(12, Math.floor((w - 18) / 4.8))).slice(0, maxLines);
  return [
    rect(x, y, w, h, '0.86 0.86 0.86', '1 1 1'),
    text(label, x + 8, labelY, 7.5, 'F2', MUTED),
    ...valueLines.map((lineText, index) => text(lineText, x + 8, y + h - 26 - index * 10, 8, 'F1', DARK)),
  ].join('');
}

function drawSectionTitle(title: string, x: number, y: number): PdfCommand {
  return [
    text(title, x, y, 12.5, 'F2', DARK),
    line(x, y - 6, x + 120, y - 6, GOLD, 0.8),
  ].join('');
}

function buildReceiptPdf(order: AnyOrder): Buffer {
  const commands: string[] = [];
  const items = Array.isArray(order.items) ? order.items : [];
  const markedDeliveredAt = pdfKenyaDateTime(order.updatedAt || order.deliveredAt || order.fulfilledAt || order.createdAt);
  const orderNo = safe(order.orderNumber || order.id);
  const address = deliveryAddress(order) || addressLines(order).join(', ');
  const pageLeft = 36;
  const pageRight = 559;
  const tableWidth = pageRight - pageLeft;
  let y = 790;

  // Page background.
  commands.push(rect(0, 0, 595, 842, '1 1 1', '1 1 1'));

  // Compact premium receipt header.
  commands.push(rect(pageLeft, y - 58, tableWidth, 58, DARK, DARK));
  commands.push(drawClasicClosetLogo(pageLeft + 18, y - 45));
  commands.push(text('DELIVERY CONFIRMATION RECEIPT', pageLeft + 235, y - 20, 15, 'F2', '1 1 1'));
  commands.push(text(`Order #${orderNo}`, pageLeft + 235, y - 38, 8.5, 'F1', '0.92 0.92 0.92'));
  commands.push(text('Status: DELIVERED', pageRight - 122, y - 38, 9, 'F2', GOLD));
  y -= 74;

  // Summary panel.
  commands.push(drawSectionTitle('Receipt Summary', pageLeft, y));
  y -= 18;
  commands.push(rect(pageLeft, y - 78, tableWidth, 78, '0.82 0.82 0.82', LIGHT_FILL));
  const halfGap = 12;
  const colW = (tableWidth - halfGap) / 2;
  const thirdW = (colW - 10) / 2;
  commands.push(fieldBox('Amount paid', money(order.total), pageLeft + 12, y - 44, thirdW, 34));
  commands.push(fieldBox('Payment method', paymentMethod(order), pageLeft + 12 + thirdW + 10, y - 44, thirdW, 34));
  commands.push(fieldBox('Payment status', paymentStatus(order), pageLeft + 12, y - 76, thirdW, 28));
  commands.push(fieldBox('Delivered on', markedDeliveredAt, pageLeft + 12 + thirdW + 10, y - 76, thirdW, 28));
  commands.push(fieldBox('Payment reference', ellipsize(paymentReference(order), 46), pageLeft + 12 + colW + halfGap, y - 76, colW - 24, 66, 3));
  y -= 98;

  // Customer and delivery details.
  commands.push(drawSectionTitle('Customer & Delivery Details', pageLeft, y));
  y -= 18;
  commands.push(rect(pageLeft, y - 98, tableWidth, 98, '0.82 0.82 0.82', LIGHT_FILL));
  commands.push(fieldBox('Customer name', customerName(order), pageLeft + 12, y - 40, 152, 34));
  commands.push(fieldBox('Phone', order.shippingAddress?.phone || order.user?.phone, pageLeft + 174, y - 40, 130, 34));
  commands.push(fieldBox('Email', customerEmail(order) || order.shippingAddress?.email, pageLeft + 12, y - 82, 292, 34));
  commands.push(text('Delivery address', pageLeft + 324, y - 21, 8, 'F2', MUTED));
  wrap(address, 38).slice(0, 5).forEach((wrappedLine, index) => {
    commands.push(text(wrappedLine, pageLeft + 324, y - 36 - index * 11, 8, 'F1', DARK));
  });
  y -= 118;

  // Items table. The columns are wider and all text is wrapped or clipped before drawing.
  // Keep extra space below the section subtitle so the underline/title never touches the table header.
  commands.push(drawSectionTitle('Items Delivered', pageLeft, y));
  y -= 26;
  const itemX = pageLeft;
  const sizeX = 318;
  const qtyX = 380;
  const totalX = 444;
  const headerH = 24;
  commands.push(rect(itemX, y - headerH, tableWidth, headerH, DARK, DARK));
  commands.push(text('Item', itemX + 12, y - 15, 8.5, 'F2', '1 1 1'));
  commands.push(text('Size', sizeX + 10, y - 15, 8.5, 'F2', '1 1 1'));
  commands.push(text('Qty', qtyX + 12, y - 15, 8.5, 'F2', '1 1 1'));
  commands.push(text('Total', totalX + 12, y - 15, 8.5, 'F2', '1 1 1'));
  y -= headerH;

  if (!items.length) {
    commands.push(rect(itemX, y - 30, tableWidth, 30, '0.88 0.88 0.88', '1 1 1'));
    commands.push(text('No item details available on this receipt.', itemX + 12, y - 18, 8.5, 'F1', DARK));
    y -= 30;
  } else {
    for (const item of items.slice(0, 12)) {
      const name = item.productName || item.name || item.product?.name || 'Item';
      const size = ellipsize(safe(item.size, '-'), 10);
      const quantity = ellipsize(safe(item.quantity || 1), 8);
      const total = ellipsize(money(item.total ?? Number(item.price || 0) * Number(item.quantity || 1)), 16);
      const itemLines = wrap(name, 48).slice(0, 3);
      const rowHeight = Math.max(34, itemLines.length * 12 + 16);

      if (y - rowHeight < 172) {
        commands.push(rect(itemX, y - 28, tableWidth, 28, '0.88 0.88 0.88', '1 1 1'));
        commands.push(text('Additional items are available in the order record.', itemX + 12, y - 17, 8, 'F1', MUTED));
        y -= 28;
        break;
      }

      commands.push(rect(itemX, y - rowHeight, tableWidth, rowHeight, '0.88 0.88 0.88', '1 1 1'));
      commands.push(line(sizeX, y - rowHeight, sizeX, y, '0.88 0.88 0.88'));
      commands.push(line(qtyX, y - rowHeight, qtyX, y, '0.88 0.88 0.88'));
      commands.push(line(totalX, y - rowHeight, totalX, y, '0.88 0.88 0.88'));
      itemLines.forEach((itemLine, index) => {
        commands.push(text(itemLine, itemX + 12, y - 18 - index * 12, 8.5, 'F1', DARK));
      });
      const centerY = y - rowHeight / 2 - 3;
      commands.push(text(size, sizeX + 10, centerY, 8.5, 'F1', DARK));
      commands.push(text(quantity, qtyX + 14, centerY, 8.5, 'F1', DARK));
      commands.push(text(total, totalX + 12, centerY, 8.5, 'F1', DARK));
      y -= rowHeight;
    }
  }

  // Compact support and declaration panels placed directly after the items section.
  y -= 18;
  if (y < 142) y = 142;
  commands.push(rect(pageLeft, y - 46, tableWidth, 46, GOLD, LIGHT_GOLD_FILL));
  commands.push(text('Need help with this order?', pageLeft + 14, y - 15, 9.5, 'F2', DARK));
  commands.push(text('For delivery issues, payments, returns, or inquiries, contact ClasicCloset support.', pageLeft + 14, y - 29, 7.8, 'F1', DARK));
  commands.push(text(`Email: ${ellipsize(supportEmail(), 28)}`, pageLeft + 14, y - 40, 7.8, 'F2', GOLD_DARK));
  commands.push(text(`Phone: ${ellipsize(supportPhone(), 18)}`, pageLeft + 190, y - 40, 7.8, 'F2', GOLD_DARK));
  commands.push(text(`Website: ${ellipsize(supportWebsite(), 26)}`, pageLeft + 345, y - 40, 7.8, 'F2', GOLD_DARK));
  y -= 58;

  commands.push(rect(pageLeft, y - 42, tableWidth, 42, '0.78 0.78 0.78', '0.98 0.98 0.98'));
  commands.push(text('Delivery Declaration', pageLeft + 14, y - 15, 9.5, 'F2', DARK));
  commands.push(text('This receipt confirms the paid order above was successfully marked as delivered by ClasicCloset.', pageLeft + 14, y - 29, 7.8, 'F1', DARK));
  commands.push(text('Keep this PDF as proof of payment, delivery details, and delivery confirmation.', pageLeft + 14, y - 39, 7.8, 'F1', DARK));
  y -= 56;

  commands.push(line(pageLeft, y, pageRight, y, GOLD, 0.8));
  commands.push(text('Thank you for shopping with ClasicCloset. Premium Fashion • Kenya', 132, y - 17, 8, 'F2', GOLD_DARK));

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

        <div style="margin-top:22px;background:#fff8df;border:1px solid #d4af37;border-radius:12px;padding:14px;color:#111">
          <strong>Customer Support & Order Enquiries</strong><br />
          Need help with this order? Contact us for order issues, delivery questions, returns, or payment inquiries.<br />
          Email: ${escapeHtml(supportEmail())}<br />
          Phone: ${escapeHtml(supportPhone())}<br />
          Website: ${escapeHtml(supportWebsite())}
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
    const textResponse = await response.text().catch(() => '');
    throw new Error(`Delivered-order email failed: ${response.status} ${textResponse}`);
  }
}
