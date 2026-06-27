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
  // The PDF is handcrafted, so the React component cannot be mounted directly inside it.
  return [
    pdfCircle(x + 22, y + 20, 19, GOLD, '1 1 1', 1.4),
    line(x + 22, y + 21, x + 22, y + 31, GOLD, 1.6),
    `q 1.6 w ${GOLD} RG ${x + 22} ${y + 31} m ${x + 22} ${y + 37} ${x + 27} ${y + 39} ${x + 31} ${y + 35} c S Q\n`,
    line(x + 22, y + 21, x + 7, y + 6, GOLD, 1.6),
    line(x + 22, y + 21, x + 37, y + 6, GOLD, 1.6),
    line(x + 5, y + 6, x + 39, y + 6, GOLD, 1.6),
    text('CLASIC', x + 54, y + 25, 12, 'F2', GOLD),
    text('CLOSET', x + 54, y + 5, 12, 'F2', GOLD),
  ].join('');
}

function wrap(value: unknown, maxChars: number): string[] {
  const raw = String(value ?? '').trim() || '-';
  const words = raw.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';

  const pushLongWord = (word: string) => {
    let remaining = word;
    while (remaining.length > maxChars) {
      lines.push(remaining.slice(0, maxChars));
      remaining = remaining.slice(maxChars);
    }
    return remaining;
  };

  for (const word of words) {
    const piece = word.length > maxChars ? pushLongWord(word) : word;
    if (!piece) continue;

    const next = current ? `${current} ${piece}` : piece;
    if (next.length > maxChars && current) {
      lines.push(current);
      current = piece;
    } else {
      current = next;
    }
  }

  if (current) lines.push(current);
  return lines.length ? lines : ['-'];
}

function tableRow(label: string, value: unknown, x: number, y: number, w: number, h = 24): PdfCommand {
  const labelW = Math.min(118, Math.floor(w * 0.43));
  const valueX = x + labelW + 8;
  const valueW = w - labelW - 14;
  const maxValueChars = Math.max(10, Math.floor(valueW / 4.9));
  const valueLines = wrap(safe(value), maxValueChars).slice(0, 3);
  const actualH = Math.max(h, valueLines.length * 10 + 12);
  const topY = y;
  const bottomY = y - actualH;

  return [
    rect(x, bottomY, w, actualH, LIGHT_BORDER, '1 1 1'),
    line(x + labelW, bottomY, x + labelW, topY, LIGHT_BORDER),
    text(label, x + 8, topY - 15, 8, 'F2'),
    ...valueLines.map((lineText, index) => text(lineText, valueX, topY - 14 - index * 10, 7.8, 'F1')),
  ].join('');
}

function buildReceiptPdf(order: AnyOrder): Buffer {
  const commands: string[] = [];
  const items = Array.isArray(order.items) ? order.items : [];
  const markedDeliveredAt = kenyaDateTime(order.updatedAt || order.deliveredAt || order.fulfilledAt || order.createdAt);
  const orderNo = safe(order.orderNumber || order.id);
  const address = deliveryAddress(order) || addressLines(order).join(', ');
  const pageLeft = 36;
  const pageRight = 559;
  const tableWidth = pageRight - pageLeft;

  commands.push(rect(0, 0, 595, 842, '1 1 1', '1 1 1'));

  // Compact premium receipt header. Logo line removed for a cleaner brand mark.
  commands.push(rect(pageLeft, 756, tableWidth, 54, DARK, DARK));
  commands.push(drawClasicClosetLogo(52, 765));
  commands.push(text('DELIVERY CONFIRMATION RECEIPT', 236, 790, 15, 'F2', '1 1 1'));
  commands.push(text(`Order #${orderNo}`, 236, 772, 9, 'F1', '0.92 0.92 0.92'));
  commands.push(text('Status: DELIVERED', 448, 772, 9, 'F2', GOLD));
  commands.push(line(pageLeft, 744, pageRight, 744, GOLD, 1.1));

  // Receipt summary with cells sized to prevent overflow. Generated date removed.
  let y = 724;
  commands.push(text('Receipt Summary', pageLeft, y, 12, 'F2', DARK));
  y -= 14;
  commands.push(rect(pageLeft, y - 82, tableWidth, 82, '0.82 0.82 0.82', '0.995 0.995 0.995'));
  commands.push(tableRow('Amount paid', money(order.total), 54, y - 12, 230));
  commands.push(tableRow('Payment method', paymentMethod(order), 54, y - 36, 230));
  commands.push(tableRow('Payment status', paymentStatus(order), 54, y - 60, 230));
  commands.push(tableRow('Payment reference', paymentReference(order), 310, y - 12, 215));
  commands.push(tableRow('Delivered on', markedDeliveredAt, 310, y - 48, 215));

  // Customer block.
  y = 610;
  commands.push(text('Customer & Delivery Details', pageLeft, y, 12, 'F2', DARK));
  y -= 14;
  commands.push(rect(pageLeft, y - 86, tableWidth, 86, '0.82 0.82 0.82', '1 1 1'));
  commands.push(tableRow('Customer name', customerName(order), 54, y - 14, 230));
  commands.push(tableRow('Phone', order.shippingAddress?.phone || order.user?.phone, 54, y - 38, 230));
  commands.push(tableRow('Email', customerEmail(order) || order.shippingAddress?.email, 54, y - 62, 230));
  commands.push(text('Delivery address', 310, y - 23, 8.5, 'F2', DARK));
  wrap(address, 42).slice(0, 4).forEach((wrappedLine, index) => {
    commands.push(text(wrappedLine, 310, y - 40 - index * 11, 8, 'F1', DARK));
  });

  // Items table. Every row gets its own dynamic height, and long values are wrapped.
  y = 496;
  commands.push(text('Items Delivered', pageLeft, y, 12, 'F2', DARK));
  y -= 25;
  commands.push(rect(pageLeft, y, tableWidth, 24, DARK, DARK));
  commands.push(text('Item', 50, y + 8, 8.5, 'F2', '1 1 1'));
  commands.push(text('Size', 322, y + 8, 8.5, 'F2', '1 1 1'));
  commands.push(text('Qty', 393, y + 8, 8.5, 'F2', '1 1 1'));
  commands.push(text('Total', 470, y + 8, 8.5, 'F2', '1 1 1'));

  const colSize = 306;
  const colQty = 380;
  const colTotal = 452;
  const colEnd = pageRight;
  y -= 2;

  if (!items.length) {
    commands.push(rect(pageLeft, y - 28, tableWidth, 28, '0.88 0.88 0.88', '1 1 1'));
    commands.push(text('No item details available on this receipt.', 50, y - 18, 8.5, 'F1', DARK));
    y -= 34;
  } else {
    for (const item of items.slice(0, 10)) {
      const name = item.productName || item.name || item.product?.name || 'Item';
      const size = safe(item.size, '-');
      const quantity = safe(item.quantity || 1);
      const total = money(item.total ?? Number(item.price || 0) * Number(item.quantity || 1));
      const itemLines = wrap(name, 45).slice(0, 4);
      const sizeLines = wrap(size, 10).slice(0, 2);
      const totalLines = wrap(total, 14).slice(0, 2);
      const rowHeight = Math.max(34, Math.max(itemLines.length, sizeLines.length, totalLines.length) * 11 + 18);
      const rowBottom = y - rowHeight;
      const middleTextY = rowBottom + rowHeight / 2 + 3;

      if (rowBottom < 205) {
        commands.push(text('Additional items may be included in the order record.', 50, y - 15, 8, 'F1', MUTED));
        y -= 22;
        break;
      }

      commands.push(rect(pageLeft, rowBottom, tableWidth, rowHeight, '0.88 0.88 0.88', '1 1 1'));
      commands.push(line(colSize, rowBottom, colSize, rowBottom + rowHeight, '0.88 0.88 0.88'));
      commands.push(line(colQty, rowBottom, colQty, rowBottom + rowHeight, '0.88 0.88 0.88'));
      commands.push(line(colTotal, rowBottom, colTotal, rowBottom + rowHeight, '0.88 0.88 0.88'));
      commands.push(line(colEnd, rowBottom, colEnd, rowBottom + rowHeight, '0.88 0.88 0.88'));

      itemLines.forEach((itemLine, index) => commands.push(text(itemLine, 50, y - 16 - index * 11, 8.5, 'F1', DARK)));
      sizeLines.forEach((lineText, index) => commands.push(text(lineText, colSize + 14, middleTextY - index * 10, 8.2, 'F1', DARK)));
      commands.push(text(quantity, colQty + 20, middleTextY, 8.2, 'F1', DARK));
      totalLines.forEach((lineText, index) => commands.push(text(lineText, colTotal + 14, middleTextY - index * 10, 8.2, 'F1', DARK)));
      y = rowBottom;
    }
  }

  // Bring support and footer immediately after the table, not at the bottom of the page.
  y -= 18;
  commands.push(rect(pageLeft, y - 54, tableWidth, 54, GOLD, LIGHT_GOLD_FILL));
  commands.push(text('Need help with this order?', 54, y - 16, 10, 'F2', DARK));
  commands.push(text('For delivery issues, payment questions, returns, or enquiries, contact ClasicCloset support.', 54, y - 30, 8, 'F1', DARK));
  commands.push(text(`Email: ${supportEmail()}`, 54, y - 43, 8, 'F2', GOLD_DARK));
  commands.push(text(`Phone: ${supportPhone()}`, 226, y - 43, 8, 'F2', GOLD_DARK));
  commands.push(text(`Website: ${supportWebsite()}`, 370, y - 43, 8, 'F2', GOLD_DARK));

  y -= 70;
  commands.push(rect(pageLeft, y - 50, tableWidth, 50, '0.78 0.78 0.78', '0.985 0.985 0.985'));
  commands.push(text('Delivery Declaration', 54, y - 15, 10, 'F2', DARK));
  commands.push(text('This receipt confirms that the paid order above was successfully marked as delivered by ClasicCloset.', 54, y - 30, 8, 'F1', DARK));
  commands.push(text('Keep this PDF as proof of payment, delivery details, and delivery confirmation.', 54, y - 42, 8, 'F1', DARK));

  y -= 66;
  commands.push(line(pageLeft, y, pageRight, y, GOLD, 0.8));
  commands.push(text('Thank you for shopping with ClasicCloset. Premium Fashion • Kenya', 150, y - 18, 8, 'F2', GOLD_DARK));

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
