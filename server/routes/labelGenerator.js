import express from 'express';
import puppeteer from 'puppeteer';
import QRCode from 'qrcode';

const router = express.Router();

const LABEL_WIDTH_IN = 4;
const LABEL_HEIGHT_IN = 6;
const OUTPUT_DPI = 300;
const BROWSER_DPI = 96;
const DEVICE_SCALE = OUTPUT_DPI / BROWSER_DPI;
const VIEWPORT_WIDTH = Math.round(LABEL_WIDTH_IN * BROWSER_DPI);
const VIEWPORT_HEIGHT = Math.round(LABEL_HEIGHT_IN * BROWSER_DPI);
const OUTPUT_WIDTH = LABEL_WIDTH_IN * OUTPUT_DPI;
const OUTPUT_HEIGHT = LABEL_HEIGHT_IN * OUTPUT_DPI;

async function generateLabelHTML(data, qaMode = false) {
  const {
    siteId = 'SITE-003',
    siteName = 'THE WAVERLY',
    addressLine = '123 MAIN STREET ASS DE 10129',
    attnName = 'CIARA RODRIGUEZ',
    zoneCode = 'C/D',
    boxIndex = '2/3',
    category = 'KITS',
    netWeightLb = '40.0',
    batch = 'B-2026-001',
    date = '1/20/2026',
    phone = '800-555-0199',
    spineText = 'SIPJOLT V98',
    qrText = ''
  } = data;

  const qrPayload = qrText || JSON.stringify({
    siteId,
    siteName,
    boxIndex,
    batch,
    ts: date
  });

  // v1.00 CORRECTED Zone Color Mapping
  const getZoneColor = (zone) => {
    const zoneUpper = (zone || '').toUpperCase().trim();
    if (zoneUpper === 'A') return { bg: '#FEE2E2', border: '#EF4444', text: '#991B1B', label: 'ZONE A (BOTTOM)' };
    if (zoneUpper === 'B1' || zoneUpper === 'B2' || zoneUpper === 'B') return { bg: '#DCFCE7', border: '#22C55E', text: '#166534', label: 'ZONE B' };
    if (zoneUpper === 'C') return { bg: '#FEF9C3', border: '#EAB308', text: '#854D0E', label: 'ZONE C (2ND TO TOP)' };
    if (zoneUpper === 'D') return { bg: '#F3F4F6', border: '#6B7280', text: '#1F2937', label: 'ZONE D (TOP)' };
    if (zoneUpper === 'E') return { bg: '#DBEAFE', border: '#2563EB', text: '#1E40AF', label: 'BLUE' };
    return { bg: '#F3F4F6', border: '#6B7280', text: '#374151', label: 'GRAY' };
  };

  const zoneColors = getZoneColor(zoneCode);

  // v1.00 CORRECTED Zone to Shelf Mapping
  const getShelfInfo = (zone) => {
    const zoneUpper = (zone || '').toUpperCase().trim();
    if (zoneUpper === 'A') return 'SHELF 1';
    if (zoneUpper === 'B1') return 'SHELF 2+3';
    if (zoneUpper === 'B2') return 'SHELF 2';
    if (zoneUpper === 'C') return 'SHELF 3';
    if (zoneUpper === 'D') return 'SHELF 4';
    if (zoneUpper === 'E') return 'FLOOR';
    return '';
  };

  const shelfInfo = getShelfInfo(zoneCode);

  const qrDataUrl = await QRCode.toDataURL(qrPayload, {
    width: 525,
    margin: 2,
    errorCorrectionLevel: 'H'
  });

  const qaOverlay = qaMode ? `
    <div style="position: absolute; inset: 0; pointer-events: none;">
      <div style="position: absolute; top: 0.125in; left: 0.125in; right: 0.125in; bottom: 0.125in; border: 2px dashed red; opacity: 0.6;"></div>
      <div style="position: absolute; bottom: 0.55in; right: 0.15in; width: 1.75in; height: 1.75in; border: 2px solid blue; opacity: 0.6;">
        <span style="position: absolute; top: -18px; left: 0; font-size: 11px; color: blue; font-weight: bold;">1.75" × 1.75"</span>
      </div>
      <div style="position: absolute; left: 0; top: 0; width: 0.3in; height: 100%; background: repeating-linear-gradient(0deg, transparent 0, transparent 0.1in, rgba(0,0,0,0.2) 0.1in, rgba(0,0,0,0.2) calc(0.1in + 1px));"></div>
    </div>
  ` : '';

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    @page {
      size: 4in 6in;
      margin: 0;
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      width: 4in;
      height: 6in;
      font-family: Arial, Helvetica, sans-serif;
      background: white;
      margin: 0;
      padding: 0;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .label {
      width: 4in;
      height: 6in;
      border: 6pt solid black;
      display: flex;
      position: relative;
      background: white;
    }
    .spine {
      width: 0.22in;
      background: black;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .spine-text {
      color: white;
      font-size: 8pt;
      font-weight: 900;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      transform: rotate(-90deg);
      white-space: nowrap;
    }
    .content {
      flex: 1;
      display: flex;
      flex-direction: column;
      padding: 0.12in;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 0.06in;
    }
    .site-badge {
      background: black;
      color: white;
      font-weight: 900;
      font-size: 14pt;
      padding: 4pt 10pt;
    }
    .logo-section {
      text-align: right;
    }
    .logo-text {
      font-weight: 900;
      font-size: 20pt;
      letter-spacing: -0.5px;
      border-bottom: 3pt solid black;
      padding-bottom: 2pt;
      display: inline-block;
    }
    .logistics-badge {
      border: 1.5pt solid black;
      font-size: 6.5pt;
      font-weight: 900;
      padding: 2pt 6pt;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-top: 3pt;
      display: inline-block;
    }
    .venue-name {
      font-weight: 900;
      font-size: 26pt;
      line-height: 1;
      text-transform: uppercase;
      letter-spacing: -0.5px;
      margin-bottom: 0.05in;
    }
    .address {
      font-weight: 700;
      font-size: 9pt;
      text-transform: uppercase;
      margin-bottom: 0.04in;
    }
    .divider {
      border-top: 2pt solid black;
      margin: 0.03in 0;
    }
    .attn {
      font-weight: 700;
      font-size: 9pt;
      text-transform: uppercase;
      margin-bottom: 0.03in;
    }
    .zone-section {
      display: flex;
      align-items: center;
      justify-content: center;
      flex: 1;
      padding: 0.05in 0;
      background: ${zoneColors.bg};
      border: 2pt solid ${zoneColors.border};
      border-radius: 4pt;
      margin: 0.03in 0;
    }
    .zone-code {
      font-weight: 900;
      font-size: 68pt;
      line-height: 0.85;
      letter-spacing: -3px;
      color: ${zoneColors.text};
    }
    .zone-color-label {
      position: absolute;
      top: 2pt;
      right: 4pt;
      font-size: 6pt;
      font-weight: 900;
      color: ${zoneColors.text};
      text-transform: uppercase;
    }
    .shelf-label {
      font-size: 7pt;
      font-weight: 900;
      color: ${zoneColors.text};
      margin-top: 2pt;
    }
    .zone-divider {
      width: 4pt;
      height: 0.95in;
      background: black;
      margin: 0 0.12in;
    }
    .box-section {
      display: flex;
      flex-direction: column;
    }
    .box-label {
      font-weight: 900;
      font-size: 12pt;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }
    .box-count {
      font-weight: 900;
      font-size: 48pt;
      line-height: 1;
      letter-spacing: -2px;
    }
    .category-tag {
      background: black;
      color: white;
      font-weight: 900;
      font-size: 10pt;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      padding: 4pt 14pt;
      text-align: center;
      margin: 0.04in auto 0;
    }
    .bottom-section {
      border-top: 2.5pt solid black;
      padding-top: 0.06in;
    }
    .weight-qr-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .weight-block {
      flex: 1;
    }
    .weight-label {
      font-weight: 900;
      font-size: 8pt;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 1pt;
    }
    .weight-value {
      display: flex;
      align-items: baseline;
      gap: 4pt;
    }
    .weight-number {
      font-weight: 900;
      font-size: 32pt;
      line-height: 1;
      letter-spacing: -1px;
    }
    .weight-unit {
      font-weight: 900;
      font-size: 12pt;
    }
    .batch-date-row {
      display: flex;
      gap: 0.15in;
      margin-top: 0.03in;
      border-top: 1pt solid #999;
      padding-top: 0.02in;
    }
    .batch-date-item {
      display: flex;
      flex-direction: column;
    }
    .batch-date-label {
      font-weight: 900;
      font-size: 6pt;
      text-transform: uppercase;
      color: #666;
    }
    .batch-date-value {
      font-weight: 900;
      font-size: 8pt;
    }
    .qr-block {
      width: 1.75in;
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .qr-border {
      border: 2pt solid black;
      padding: 0.1in;
      background: white;
    }
    .qr-code {
      width: 1.55in;
      height: 1.55in;
    }
    .qr-label {
      font-weight: 900;
      font-size: 7pt;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-top: 3pt;
      text-align: center;
    }
    .driver-footer {
      background: black;
      color: white;
      border-radius: 4pt;
      padding: 0.05in 0.08in;
      margin-top: 0.05in;
    }
    .driver-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1pt solid rgba(255,255,255,0.3);
      padding-bottom: 3pt;
      margin-bottom: 3pt;
    }
    .driver-title {
      font-weight: 900;
      font-size: 8pt;
    }
    .driver-phone {
      font-weight: 900;
      font-size: 8pt;
    }
    .driver-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2pt 10pt;
      font-size: 7pt;
      font-weight: 700;
    }
    .driver-item {
      display: flex;
      align-items: center;
      gap: 5pt;
    }
    .driver-number {
      background: white;
      color: black;
      width: 12pt;
      height: 12pt;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 6pt;
      font-weight: 900;
    }
    .driver-warning {
      background: white;
      color: black;
      border-radius: 10pt;
      padding: 2pt 5pt;
      display: flex;
      align-items: center;
      gap: 3pt;
      font-size: 6pt;
    }
    .warning-icon {
      width: 10pt;
      height: 10pt;
      border-radius: 50%;
      border: 1.5pt solid black;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 900;
      font-size: 8pt;
    }
  </style>
</head>
<body>
  <div class="label">
    <div class="spine">
      <span class="spine-text">${spineText}</span>
    </div>
    <div class="content">
      <div class="header">
        <div class="site-badge">${siteId}</div>
        <div class="logo-section">
          <div class="logo-text">SIPJOLT</div>
          <div class="logistics-badge">MILK RUN LOGISTICS</div>
        </div>
      </div>
      
      <div class="venue-name">${siteName}</div>
      <div class="address">⊙ ${addressLine}</div>
      
      <div class="divider"></div>
      
      <div class="attn">⚇ ATTN: ${attnName}</div>
      
      <div class="divider"></div>
      
      <div class="zone-section" style="position: relative;">
        <span class="zone-color-label">${zoneColors.label}</span>
        <div class="zone-code">${zoneCode}</div>
        <div class="zone-divider"></div>
        <div class="box-section">
          <div class="box-label">BOX</div>
          <div class="box-count">${boxIndex}</div>
          ${shelfInfo ? `<div class="shelf-label">${shelfInfo}</div>` : ''}
        </div>
      </div>
      
      ${category ? `<div class="category-tag">${category}</div>` : ''}
      
      <div class="bottom-section">
        <div class="weight-qr-row">
          <div class="weight-block">
            <div class="weight-label">NET WEIGHT</div>
            <div class="weight-value">
              <span class="weight-number">${netWeightLb}</span>
              <span class="weight-unit">LB</span>
            </div>
            <div class="batch-date-row">
              <div class="batch-date-item">
                <span class="batch-date-label">BATCH</span>
                <span class="batch-date-value">${batch}</span>
              </div>
              <div class="batch-date-item">
                <span class="batch-date-label">DATE</span>
                <span class="batch-date-value">${date}</span>
              </div>
            </div>
          </div>
          <div class="qr-block">
            <div class="qr-border">
              <img class="qr-code" src="${qrDataUrl}" alt="QR Code" />
            </div>
            <div class="qr-label">SCAN TO VERIFY</div>
          </div>
        </div>
      </div>
      
      <div class="driver-footer">
        <div class="driver-header">
          <span class="driver-title">🚚 DRIVER</span>
          <span class="driver-phone">📞 ${phone}</span>
        </div>
        <div class="driver-grid">
          <div class="driver-item">
            <span class="driver-number">1</span>
            CLOSET ONLY
          </div>
          <div class="driver-item">
            <span class="driver-number">2</span>
            MATCH ZONE
          </div>
          <div class="driver-item">
            <span class="driver-number">3</span>
            PHOTO RACK
          </div>
          <div class="driver-warning">
            <span class="warning-icon">!</span>
            WET = REFUSE
          </div>
        </div>
      </div>
    </div>
    ${qaOverlay}
  </div>
</body>
</html>`;
}

let browserInstance = null;

async function getBrowser() {
  if (!browserInstance) {
    const chromiumPath = process.env.PUPPETEER_EXECUTABLE_PATH || 
      '/nix/store/qa9cnw4v5xkxyip6mb9kxqfq1z4x2dx1-chromium-138.0.7204.100/bin/chromium';
    
    browserInstance = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer'
      ],
      executablePath: chromiumPath
    });
  }
  return browserInstance;
}

router.post('/generate', async (req, res) => {
  try {
    const { format = 'png', qaMode = false, ...labelData } = req.body;
    const html = await generateLabelHTML(labelData, qaMode);
    
    const browser = await getBrowser();
    const page = await browser.newPage();
    
    await page.setViewport({
      width: VIEWPORT_WIDTH,
      height: VIEWPORT_HEIGHT,
      deviceScaleFactor: DEVICE_SCALE
    });
    
    await page.setContent(html, { waitUntil: 'networkidle0' });
    
    const timestamp = Date.now();
    const filename = `${labelData.siteId || 'SITE-001'}_box-${(labelData.boxIndex || '1/1').replace('/', 'of')}_${timestamp}`;
    
    // Add no-cache headers to ensure fresh generation
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    if (format === 'pdf') {
      const pdf = await page.pdf({
        width: '4in',
        height: '6in',
        printBackground: true,
        margin: { top: 0, right: 0, bottom: 0, left: 0 },
        preferCSSPageSize: true
      });
      
      await page.close();
      
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}.pdf"`);
      res.send(pdf);
    } else {
      const screenshot = await page.screenshot({
        type: 'png',
        clip: {
          x: 0,
          y: 0,
          width: VIEWPORT_WIDTH,
          height: VIEWPORT_HEIGHT
        }
      });
      
      await page.close();
      
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}.png"`);
      res.send(screenshot);
    }
  } catch (error) {
    console.error('Label generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.get('/preview', async (req, res) => {
  try {
    const labelData = {
      siteId: req.query.siteId || 'SITE-003',
      siteName: req.query.siteName || 'THE WAVERLY',
      addressLine: req.query.addressLine || '123 MAIN STREET ASS DE 10129',
      attnName: req.query.attnName || 'CIARA RODRIGUEZ',
      zoneCode: req.query.zoneCode || 'C/D',
      boxIndex: req.query.boxIndex || '2/3',
      category: req.query.category || 'KITS',
      netWeightLb: req.query.netWeightLb || '40.0',
      batch: req.query.batch || 'B-2026-001',
      date: req.query.date || '1/20/2026',
      phone: req.query.phone || '800-555-0199',
      spineText: req.query.spineText || 'SIPJOLT V98',
      qrText: req.query.qrText || ''
    };
    const qaMode = req.query.qaMode === 'true';
    
    const html = await generateLabelHTML(labelData, qaMode);
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (error) {
    console.error('Preview error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
