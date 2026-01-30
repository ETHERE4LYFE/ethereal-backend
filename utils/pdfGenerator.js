// =========================================================
// PDF GENERATOR - ETHERE4L (CLIENTE / PROVEEDOR)
// DEFINITIVE LUXURY VERSION
// =========================================================
const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');

/* =======================
   🆕 AGREGADO (NO BORRA)
   ======================= */
const axios = require('axios');

/* =======================
   🆕 AGREGADO (NO BORRA)
   Función para renderizar imágenes desde URL HTTPS
   ======================= */
async function renderImageFromURL(doc, url, x, y, width) {
  try {
    const res = await axios.get(url, { responseType: 'arraybuffer' });
    const buffer = Buffer.from(res.data);
    doc.image(buffer, x, y, { width });
    return true;
  } catch (err) {
    console.warn('[PDF] Error cargando imagen remota:', url);
    return false;
  }
}

async function buildPDF(cliente, pedido, jobId, type = 'CLIENTE') {
  return new Promise(async (resolve, reject) => {
    try {
      const ROOT = path.resolve(__dirname, '..');
      const LOGO_PATH = path.join(ROOT, 'assets', 'branding', 'logo.png');
      const FONT_PATH = path.join(ROOT, 'fonts', 'static', 'Cinzel-Bold.ttf');

      const doc = new PDFDocument({ size: 'A4', margin: 50 });
      const buffers = [];

      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', reject);

      // Fuente
      let mainFont = 'Helvetica';
      if (fs.existsSync(FONT_PATH)) {
        doc.registerFont('Cinzel', FONT_PATH);
        mainFont = 'Cinzel';
      }

      const BLACK = '#000000';
      const GRAY = '#666666';
      const LIGHT_GRAY = '#F2F2F2';

      // =====================================================
      // 🖤 WATERMARK LOGO (FONDO)
      // =====================================================
      if (fs.existsSync(LOGO_PATH)) {
        doc.opacity(0.07);
        doc.image(
          LOGO_PATH,
          doc.page.width / 2 - 200,
          doc.page.height / 2 - 200,
          { width: 400 }
        );
        doc.opacity(1);
      }

      // =====================================================
      // ENCABEZADO
      // =====================================================
      doc.font(mainFont).fontSize(18).fillColor(BLACK)
        .text('CONFIRMACIÓN DE ORDEN', { align: 'center' });

      doc.moveDown(0.5);
      doc.font('Helvetica').fontSize(10).fillColor(GRAY)
        .text(`ID: ${jobId}`, { align: 'center' })
        .text(`Fecha: ${new Date().toLocaleDateString('es-MX')}`, { align: 'center' });

      doc.moveDown(2);

      // =====================================================
      // DATOS DE ENVÍO (TABLA)
      // =====================================================
      const tableX = 50;
      let y = doc.y;

      doc.font('Helvetica-Bold').fontSize(11).fillColor(BLACK)
        .text('DATOS DE ENVÍO');

      y += 15;

      const rows = [
        ['Nombre', cliente.nombre],
        ['Email', cliente.email],
        ['Teléfono', cliente.telefono],
        ['Dirección', cliente.direccion]
      ];

      rows.forEach((row, i) => {
        doc.rect(tableX, y, 500, 22).fill(i % 2 === 0 ? LIGHT_GRAY : '#FFFFFF');
        doc.fillColor(BLACK).fontSize(9).font('Helvetica-Bold')
          .text(row[0], tableX + 10, y + 7);
        doc.font('Helvetica').fillColor(GRAY)
          .text(row[1], tableX + 140, y + 7, { width: 340 });
        y += 22;
      });

      doc.moveDown(2);

      // =====================================================
      // TABLA DE PRODUCTOS
      // =====================================================
      doc.font('Helvetica-Bold').fontSize(11).fillColor(BLACK)
        .text('PRODUCTOS');

      y = doc.y + 10;

      const cols = {
        img: 50,
        name: 120,
        size: 300,
        qty: 350,
        price: 400,
        total: 470
      };

      doc.fontSize(9).font('Helvetica-Bold').fillColor(BLACK);
      doc.text('IMG', cols.img, y);
      doc.text('PRODUCTO', cols.name, y);
      doc.text('TALLA', cols.size, y);
      doc.text('CANT', cols.qty, y);

      if (type === 'CLIENTE') {
        doc.text('PRECIO', cols.price, y);
        doc.text('SUBTOTAL', cols.total, y);
      }

      y += 15;
      doc.moveTo(50, y).lineTo(550, y).stroke();

      y += 10;
      doc.font('Helvetica').fontSize(9).fillColor(GRAY);

      for (const item of pedido.items) {

        // -----------------------------------------------------
        // 🖼️ IMAGEN DE PRODUCTO (LOCAL O REMOTA)
        // -----------------------------------------------------
        const IMG_WIDTH = 40;
        const IMG_HEIGHT = 40;
        let imageRendered = false;

        // === LÓGICA ORIGINAL (NO BORRADA) ===
        if (Array.isArray(item.fotos) && item.fotos.length > 0) {
          const localImagePath = path.join(ROOT, item.fotos[0]);

          if (fs.existsSync(localImagePath)) {
            try {
              doc.image(localImagePath, cols.img, y, { width: IMG_WIDTH });
              imageRendered = true;
            } catch (err) {
              console.warn('[PDF] Error renderizando imagen local:', localImagePath);
            }
          }
        }

        // === 🆕 FALLBACK A URL HTTPS (AGREGADO) ===
        if (!imageRendered && Array.isArray(item.fotos) && item.fotos[0]) {
          imageRendered = await renderImageFromURL(
            doc,
            item.fotos[0],
            cols.img,
            y,
            IMG_WIDTH
          );
        }

        // === PLACEHOLDER ORIGINAL ===
        if (!imageRendered) {
          doc.rect(cols.img, y, IMG_WIDTH, IMG_HEIGHT)
            .strokeColor('#CCCCCC')
            .lineWidth(0.5)
            .stroke();

          doc.font('Helvetica')
            .fontSize(8)
            .fillColor('#999999')
            .text(
              'IMG',
              cols.img,
              y + IMG_HEIGHT / 2 - 4,
              { width: IMG_WIDTH, align: 'center' }
            );
        }

        doc.text(item.nombre, cols.name, y, { width: 170 });
        doc.text(item.talla, cols.size, y);
        doc.text(item.cantidad, cols.qty, y);

        if (type === 'CLIENTE') {
          doc.text(`$${item.precio}`, cols.price, y);
          doc.text(`$${item.precio * item.cantidad}`, cols.total, y);
        }

        y += 55;
      }

      doc.moveDown(2);

      // =====================================================
      // TOTAL A PAGAR (DESTACADO)
      // =====================================================
      if (type === 'CLIENTE') {
        doc.rect(300, y, 250, 70).fill('#000000');
        doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(12)
          .text('TOTAL A PAGAR', 300, y + 15, { align: 'center', width: 250 });

        doc.fontSize(18)
          .text(`$${pedido.total.toLocaleString('es-MX')} MXN`, 300, y + 35, {
            align: 'center',
            width: 250
          });

        y += 90;
      }

      // =====================================================
      // BLOQUE DE PAGO
      // =====================================================
      if (type === 'CLIENTE') {
        doc.font('Helvetica-Bold').fontSize(11).fillColor(BLACK)
          .text('DATOS PARA TRANSFERENCIA');

        const qrData = `ETHERE4L|${jobId}|MXN|${pedido.total}`;
        const qr = await QRCode.toDataURL(qrData);

        doc.image(qr, 50, y + 10, { width: 90 });

        doc.font('Helvetica').fontSize(9).fillColor(GRAY);
        doc.text('BANCO: BBVA', 160, y + 20);
        doc.text('CLABE: 0123 4567 8901 2345 67', 160, y + 35);
        doc.text(`CONCEPTO: ${jobId}`, 160, y + 50);
      }

      // =====================================================
      // FOOTER
      // =====================================================
      doc.fontSize(8).fillColor(GRAY)
        .text('ETHERE4L • STREETWEAR & HIGH FASHION', 50, 760, {
          align: 'center'
        });

      doc.end();

    } catch (err) {
      console.error('[PDF ERROR]', err);
      reject(err);
    }
  });
}

module.exports = { buildPDF };
