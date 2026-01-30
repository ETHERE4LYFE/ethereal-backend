// =========================================================
// PDF GENERATOR - ETHERE4L (CLIENTE / PROVEEDOR)
// DEFINITIVE LUXURY VERSION - PRODUCTION READY
// =========================================================
const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const axios = require('axios');

// 🌐 URL BASE DE TUS IMÁGENES (NETLIFY)
// Esto es vital para convertir rutas relativas "/images/..." en URLs absolutas
const FRONTEND_URL = 'https://ethereal-frontend.netlify.app';

/* =======================
   🆕 AGREGADO: Helper robusto para descargar Buffers
   ======================= */
async function fetchRemoteImageBuffer(url) {
  try {
    // Si la URL es relativa (empieza con /), le pegamos el dominio
    let fullUrl = url;
    if (!url.startsWith('http')) {
       // Aseguramos que no haya dobles slashes //
       const cleanPath = url.startsWith('/') ? url.substring(1) : url;
       fullUrl = `${FRONTEND_URL}/${cleanPath}`;
    }
    
    // console.log(`[PDF] Descargando imagen: ${fullUrl}`); // Descomentar para debug

    const response = await axios.get(fullUrl, {
      responseType: 'arraybuffer',
      timeout: 5000 // Timeout de seguridad
    });
    
    return Buffer.from(response.data, 'binary');
  } catch (err) {
    console.warn(`[PDF WARN] No se pudo descargar imagen: ${url}`);
    return null;
  }
}

async function buildPDF(cliente, pedido, jobId, type = 'CLIENTE') {
  return new Promise(async (resolve, reject) => {
    try {
      const ROOT = path.resolve(__dirname, '..');
      // Intentamos buscar assets locales del backend (logo.png)
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
        ['Nombre', `${cliente.nombre} ${cliente.apellidos || ''}`], // Agregué apellidos si existen
        ['Email', cliente.email],
        ['Teléfono', cliente.telefono],
        ['Dirección', `${cliente.calle || ''} ${cliente.numero_exterior || ''}, ${cliente.colonia || ''}`],
        ['Ciudad', `${cliente.ciudad || ''}, ${cliente.estado || ''}, CP: ${cliente.cp || ''}`]
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
      y = doc.y + 20; // Ajuste de espacio

      // =====================================================
      // TABLA DE PRODUCTOS
      // =====================================================
      doc.font('Helvetica-Bold').fontSize(11).fillColor(BLACK)
        .text('PRODUCTOS');

      y += 15;

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

      // 🔄 ITERACIÓN DE PRODUCTOS
      for (const item of pedido.items) {
        
        // Control de salto de página manual si se acaba el espacio
        if (y > 700) {
            doc.addPage();
            y = 50;
        }

        // -----------------------------------------------------
        // 🖼️ LÓGICA DE IMAGEN HÍBRIDA (La Solución)
        // -----------------------------------------------------
        const IMG_WIDTH = 40;
        const IMG_HEIGHT = 40;
        let imageRendered = false;

        // 1. Determinar la fuente de la imagen
        // item.fotos suele ser un array, tomamos la primera. O item.image
        let imageSource = null;
        if (Array.isArray(item.fotos) && item.fotos.length > 0) imageSource = item.fotos[0];
        else if (item.image) imageSource = item.image;

        // 2. Intentar cargar
        if (imageSource) {
            // A. Intento Local (Solo funcionará si tienes assets en Railway, poco probable para productos)
            const localPath = path.join(ROOT, imageSource);
            if (fs.existsSync(localPath)) {
                try {
                    doc.image(localPath, cols.img, y, { width: IMG_WIDTH, height: IMG_HEIGHT, fit: [IMG_WIDTH, IMG_HEIGHT] });
                    imageRendered = true;
                } catch(e) {}
            }

            // B. Intento Remoto (La clave para producción)
            if (!imageRendered) {
                const buffer = await fetchRemoteImageBuffer(imageSource);
                if (buffer) {
                    try {
                        doc.image(buffer, cols.img, y, { width: IMG_WIDTH, height: IMG_HEIGHT, fit: [IMG_WIDTH, IMG_HEIGHT] });
                        imageRendered = true;
                    } catch (e) { console.warn('Buffer de imagen corrupto o formato no soportado'); }
                }
            }
        }

        // === PLACEHOLDER (Si todo falla) ===
        if (!imageRendered) {
          doc.rect(cols.img, y, IMG_WIDTH, IMG_HEIGHT)
            .strokeColor('#CCCCCC')
            .lineWidth(0.5)
            .stroke();

          doc.font('Helvetica')
            .fontSize(8)
            .fillColor('#999999')
            .text('IMG', cols.img, y + IMG_HEIGHT / 2 - 4, { width: IMG_WIDTH, align: 'center' });
        }

        // Reset color y fuente para texto
        doc.fillColor(GRAY).font('Helvetica');

        // Textos alineados verticalmente a la imagen
        const textY = y + 10;
        doc.text(item.nombre, cols.name, textY, { width: 170 });
        doc.text(item.talla || 'U', cols.size, textY);
        doc.text(item.cantidad, cols.qty, textY);

        if (type === 'CLIENTE') {
          doc.text(`$${item.precio}`, cols.price, textY);
          doc.text(`$${item.precio * item.cantidad}`, cols.total, textY);
        }

        y += 55; // Espacio por fila
      }

      doc.moveDown(2);

      // =====================================================
      // TOTAL A PAGAR (DESTACADO)
      // =====================================================
      if (type === 'CLIENTE') {
        const totalBoxY = y;
        doc.rect(300, totalBoxY, 250, 70).fill('#000000');
        doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(12)
          .text('TOTAL A PAGAR', 300, totalBoxY + 15, { align: 'center', width: 250 });

        doc.fontSize(18)
          .text(`$${pedido.total.toLocaleString('es-MX')} MXN`, 300, totalBoxY + 35, {
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
          .text('DATOS PARA TRANSFERENCIA', 50, y);

        // QR GENERATOR
        const qrData = `ETHERE4L|${jobId}|MXN|${pedido.total}`;
        const qr = await QRCode.toDataURL(qrData);

        doc.image(qr, 50, y + 15, { width: 90 });

        doc.font('Helvetica').fontSize(9).fillColor(GRAY);
        doc.text('BANCO:', 160, y + 25).font('Helvetica-Bold').text('BBVA', 220, y + 25);
        doc.font('Helvetica').text('CLABE:', 160, y + 40).font('Helvetica-Bold').text('0123 4567 8901 2345 67', 220, y + 40);
        doc.font('Helvetica').text('CONCEPTO:', 160, y + 55).fillColor('#FF0000').font('Helvetica-Bold').text(jobId, 220, y + 55);
      }

      // =====================================================
      // FOOTER
      // =====================================================
      doc.fontSize(8).fillColor(GRAY)
        .text('ETHERE4L • STREETWEAR & HIGH FASHION', 50, 760, {
          align: 'center', width: 500
        });

      doc.end();

    } catch (err) {
      console.error('[PDF ERROR]', err);
      reject(err);
    }
  });
}

module.exports = { buildPDF };
