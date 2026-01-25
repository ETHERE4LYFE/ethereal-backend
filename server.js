// ===============================
// ETHERE4L BACKEND – RAILWAY SAFE
// ===============================

// dotenv SOLO en local
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const { Resend } = require('resend');

// --- 1. APP ---
const app = express();

// --- 2. PUERTO (SANITIZADO TOTAL) ---
let portToUse = 3000;
const rawPort = process.env.PORT;

if (rawPort) {
    const parsedPort = parseInt(rawPort, 10);
    if (!isNaN(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
        portToUse = parsedPort;
        console.log(`✅ Using Railway PORT: ${portToUse}`);
    } else {
        console.warn(`⚠️ Invalid PORT received ("${rawPort}"). Using 3000`);
    }
} else {
    console.warn("⚠️ No PORT provided. Using 3000");
}

// --- 3. RESEND (GRACEFUL INIT) ---
let resend = null;

if (process.env.RESEND_API_KEY && process.env.RESEND_API_KEY.trim() !== "") {
    try {
        resend = new Resend(process.env.RESEND_API_KEY.trim());
        console.log("✅ Resend initialized");
    } catch (err) {
        console.error("❌ Failed to initialize Resend:", err.message);
    }
} else {
    console.warn("⚠️ RESEND_API_KEY missing. Email disabled.");
}

// --- 4. MIDDLEWARES ---
app.use(cors());
app.use(express.json());

// --- 5. HEALTH CHECK ---
app.get('/', (req, res) => {
    res.status(200).json({
        status: 'ok',
        service: 'ETHERE4L backend',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// --- 6. API ---
app.post('/api/crear-pedido', (req, res) => {
    const { cliente, pedido } = req.body;

    if (!cliente || !pedido || !Array.isArray(pedido.items)) {
        console.warn("⚠️ Invalid payload");
        return res.status(400).json({ success: false, message: "Datos incompletos" });
    }

    const jobId = `JOB-${Date.now().toString().slice(-6)}`;

    res.json({
        success: true,
        jobId,
        message: "Pedido recibido. Procesando en segundo plano."
    });

    console.log(`🚀 [${jobId}] Pedido recibido`);

    setImmediate(() => {
        runBackgroundTask(jobId, cliente, pedido)
            .catch(err => console.error(`❌ [${jobId}] Background error:`, err));
    });
});

// --- 7. EMAIL HTML ---
function generateEmailHTML(cliente, pedido, jobId, isAdmin = false) {
    return `
    <div style="font-family: Arial, Helvetica, sans-serif; background:#f4f4f4; padding:20px;">
      <div style="max-width:600px; margin:auto; background:#ffffff; border-radius:8px; overflow:hidden;">
        
        <!-- HEADER -->
        <div style="background:#000; padding:20px; text-align:center;">
          <img src="https://ethere4l.com/assets/logo-email.png" alt="ETHERE4L" style="max-width:160px;" />
        </div>

        <!-- BODY -->
        <div style="padding:24px;">
          <h2 style="margin-top:0;">${isAdmin ? '🚨 Nuevo pedido recibido' : '🛍️ Pedido confirmado'}</h2>

          <p><strong>ID de pedido:</strong> ${jobId}</p>
          <p><strong>Cliente:</strong> ${cliente.nombre || 'No especificado'}</p>
          <p><strong>Email:</strong> ${cliente.email || 'No proporcionado'}</p>

          <hr />

          <h3>Resumen del pedido</h3>
          <ul>
            ${pedido.items.map(item => `
              <li>
                ${item.nombre} — Talla: ${item.talla || 'N/A'} × ${item.cantidad}
              </li>
            `).join('')}
          </ul>

          <p><strong>Total:</strong> $${pedido.total}</p>

          <p style="margin-top:20px;">
            📎 Se adjunta el PDF con el detalle completo de la orden.
          </p>

          ${!isAdmin ? `
          <p style="margin-top:20px;">
            Si tienes dudas, contáctanos por WhatsApp o Instagram.
          </p>
          ` : ''}

        </div>

        <!-- FOOTER -->
        <div style="background:#fafafa; padding:16px; text-align:center; font-size:12px; color:#555;">
          ETHERE4L © ${new Date().getFullYear()}<br/>
          <a href="https://ethere4l.com" style="color:#000;">ethere4l.com</a>
        </div>

      </div>
    </div>
    `;
}


// --- 8. BACKGROUND TASK ---
async function runBackgroundTask(jobId, cliente, pedido) {
    try {
        console.log(`⚙️ [${jobId}] Generando PDF...`);
        const pdfBuffer = await generatePDF(cliente, pedido);

        if (!resend) {
            console.warn(`⚠️ [${jobId}] Email skipped (Resend disabled)`);
            return;
        }

        const fromAddress = 'ETHERE4L Orders <orders@ethere4l.com>';

        /* =====================
           1️⃣ EMAIL AL ADMIN (SIEMPRE)
        ===================== */
        console.log(`✉️ [${jobId}] Enviando email al ADMIN`);

        await resend.emails.send({
            from: fromAddress,
            to: [process.env.ADMIN_EMAIL],
            subject: '🚨 Nuevo pedido recibido – ETHERE4L',
            html: generateEmailHTML(cliente, pedido, jobId, true),
            attachments: [{
                filename: `Orden_${jobId}.pdf`,
                content: pdfBuffer
            }]
        });

        /* =====================
           2️⃣ EMAIL AL CLIENTE (SI EXISTE)
        ===================== */
        if (cliente.email && cliente.email.includes('@')) {
            console.log(`✉️ [${jobId}] Enviando email al CLIENTE: ${cliente.email}`);

            await resend.emails.send({
                from: fromAddress,
                to: [cliente.email],
                subject: '🛍️ Tu pedido en ETHERE4L fue recibido',
                html: generateEmailHTML(cliente, pedido, jobId, false),
                attachments: [{
                    filename: `Orden_${jobId}.pdf`,
                    content: pdfBuffer
                }]
            });
        } else {
            console.warn(`⚠️ [${jobId}] Cliente sin email, solo admin notificado`);
        }

        console.log(`🎉 [${jobId}] Emails enviados correctamente`);

    } catch (err) {
        console.error(`🔥 [${jobId}] Crash en worker:`, err);
        console.warn(`💾 [${jobId}] Pedido backup:`, JSON.stringify({ cliente, pedido }));
    }
}

// --- 9. PDF ---
function generatePDF(cliente, pedido) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument();
        const buffers = [];

        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        doc.on('error', reject);

        doc.fontSize(20).text('ETHERE4L - Orden de Compra', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).text(`Cliente: ${cliente.nombre}`);
        doc.text(`Total: $${pedido.total}`);
        doc.end();
    });
}

// --- 10. START SERVER ---
const server = app.listen(portToUse, '0.0.0.0', () => {
    console.log("==================================");
    console.log(`🟢 Server listening on ${portToUse}`);
    console.log(`📧 Email system: ${resend ? 'ACTIVE' : 'DISABLED'}`);
    console.log("==================================");
});

// --- 11. GRACEFUL SHUTDOWN ---
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Closing server...');
    server.close(() => console.log('Server closed'));
});
