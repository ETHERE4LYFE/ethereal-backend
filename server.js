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
function generateEmailHTML(cliente, pedido, jobId) {
    return `
        <div style="font-family: Arial, sans-serif;">
            <h2>🛍️ Confirmación de pedido - ETHERE4L</h2>
            <p><strong>ID:</strong> ${jobId}</p>
            <p><strong>Cliente:</strong> ${cliente.nombre || 'N/A'}</p>
            <p><strong>Email:</strong> ${cliente.email || 'N/A'}</p>
            <hr />
            <ul>
                ${pedido.items.map(item => `
                    <li>${item.nombre} × ${item.cantidad}</li>
                `).join('')}
            </ul>
            <p><strong>Total:</strong> $${pedido.total}</p>
            <p>📎 PDF adjunto con el detalle de tu orden.</p>
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

        // 🔐 EMAIL SEGURO (NUNCA undefined)
        const clientEmail =
            typeof cliente.email === 'string' && cliente.email.includes('@')
                ? cliente.email
                : null;

        const recipient = clientEmail || process.env.ADMIN_EMAIL;

        const subject = clientEmail
            ? 'Confirmación de Pedido - ETHERE4L'
            : `[ADMIN] Nuevo pedido recibido - ${jobId}`;

        console.log(`✉️ [${jobId}] Enviando email a ${recipient}`);

        const { error } = await resend.emails.send({
            from: 'ETHERE4L <ventas@ethere4l.com>',
            to: recipient,
            subject,
            html: generateEmailHTML(cliente, pedido, jobId),
            attachments: [{
                filename: `Orden_${jobId}.pdf`,
                content: pdfBuffer
            }]
        });

        if (error) {
            console.error(`🛑 [${jobId}] Email error: ${error.message}`);
            console.warn(`💾 [${jobId}] Pedido backup:`, JSON.stringify({ cliente, pedido }));
        } else {
            console.log(`🎉 [${jobId}] Email enviado correctamente`);
        }

    } catch (err) {
        console.error(`🔥 [${jobId}] Crash en worker:`, err);
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
