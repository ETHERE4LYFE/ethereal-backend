require('dotenv').config();
const express = require('express');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const { Resend } = require('resend');

// --- CONFIGURACIÓN ---
const app = express();
const PORT = process.env.PORT || 3000;

// Logs de arranque
console.log("___________________________________________________");
console.log("🚀 BOOTING: ETHERE4L BACKEND - RESEND ONLY EDITION");
console.log("🚫 PROTOCOL: NO-SMTP | ARCHITECTURE: FIRE-AND-FORGET");
console.log("___________________________________________________");

// Detectar entorno real
const isRailway = !!process.env.RAILWAY_ENVIRONMENT;
const isProduction = process.env.NODE_ENV === 'production';

// Validación SEGURA de variables (NO rompe build)
let resend = null;

if (isProduction && isRailway && !process.env.RESEND_API_KEY) {
    console.error("🚨 [FATAL] RESEND_API_KEY no encontrada en producción.");
    process.exit(1);
}

if (process.env.RESEND_API_KEY) {
    resend = new Resend(process.env.RESEND_API_KEY);
} else {
    console.warn("⚠️ RESEND_API_KEY no detectada (modo build / local).");
}

if (!process.env.ADMIN_EMAIL) {
    console.warn("⚠️ ADMIN_EMAIL no configurado. Emails no serán enviados.");
}

// Middlewares
app.use(cors());
app.use(express.json());

// --- ENDPOINT PRINCIPAL ---
app.post('/api/crear-pedido', (req, res) => {
    const { cliente, pedido } = req.body;

    if (!cliente || !pedido || !pedido.items) {
        console.warn("⚠️ Payload inválido recibido.");
        return res.status(400).json({
            success: false,
            message: "Datos incompletos."
        });
    }

    const jobId = `JOB-${Date.now().toString().slice(-6)}`;

    // RESPUESTA INMEDIATA
    res.json({
        success: true,
        message: 'Pedido recibido. Procesando en segundo plano.',
        jobId
    });

    console.log(`⚡ [${jobId}] HTTP cerrado. Lanzando background task...`);

    setImmediate(() => {
        runBackgroundTask(jobId, cliente, pedido);
    });
});

// --- WORKER DE FONDO ---
async function runBackgroundTask(jobId, cliente, pedido) {
    try {
        console.log(`⚙️ [${jobId}] Generando PDF...`);
        const pdfBuffer = await generatePDF(cliente, pedido);
        console.log(`✅ [${jobId}] PDF generado (${pdfBuffer.length} bytes)`);

        // Si no hay configuración de email, TERMINAMOS AQUÍ (sin error)
        if (!resend || !process.env.ADMIN_EMAIL) {
            console.warn(`⚠️ [${jobId}] Email omitido (configuración incompleta).`);
            return;
        }

        console.log(`📨 [${jobId}] Enviando email vía Resend...`);

        const { data, error } = await resend.emails.send({
            from: 'ETHERE4L <onboarding@resend.dev>', // cambiar cuando tengas dominio
            to: process.env.ADMIN_EMAIL,
            subject: `Nueva Venta: ${cliente.nombre} ($${pedido.total})`,
            html: `
                <h3>Nueva Orden ${jobId}</h3>
                <p><strong>Cliente:</strong> ${cliente.nombre}</p>
                <p><strong>Total:</strong> $${pedido.total}</p>
                <p>Ver PDF adjunto.</p>
            `,
            attachments: [
                {
                    filename: `Orden_${jobId}.pdf`,
                    content: pdfBuffer
                }
            ]
        });

        if (error) {
            console.error(`🛑 [${jobId}] Resend Error:`, error);
        } else {
            console.log(`🎉 [${jobId}] Email enviado. ID: ${data.id}`);
        }

    } catch (err) {
        console.error(`🔥 [${jobId}] Error en background task:`, err);
    }
}

// --- GENERADOR DE PDF ---
function generatePDF(cliente, pedido) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument();
            const buffers = [];

            doc.on('data', buffers.push.bind(buffers));
            doc.on('end', () => resolve(Buffer.concat(buffers)));

            doc.fontSize(20).text('ETHERE4L', { align: 'center' });
            doc.moveDown();
            doc.fontSize(12).text(`Cliente: ${cliente.nombre}`);
            doc.text(`Total: $${pedido.total}`);
            doc.moveDown();

            pedido.items.forEach(item => {
                doc.text(`• ${item.nombre} (${item.talla})`);
            });

            doc.end();
        } catch (e) {
            reject(e);
        }
    });
}

// --- PROTECCIÓN GLOBAL ---
process.on('unhandledRejection', reason => {
    console.error('🔥 Unhandled Rejection:', reason);
});

process.on('uncaughtException', err => {
    console.error('🔥 Uncaught Exception:', err);
});

// Health check
app.get('/', (req, res) => {
    res.send('🟢 ETHERE4L Backend Online');
});

// Start
app.listen(PORT, () => {
    console.log(`🟢 Server listening on port ${PORT}`);
});
