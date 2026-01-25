require('dotenv').config();
const express = require('express');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const { Resend } = require('resend');

// --- CONFIGURACIÓN ---
const app = express();
const PORT = process.env.PORT || 3000;

// Marca de agua para logs (Verificar versión en Railway)
console.log("___________________________________________________");
console.log("🚀 BOOTING: ETHERE4L BACKEND - RESEND ONLY EDITION");
console.log("🚫 PROTOCOL: NO-SMTP | ARCHITECTURE: FIRE-AND-FORGET");
console.log("___________________________________________________");

// Validación de entorno
if (!process.env.RESEND_API_KEY) {
    console.error("🚨 [FATAL] RESEND_API_KEY no encontrada. El servidor no iniciará.");
    process.exit(1);
}

const resend = new Resend(process.env.RESEND_API_KEY);

// Middlewares
app.use(cors());
app.use(express.json());

// --- ENDPOINT ---
app.post('/api/crear-pedido', (req, res) => {
    const { cliente, pedido } = req.body;

    // 1. Validación rápida
    if (!cliente || !pedido || !pedido.items) {
        console.warn("⚠️ Payload inválido recibido.");
        return res.status(400).json({ success: false, message: "Datos incompletos." });
    }

    // 2. ID de Trazabilidad (Job ID)
    const jobId = `JOB-${Date.now().toString().slice(-6)}`;

    // 3. RESPUESTA INMEDIATA (HTTP 200)
    // El frontend recibe esto en < 100ms
    res.json({
        success: true,
        message: 'Pedido recibido. Procesando PDF y Email en segundo plano.',
        jobId: jobId
    });

    console.log(`⚡ [${jobId}] Request HTTP cerrado. Iniciando background task...`);

    // 4. FIRE-AND-FORGET (Ejecución diferida)
    setImmediate(() => {
        runBackgroundTask(jobId, cliente, pedido);
    });
});

// --- BACKGROUND WORKER ---
async function runBackgroundTask(jobId, cliente, pedido) {
    try {
        console.log(`⚙️ [${jobId}] Generando PDF...`);
        
        // A. Generar PDF
        const pdfBuffer = await generatePDF(cliente, pedido);
        console.log(`✅ [${jobId}] PDF generado (${pdfBuffer.length} bytes). Enviando a Resend API...`);

        // B. Enviar Email vía HTTP (Resend)
        const { data, error } = await resend.emails.send({
            from: 'ETHERE4L <onboarding@resend.dev>', // Cambiar en producción
            to: [process.env.ADMIN_EMAIL],
            subject: `Nueva Venta: ${cliente.nombre} ($${pedido.total})`,
            html: `
                <h3>Nueva Orden ${jobId}</h3>
                <p>Cliente: ${cliente.nombre}</p>
                <p>Total: $${pedido.total}</p>
                <p>Ver adjunto.</p>
            `,
            attachments: [
                {
                    filename: `Orden_${jobId}.pdf`,
                    content: pdfBuffer
                }
            ]
        });

        if (error) {
            console.error(`🛑 [${jobId}] Resend API Error:`, error);
        } else {
            console.log(`🎉 [${jobId}] COMPLETADO. Email ID: ${data.id}`);
        }

    } catch (err) {
        console.error(`🔥 [${jobId}] CRASH EN BACKGROUND:`, err.message);
    }
}

// --- HELPER PDF ---
function generatePDF(cliente, pedido) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument();
            let buffers = [];
            doc.on('data', buffers.push.bind(buffers));
            doc.on('end', () => resolve(Buffer.concat(buffers)));
            
            doc.fontSize(20).text('ETHERE4L', { align: 'center' });
            doc.text(`Orden: ${cliente.nombre}`);
            doc.text(`Total: $${pedido.total}`);
            
            pedido.items.forEach(item => {
                doc.fontSize(12).text(`- ${item.nombre} (${item.talla})`);
            });
            
            doc.end();
        } catch (e) { reject(e); }
    });
}

app.listen(PORT, () => console.log(`🟢 Server listening on port ${PORT}`));