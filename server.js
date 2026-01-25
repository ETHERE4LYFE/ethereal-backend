// ===============================
// ETHERE4L BACKEND – RAILWAY SAFE
// ===============================

// ⚠️ dotenv SOLO en local
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
        console.warn(`⚠️ Invalid PORT received ("${rawPort}"). Falling back to 3000`);
    }
} else {
    console.warn("⚠️ No PORT provided by Railway. Using 3000");
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
    console.warn("⚠️ RESEND_API_KEY missing. Email sending disabled.");
}

// --- 4. MIDDLEWARES ---
app.use(cors());
app.use(express.json());

// --- 5. HEALTH CHECK (CRÍTICO PARA RAILWAY) ---
app.get('/', (req, res) => {
    res.status(200).send('🟢 ETHERE4L Backend Online');
});

// --- 6. API ---
app.post('/api/crear-pedido', (req, res) => {
    const { cliente, pedido } = req.body;

    if (!cliente || !pedido || !Array.isArray(pedido.items)) {
        console.warn("⚠️ Invalid payload received");
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

// --- 7. BACKGROUND TASK ---
async function runBackgroundTask(jobId, cliente, pedido) {
    try {
        // 1. Generación de PDF (Independiente)
        console.log(`⚙️ [${jobId}] Generando PDF...`);
        const pdfBuffer = await generatePDF(cliente, pedido);
        
        // 2. Lógica de Enrutamiento de Email
        // Si no hay dominio verificado, Resend SOLO permite enviar al dueño de la cuenta.
        const isProductionDomainVerified = process.env.DOMAIN_VERIFIED === 'true'; 
        
        const recipient = isProductionDomainVerified 
            ? cliente.email // Producción real (requiere dominio verificado)
            : process.env.ADMIN_EMAIL; // Fallback Sandbox (siempre al admin)

        const emailSubject = isProductionDomainVerified
            ? `Confirmación de Pedido - ETHERE4L`
            : `[SANDBOX] Nuevo Pedido de ${cliente.nombre}`; // Subject claro para debug

        console.log(`✉️ [${jobId}] Enviando email a: ${recipient} (Modo: ${isProductionDomainVerified ? 'PROD' : 'SANDBOX'})`);

        const { data, error } = await resend.emails.send({
            from: 'ETHERE4L <ventas@ethere4l.com>', // En Prod cambiar a: ventas@tudominio.com
            to: [recipient], 
            // Si estamos en Sandbox, agregamos Bcc al admin para asegurar que llegue
            // Ojo: En Sandbox 'to' y 'bcc' deben ser correos verificados/propios.
            subject: emailSubject,
            html: generateEmailHTML(cliente, pedido), // Tu helper HTML
            attachments: [{ filename: `Orden_${jobId}.pdf`, content: pdfBuffer }]
        });

        if (error) {
            // Log estructurado del error 403 u otros
            console.error(`🛑 [${jobId}] Error Resend [${error.name}]: ${error.message}`);
            // Aquí confirmamos que el PDF se generó pero falló el envío.
        } else {
            console.log(`🎉 [${jobId}] Email enviado. ID: ${data.id}`);
        }
        if (error) {
    console.error(`🛑 [${jobId}] FALLO ENVÍO EMAIL. ERROR: ${error.message}`);
    // DUMP DE SEGURIDAD:
    console.warn(`💾 [${jobId}] DATA BACKUP:`, JSON.stringify({ cliente, pedido }));
}

    } catch (err) {
        console.error(`🔥 [${jobId}] Crash en Worker:`, err);
    }
}

// --- 8. PDF HELPER ---
function generatePDF(cliente, pedido) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument();
        const buffers = [];

        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        doc.on('error', reject);

        doc.fontSize(20).text('ETHERE4L - Orden', { align: 'center' });
        doc.moveDown();
        doc.text(`Cliente: ${cliente.nombre}`);
        doc.text(`Total: $${pedido.total}`);

        doc.end();
    });
}

app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'ETHERE4L backend',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});


// --- 9. START SERVER ---
const server = app.listen(portToUse, '0.0.0.0', () => {
    console.log("==================================");
    console.log(`🟢 Server listening on ${portToUse}`);
    console.log(`📧 Email system: ${resend ? 'ACTIVE' : 'DISABLED'}`);
    console.log("==================================");
});

// --- 10. GRACEFUL SHUTDOWN ---
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down...');
    server.close(() => console.log('Server closed'));
});
