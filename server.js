require('dotenv').config();
const express = require('express');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const { Resend } = require('resend');

// --- 1. CONFIGURACIÓN Y SEGURIDAD ---
const app = express();
const PORT = process.env.PORT || 3000;

// Validación estricta al inicio
const requiredEnv = ['RESEND_API_KEY', 'ADMIN_EMAIL'];
const missingEnv = requiredEnv.filter(key => !process.env[key]);

if (missingEnv.length > 0) {
    console.error(`🚨 [FATAL] Faltan variables: ${missingEnv.join(', ')}`);
    process.exit(1);
}

const resend = new Resend(process.env.RESEND_API_KEY);

// Middlewares
app.use(cors());
app.use(express.json());

// --- 2. MANEJO DE ERRORES GLOBALES (CRÍTICO PARA BACKGROUND TASKS) ---
// Evita que el servidor se reinicie si una tarea de fondo falla
process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 [CRITICAL] Unhandled Rejection at:', promise, 'reason:', reason);
    // No salimos del proceso, solo logueamos para mantener vivo el servidor
});

process.on('uncaughtException', (error) => {
    console.error('🔥 [CRITICAL] Uncaught Exception:', error);
});

// Health Check
app.get("/", (req, res) => res.send("🟢 Backend ETHERE4L (Robust Mode) Online"));

// --- 3. ENDPOINT PRINCIPAL (OPTIMIZADO) ---
app.post('/api/crear-pedido', (req, res) => {
    const { cliente, pedido } = req.body;

    // A. Validación Sincrónica
    if (!cliente || !pedido || !pedido.items) {
        console.warn("⚠️ [REJECT] Payload inválido recibido.");
        return res.status(400).json({ success: false, message: "Datos incompletos." });
    }

    // B. Generar ID de Tarea para Trazabilidad
    const jobId = `JOB-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    // C. RESPUESTA INMEDIATA (The "Fire" part)
    // Respondemos antes de hacer nada pesado
    res.status(200).json({ 
        success: true, 
        message: "Pedido recibido. Procesando en segundo plano.",
        jobId: jobId 
    });

    console.log(`🚀 [${jobId}] Request HTTP completado. Iniciando Handover...`);

    // D. EJECUCIÓN DIFERIDA (The "Forget" part)
    // setImmediate garantiza que esto corra EN EL SIGUIENTE TICK del Event Loop
    // Esto asegura que la conexión HTTP ya se cerró completamente.
    setImmediate(() => {
        processBackgroundOrder(jobId, cliente, pedido);
    });
});

/**
 * 4. WORKER INTERNO (Lógica de Negocio)
 * Ejecuta PDF y Email de forma aislada y segura.
 */
async function processBackgroundOrder(jobId, cliente, pedido) {
    console.log(`⚙️ [${jobId}] 1. Iniciando Worker Interno...`);

    try {
        // PASO 1: Generar PDF
        const startPdf = Date.now();
        const pdfBuffer = await generatePDFSafe(jobId, cliente, pedido);
        console.log(`✅ [${jobId}] 2. PDF Generado (${Date.now() - startPdf}ms) | Tamaño: ${pdfBuffer.length} bytes`);

        // PASO 2: Enviar Email
        console.log(`ep [${jobId}] 3. Intentando enviar email a ${process.env.ADMIN_EMAIL}...`);
        
        const { data, error } = await resend.emails.send({
            from: 'ETHERE4L <onboarding@resend.dev>', // Cambiar a tu dominio verificado en prod
            to: [process.env.ADMIN_EMAIL],
            subject: `NUEVA VENTA: ${cliente.nombre} ($${pedido.total})`,
            html: generateEmailHTML(cliente, pedido),
            attachments: [
                {
                    filename: `Orden_${cliente.nombre.replace(/[^a-zA-Z0-9]/g, '_')}_${jobId}.pdf`,
                    content: pdfBuffer
                }
            ]
        });

        if (error) {
            console.error(`⚠️ [${jobId}] Error devuelto por API Resend:`, error);
        } else {
            console.log(`🎉 [${jobId}] 4. PROCESO COMPLETADO EXITOSAMENTE. Email ID: ${data.id}`);
        }

    } catch (err) {
        // Captura errores catastróficos dentro del worker para no ensuciar el log global
        console.error(`❌ [${jobId}] FALLO EN TAREA DE FONDO:`, err.message);
        console.error(err.stack);
    }
}

// --- 5. HELPERS (Robustecidos) ---

function generatePDFSafe(jobId, cliente, pedido) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({ margin: 50 });
            let buffers = [];

            // Manejo de errores del stream interno de PDFKit
            doc.on('error', (err) => {
                console.error(`🔥 [${jobId}] Error interno PDFKit:`, err);
                reject(err);
            });

            doc.on('data', buffers.push.bind(buffers));
            doc.on('end', () => resolve(Buffer.concat(buffers)));

            // --- CONTENIDO PDF ---
            doc.fontSize(20).font('Helvetica-Bold').text('ETHERE4L', { align: 'center' });
            doc.fontSize(10).text(`Orden Ref: ${jobId}`, { align: 'center' });
            doc.moveDown();
            
            doc.fontSize(12).font('Helvetica-Bold').text('Cliente:');
            doc.fontSize(10).font('Helvetica').text(`Nombre: ${cliente.nombre}`);
            doc.text(`Tel: ${cliente.telefono}`);
            doc.text(`Dir: ${cliente.direccion}`);
            if(cliente.notas) doc.text(`Notas: ${cliente.notas}`);
            doc.moveDown();

            doc.fontSize(12).font('Helvetica-Bold').text('Items:');
            pedido.items.forEach(item => {
                // Sanitización por si viene null
                const nombre = item.nombre || "Item";
                const precio = item.precio || 0;
                doc.fontSize(10).text(`• ${nombre} (${item.talla}) x${item.cantidad} - $${precio}`);
            });
            
            doc.moveDown();
            doc.fontSize(14).font('Helvetica-Bold').text(`TOTAL: $${pedido.total}`, { align: 'right' });
            
            doc.end(); // Finalizar stream explícitamente

        } catch (e) {
            reject(e);
        }
    });
}

function generateEmailHTML(cliente, pedido) {
    return `
        <div style="font-family: sans-serif; padding: 20px;">
            <h2 style="color: #000;">Nueva Orden Recibida</h2>
            <p><strong>Cliente:</strong> ${cliente.nombre}</p>
            <p><strong>Teléfono:</strong> ${cliente.telefono}</p>
            <p><strong>Total:</strong> $${pedido.total}</p>
            <hr/>
            <p style="color: #666;">El detalle completo se encuentra en el PDF adjunto.</p>
        </div>
    `;
}

// Iniciar Servidor
app.listen(PORT, () => {
    console.log(`✅ Servidor ETHERE4L (Deterministic Queue) corriendo en puerto ${PORT}`);
});