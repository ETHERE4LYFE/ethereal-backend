require('dotenv').config();
const express = require('express');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');

const app = express();

// --- 0. DIAGNÓSTICO DE VARIABLES DE ENTORNO ---
// Esto se ejecuta al iniciar para validar que Railway tenga las llaves
const requiredEnv = ['EMAIL_USER', 'EMAIL_PASS', 'ADMIN_EMAIL'];
const missingEnv = requiredEnv.filter(key => !process.env[key]);

if (missingEnv.length > 0) {
    console.error("❌ ERROR CRÍTICO DE CONFIGURACIÓN:");
    console.error(`Faltan las siguientes variables de entorno: ${missingEnv.join(', ')}`);
    console.error("El envío de correos fallará hasta que se configuren en Railway.");
} else {
    console.log("✅ Variables de entorno de correo detectadas correctamente.");
}

// 1. Middlewares
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("🔥 Backend ETHERE4L activo y funcionando. Logs activados.");
});

// 2. Configuración de Email (Nodemailer)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verificación de conexión SMTP al arrancar
transporter.verify(function (error, success) {
    if (error) {
        console.error("❌ Error de conexión SMTP (Gmail):", error.message);
    } else {
        console.log("✅ Servidor listo para enviar correos (SMTP OK).");
    }
});

// 3. Ruta Principal: Crear Pedido
app.post('/api/crear-pedido', async (req, res) => {
    console.log("📥 Recibiendo solicitud de pedido...");

    try {
        // --- A. VALIDACIÓN DEL PAYLOAD (Datos recibidos) ---
        const { cliente, pedido } = req.body;

        // Logs de depuración (Debug)
        // console.log("Payload recibido:", JSON.stringify(req.body, null, 2));

        if (!cliente || !cliente.nombre) {
            throw new Error("Datos del cliente incompletos o faltantes.");
        }
        if (!pedido || !pedido.items || !Array.isArray(pedido.items)) {
            throw new Error("Estructura del pedido inválida (faltan items o no es array).");
        }

        console.log(`📦 Procesando pedido para: ${cliente.nombre} | Total: $${pedido.total}`);

        // --- B. GENERACIÓN DEL PDF ---
        let pdfBuffer;
        try {
            const doc = new PDFDocument({ margin: 50 });
            let buffers = [];

            doc.on('data', buffers.push.bind(buffers));
            
            // --- DISEÑO DEL PDF ---
            // Encabezado
            doc.fontSize(20).font('Helvetica-Bold').text('ETHERE4L', { align: 'center' });
            doc.fontSize(10).font('Helvetica').text('Orden de Compra', { align: 'center' });
            doc.moveDown();
            doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
            doc.moveDown();

            // Datos Cliente
            doc.fontSize(12).font('Helvetica-Bold').text('Datos del Cliente:');
            doc.fontSize(10).font('Helvetica');
            doc.text(`Nombre: ${cliente.nombre}`);
            doc.text(`Teléfono: ${cliente.telefono || 'N/A'}`);
            doc.text(`Dirección: ${cliente.direccion || 'N/A'}`);
            if(cliente.notas) doc.text(`Notas: ${cliente.notas}`);
            doc.moveDown();

            // Items
            doc.fontSize(12).font('Helvetica-Bold').text('Detalle del Pedido:', { underline: true });
            doc.moveDown(0.5);

            pedido.items.forEach((item) => {
                const y = doc.y;
                // Sanitización visual por si llega undefined
                const nombreItem = item.nombre || "Producto sin nombre";
                const tallaItem = item.talla || "N/A";
                const precioItem = item.precio || 0;
                
                doc.fontSize(10).font('Helvetica-Bold').text(`• ${nombreItem}`, 50, y);
                doc.font('Helvetica').text(`Talla: ${tallaItem}`, 50, y + 12);
                doc.text(`Cant: ${item.cantidad}`, 300, y);
                doc.text(`$${precioItem}`, 400, y);
                doc.moveDown(2);
            });

            doc.moveDown();
            doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
            doc.moveDown();

            // Total
            doc.fontSize(14).font('Helvetica-Bold').text(`TOTAL A PAGAR: $${pedido.total || 0}`, { align: 'right' });

            // Footer
            doc.moveDown(2);
            doc.fontSize(10).font('Helvetica-Oblique').fillColor('red');
            doc.text('NOTA IMPORTANTE:', { align: 'center' });
            doc.fillColor('black').font('Helvetica');
            doc.text('Realiza tu transferencia a la cuenta enviada por Instagram/WhatsApp.', { align: 'center' });

            doc.end();

            // Esperar buffer completo
            pdfBuffer = await new Promise((resolve, reject) => {
                doc.on('end', () => resolve(Buffer.concat(buffers)));
                doc.on('error', reject);
            });
            console.log("📄 PDF Generado correctamente en memoria.");

        } catch (pdfError) {
            console.error("🔥 Error generando PDF:", pdfError);
            throw new Error("Fallo al generar el archivo PDF de la orden.");
        }

        // --- C. ENVÍO DE EMAIL ---
        try {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: process.env.ADMIN_EMAIL,
                subject: `🔔 NUEVA VENTA - ${cliente.nombre} ($${pedido.total})`,
                html: `
                    <h3>¡Nueva venta en ETHERE4L!</h3>
                    <p><strong>Cliente:</strong> ${cliente.nombre}</p>
                    <p><strong>Total:</strong> $${pedido.total}</p>
                    <p>Revisa el PDF adjunto.</p>
                `,
                attachments: [
                    {
                        filename: `Orden-${cliente.nombre.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`, // Nombre seguro
                        content: pdfBuffer
                    }
                ]
            };

            await transporter.sendMail(mailOptions);
            console.log("✉️ Correo enviado al administrador.");

        } catch (mailError) {
            console.error("🔥 Error enviando Email:", mailError);
            // IMPORTANTE: Si es error de auth, lo decimos explícitamente
            if (mailError.code === 'EAUTH') {
                throw new Error("Error de autenticación con Gmail. Verifica EMAIL_PASS en Railway.");
            }
            throw new Error(`Fallo al enviar el correo: ${mailError.message}`);
        }

        // ÉXITO TOTAL
        res.json({ success: true, message: 'Pedido procesado correctamente.' });

    } catch (error) {
        console.error('❌ Error fatal en /api/crear-pedido:', error.message);
        
        // Devolvemos el mensaje REAL al frontend para que sepas qué pasó
        res.status(500).json({ 
            success: false, 
            message: error.message || 'Error interno desconocido.'
        });
    }
});

// 4. Iniciar Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor ETHERE4L corriendo en puerto ${PORT}`);
});