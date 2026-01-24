require('dotenv').config();
const express = require('express');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');

const app = express();
app.get("/", (req, res) => {
  res.send("🔥 Backend ETHERE4L activo y funcionando");
});


// 1. Middlewares
app.use(cors()); // Permite conexiones desde cualquier origen (Netlify/Localhost)
app.use(express.json());

// 2. Configuración de Email (Nodemailer)
const transporter = nodemailer.createTransport({
    service: 'gmail', // Puedes usar 'outlook', 'yahoo', etc.
    auth: {
        user: process.env.EMAIL_USER, // Tu correo (lo configuraremos en el siguiente paso)
        pass: process.env.EMAIL_PASS  // Tu contraseña de aplicación
    }
});

// 3. Ruta Principal: Crear Pedido
app.post('/api/crear-pedido', async (req, res) => {
    try {
        const { cliente, pedido } = req.body;
        console.log(`📦 Nuevo pedido recibido de: ${cliente.nombre}`);

        // --- A. GENERACIÓN DEL PDF EN MEMORIA ---
        const doc = new PDFDocument({ margin: 50 });
        let buffers = [];
        
        // Capturar los "chunks" del PDF en un buffer
        doc.on('data', buffers.push.bind(buffers));
        
        // --- DISEÑO DEL PDF ---
        
        // 1. Encabezado
        doc.fontSize(20).font('Helvetica-Bold').text('ETHERE4L', { align: 'center' });
        doc.fontSize(10).font('Helvetica').text('Orden de Compra', { align: 'center' });
        doc.moveDown();
        doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke(); // Línea separadora
        doc.moveDown();

        // 2. Datos del Cliente
        doc.fontSize(12).font('Helvetica-Bold').text('Datos del Cliente:');
        doc.fontSize(10).font('Helvetica');
        doc.text(`Nombre: ${cliente.nombre}`);
        doc.text(`Teléfono: ${cliente.telefono}`);
        doc.text(`Dirección: ${cliente.direccion}`);
        if(cliente.notas) doc.text(`Notas: ${cliente.notas}`);
        doc.moveDown();

        // 3. Tabla de Productos
        doc.fontSize(12).font('Helvetica-Bold').text('Detalle del Pedido:', { underline: true });
        doc.moveDown(0.5);

        pedido.items.forEach((item, index) => {
            const y = doc.y;
            
            // Nombre y Talla
            doc.fontSize(10).font('Helvetica-Bold').text(`• ${item.nombre}`, 50, y);
            doc.font('Helvetica').text(`Talla: ${item.talla}`, 50, y + 12);
            
            // Cantidad y Precio
            doc.text(`Cant: ${item.cantidad}`, 300, y);
            doc.text(`$${item.precio}`, 400, y);
            
            doc.moveDown(2); // Espacio entre items
        });

        doc.moveDown();
        doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke(); // Línea final
        doc.moveDown();

        // 4. Total
        doc.fontSize(14).font('Helvetica-Bold').text(`TOTAL A PAGAR: $${pedido.total}`, { align: 'right' });

        // 5. Instrucciones de Pago
        doc.moveDown(2);
        doc.fontSize(10).font('Helvetica-Oblique').fillColor('red');
        doc.text('NOTA IMPORTANTE:', { align: 'center' });
        doc.fillColor('black').font('Helvetica');
        doc.text('Realiza tu transferencia a la cuenta enviada por Instagram/WhatsApp.', { align: 'center' });
        doc.text('Envía comprobante junto con este PDF.', { align: 'center' });

        // Finalizar PDF
        doc.end();

        // --- B. ESPERAR A QUE EL PDF TERMINE ---
        const pdfData = await new Promise((resolve) => {
            doc.on('end', () => {
                const result = Buffer.concat(buffers);
                resolve(result);
            });
        });

        // --- C. ENVIAR CORREO AL ADMIN ---
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL, // Tu correo personal donde recibes las ventas
            subject: `🔔 NUEVA VENTA - ${cliente.nombre} ($${pedido.total})`,
            html: `
                <h3>¡Nueva venta en ETHERE4L!</h3>
                <p><strong>Cliente:</strong> ${cliente.nombre}</p>
                <p><strong>Total:</strong> $${pedido.total}</p>
                <p>Adjunto encontrarás la orden de compra en PDF.</p>
            `,
            attachments: [
                {
                    filename: `Orden-${cliente.nombre.replace(/ /g, '_')}.pdf`,
                    content: pdfData
                }
            ]
        };

        await transporter.sendMail(mailOptions);

        // Responder al Frontend con éxito
        res.json({ success: true, message: 'Pedido creado y notificado.' });

    } catch (error) {
        console.error('Error en el servidor:', error);
        res.status(500).json({ success: false, message: 'Error interno al procesar el pedido.' });
    }
});

// 4. Iniciar Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor ETHERE4L corriendo en puerto ${PORT}`);
});