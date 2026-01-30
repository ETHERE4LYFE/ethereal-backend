// =========================================================
// SERVER.JS - ETHERE4L BACKEND (FINAL PRODUCTION)
// =========================================================

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const { Resend } = require('resend');

// ✅ IMPORTANTE: Conectamos con tus archivos de lujo
const { buildPDF } = require('./utils/pdfGenerator');
const { getEmailTemplate, getPaymentConfirmedEmail } = require('./utils/emailTemplates');

// ===============================
// 1. DATABASE SETUP (PERSISTENCIA)
// ===============================
const RAILWAY_VOLUME = '/app/data';
const isRailway = fs.existsSync(RAILWAY_VOLUME);
const DATA_DIR = isRailway ? RAILWAY_VOLUME : path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'orders.db');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

let db;
let dbPersistent = false;

try {
    db = new Database(DB_PATH, { verbose: console.log });
    db.pragma('journal_mode = WAL');

    db.exec(`
        CREATE TABLE IF NOT EXISTS pedidos (
            id TEXT PRIMARY KEY,
            email TEXT,
            data TEXT,
            status TEXT DEFAULT 'PENDIENTE',
            payment_ref TEXT,
            confirmed_by TEXT,
            paid_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    dbPersistent = true;
    console.log(`✅ DB Conectada en: ${DB_PATH}`);
} catch (err) {
    console.error('❌ DB ERROR → SAFE MODE ACTIVO', err);
    db = {
        prepare: () => ({ run: () => {}, get: () => null, all: () => [] }),
        exec: () => {}
    };
}

// ===============================
// 2. APP CONFIG
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;

// Configuración CORS para Netlify
app.use(cors({
    origin: [
        'https://ethereal-frontend.netlify.app',
        'http://localhost:5500'
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());

// Resend Config
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'ethere4lyfe@gmail.com';
const SENDER_EMAIL = 'orders@ethere4l.com'; // Tu dominio verificado
const resend = new Resend(RESEND_API_KEY);

// ===============================
// 3. API ENDPOINTS
// ===============================

// Health Check
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'ETHERE4L Backend',
        version: 'Production Gold',
        db: dbPersistent ? 'PERSISTENT' : 'MEMORY_ONLY'
    });
});

// CREAR PEDIDO
app.post('/api/crear-pedido', (req, res) => {
    const { cliente, pedido } = req.body;

    if (!cliente || !pedido) {
        return res.status(400).json({ success: false, message: 'Datos incompletos' });
    }

    const jobId = `ORD-${Date.now().toString().slice(-6)}`;

    // Respuesta rápida al frontend
    res.json({ 
        success: true, 
        jobId,
        message: "Pedido procesado correctamente"
    });

    // Procesar en background
    setImmediate(() => {
        processOrder(jobId, cliente, pedido)
            .catch(err => console.error(`❌ Error en Job ${jobId}:`, err));
    });
});

// CONFIRMAR PAGO
app.post('/api/confirmar-pago', (req, res) => {
    const { jobId, paymentRef, confirmedBy } = req.body;
    
    if (!jobId) return res.status(400).json({ error: 'jobId requerido' });

    res.json({ success: true, message: 'Confirmación iniciada' });

    setImmediate(async () => {
        try {
            if (!dbPersistent) return;

            // Actualizar DB
            const info = db.prepare(`
                UPDATE pedidos 
                SET status='PAGADO', paid_at=datetime('now'), payment_ref=?, confirmed_by=?
                WHERE id=?
            `).run(paymentRef || 'MANUAL', confirmedBy || 'Admin', jobId);

            if (info.changes > 0) {
                // Enviar correo de confirmación
                const row = db.prepare("SELECT * FROM pedidos WHERE id=?").get(jobId);
                const { cliente, pedido } = JSON.parse(row.data);
                
                await resend.emails.send({
                    from: `ETHERE4L <${SENDER_EMAIL}>`,
                    to: [cliente.email],
                    subject: `Pago Confirmado – ${jobId}`,
                    html: getPaymentConfirmedEmail(cliente, pedido, jobId)
                });
                console.log(`💰 Pago confirmado para ${jobId}`);
            }
        } catch (e) {
            console.error("Error confirmando pago:", e);
        }
    });
});

// ===============================
// 4. BACKGROUND WORKER (MAGIA AQUÍ)
// ===============================
async function processOrder(jobId, cliente, pedido) {
    console.log(`⚙️ Procesando pedido ${jobId}...`);

    // 1. Guardar en DB
    if (dbPersistent) {
        try {
            db.prepare(`
                INSERT INTO pedidos (id, email, data, status) VALUES (?, ?, ?, 'PENDIENTE')
            `).run(jobId, cliente.email, JSON.stringify({ cliente, pedido }));
        } catch (e) { console.error('Error guardando DB:', e); }
    }

    // 2. Generar PDFs (USANDO EL GENERADOR DE LUJO)
    // Aquí es donde llamamos al archivo utils/pdfGenerator.js
    const pdfBuffer = await buildPDF(cliente, pedido, jobId, 'CLIENTE');
    
    // (Opcional) PDF Proveedor si lo necesitas diferente
    // const pdfProveedor = await buildPDF(cliente, pedido, jobId, 'PROVEEDOR');

    // 3. Enviar Emails
    if (RESEND_API_KEY) {
        
        // Email Cliente
        await resend.emails.send({
            from: `ETHERE4L <${SENDER_EMAIL}>`,
            to: [cliente.email],
            subject: `Orden Recibida ${jobId}`,
            html: getEmailTemplate(cliente, pedido, jobId, false),
            attachments: [{ filename: `Orden_${jobId}.pdf`, content: pdfBuffer }]
        });

        // Email Admin
        if (ADMIN_EMAIL) {
            await resend.emails.send({
                from: `ETHERE4L System <${SENDER_EMAIL}>`,
                to: [ADMIN_EMAIL],
                subject: `🚨 NUEVA VENTA ${jobId}`,
                html: getEmailTemplate(cliente, pedido, jobId, true),
                attachments: [{ filename: `Orden_${jobId}.pdf`, content: pdfBuffer }]
            });
        }
        console.log(`✅ Emails enviados para ${jobId}`);
    }
}

// ===============================
// START
// ===============================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ETHERE4L Backend GOLD corriendo en puerto ${PORT}`);
});