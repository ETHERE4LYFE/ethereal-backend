// =========================================================
// SERVER.JS - ETHERE4L BACKEND (PRODUCTION MASTER)
// =========================================================

// Cargar variables de entorno solo en local
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const { Resend } = require('resend');

// ✅ IMPORTACIONES CLAVE (CONECTAN CON TUS ARCHIVOS DE LUJO)
const { buildPDF } = require('./utils/pdfGenerator');
const { getEmailTemplate, getPaymentConfirmedEmail } = require('./utils/emailTemplates');

// ===============================
// 1. DATABASE SETUP (PERSISTENCIA)
// ===============================
const RAILWAY_VOLUME = '/app/data';
const isRailway = fs.existsSync(RAILWAY_VOLUME);
const DATA_DIR = isRailway ? RAILWAY_VOLUME : path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'orders.db');

// Asegurar que el directorio existe
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

let db;
let dbPersistent = false;

try {
    console.log(`🔌 Conectando DB en: ${DB_PATH}`);
    db = new Database(DB_PATH); // verbose quitado para limpiar logs
    db.pragma('journal_mode = WAL'); // Optimización de escritura

    // Crear tabla si no existe
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
    console.log('✅ DB Conectada y Persistente');
} catch (err) {
    console.error('❌ DB ERROR → SAFE MODE ACTIVO', err);
    // Mock DB para no crashear
    db = {
        prepare: () => ({ run: () => {}, get: () => null, all: () => [] }),
        exec: () => {}
    };
}

// ===============================
// 2. CONFIGURACIÓN APP & RESEND
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;

// Configuración CORS estricta para Netlify
app.use(cors({
    origin: [
        'https://ethereal-frontend.netlify.app', // Tu producción
        'http://localhost:5500',                // Tu local
        'http://127.0.0.1:5500'
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Configuración de Email
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'ethere4lyfe@gmail.com'; 
const SENDER_EMAIL = 'orders@ethere4l.com'; // Tu dominio verificado

let resend = null;
if (RESEND_API_KEY) {
    resend = new Resend(RESEND_API_KEY);
    console.log('📧 Sistema de correos ACTIVO');
} else {
    console.warn('⚠️ SIN API KEY DE RESEND - Correos desactivados');
}

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

    // Respuesta inmediata con "success: true" para el frontend
    res.json({ 
        success: true, 
        jobId,
        message: "Pedido procesado correctamente"
    });

    console.log(`🚀 [${jobId}] Pedido recibido. Procesando...`);

    // Background Worker
    setImmediate(() => {
        processOrderBackground(jobId, cliente, pedido)
            .catch(err => console.error(`❌ Error en Job ${jobId}:`, err));
    });
});

// CONFIRMAR PAGO
app.post('/api/confirmar-pago', (req, res) => {
    const { jobId, paymentRef, confirmedBy } = req.body;
    
    if (!jobId) return res.status(400).json({ error: 'jobId requerido' });

    // Respuesta rápida
    res.json({ success: true, message: 'Procesando confirmación' });

    setImmediate(async () => {
        try {
            if (!dbPersistent) {
                console.warn('⚠️ DB no persistente, no se puede guardar pago');
                return;
            }

            // 1. Actualizar DB
            const info = db.prepare(`
                UPDATE pedidos 
                SET status='PAGADO', paid_at=datetime('now'), payment_ref=?, confirmed_by=?
                WHERE id=?
            `).run(paymentRef || 'MANUAL', confirmedBy || 'Admin', jobId);

            if (info.changes === 0) {
                console.error(`❌ Pedido ${jobId} no encontrado para confirmar pago`);
                return;
            }

            // 2. Obtener datos para email
            const row = db.prepare("SELECT * FROM pedidos WHERE id=?").get(jobId);
            const { cliente, pedido } = JSON.parse(row.data);
            
            // 3. Enviar Email de Confirmación
            if (resend) {
                await resend.emails.send({
                    from: `ETHERE4L <${SENDER_EMAIL}>`,
                    to: [cliente.email],
                    subject: `Pago Confirmado – ${jobId}`,
                    html: getPaymentConfirmedEmail(cliente, pedido, jobId)
                });
                console.log(`💰 Pago confirmado y notificado para ${jobId}`);
            }

        } catch (e) {
            console.error("Error confirmando pago:", e);
        }
    });
});

// ===============================
// 4. BACKGROUND WORKER (LA MAGIA)
// ===============================
async function processOrderBackground(jobId, cliente, pedido) {
    // 1. Guardar en DB
    if (dbPersistent) {
        try {
            db.prepare(`
                INSERT INTO pedidos (id, email, data, status) VALUES (?, ?, ?, 'PENDIENTE')
            `).run(jobId, cliente.email, JSON.stringify({ cliente, pedido }));
            console.log(`💾 [${jobId}] Guardado en SQLite`);
        } catch (e) { console.error('Error SQL INSERT:', e); }
    }

    // 2. Generar PDFs (USANDO EL GENERADOR NUEVO CON IMÁGENES)
    // Aquí es donde sucede la mejora visual
    const pdfBuffer = await buildPDF(cliente, pedido, jobId, 'CLIENTE');
    
    // (Opcional) Generar PDF Proveedor si fuera distinto
    // const pdfProveedor = await buildPDF(cliente, pedido, jobId, 'PROVEEDOR');

    // 3. Enviar Emails
    if (resend) {
        // A. Email Cliente
        await resend.emails.send({
            from: `ETHERE4L <${SENDER_EMAIL}>`,
            to: [cliente.email],
            subject: `Orden Recibida ${jobId}`,
            html: getEmailTemplate(cliente, pedido, jobId, false),
            attachments: [{ filename: `Orden_${jobId}.pdf`, content: pdfBuffer }]
        });
        console.log(`✉️ [${jobId}] Email enviado al cliente`);

        // B. Email Admin
        if (ADMIN_EMAIL) {
            await resend.emails.send({
                from: `ETHERE4L System <${SENDER_EMAIL}>`,
                to: [ADMIN_EMAIL],
                subject: `🚨 NUEVA VENTA ${jobId}`,
                html: getEmailTemplate(cliente, pedido, jobId, true),
                attachments: [{ filename: `Orden_${jobId}.pdf`, content: pdfBuffer }]
            });
            console.log(`✉️ [${jobId}] Email enviado al admin`);
        }
    }
}

// ===============================
// START SERVER
// ===============================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ETHERE4L Backend GOLD corriendo en puerto ${PORT}`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM recibido. Cerrando...');
    server.close(() => console.log('Servidor cerrado.'));
});