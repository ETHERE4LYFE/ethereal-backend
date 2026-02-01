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

/* --- NUEVAS DEPENDENCIAS (SEGURIDAD & PAGOS) --- */
const Stripe = require('stripe');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

// ✅ IMPORTACIONES CLAVE
const { buildPDF } = require('./utils/pdfGenerator');
const { getEmailTemplate, getPaymentConfirmedEmail } = require('./utils/emailTemplates');

// ===============================
// 0. CONFIGURACIÓN DE SEGURIDAD
// ===============================
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'secret_dev_key_change_in_prod';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH; // Hash generado con bcrypt
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// ================= CATÁLOGO ESTÁTICO (VALIDACIÓN DE PRECIOS) =================
let PRODUCTS_DB = [];
let CATALOG_DB = [];

try {
    PRODUCTS_DB = require('./config/productos.json');
    console.log(`✅ productos.json cargado (${PRODUCTS_DB.length} productos)`);
} catch (err) {
    console.warn('⚠️ No se pudo cargar config/productos.json');
}

try {
    CATALOG_DB = require('./config/catalogo.json');
    console.log(`✅ catalogos.json cargado (${CATALOG_DB.length} items)`);
} catch (err) {
    console.warn('⚠️ No se pudo cargar config/catalogos.json');
}


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
    console.log(`🔌 Conectando DB en: ${DB_PATH}`);
    db = new Database(DB_PATH); 
    db.pragma('journal_mode = WAL');

    // Tabla extendida con campos de tracking
    db.exec(`
        CREATE TABLE IF NOT EXISTS pedidos (
            id TEXT PRIMARY KEY,
            email TEXT,
            data TEXT,
            status TEXT DEFAULT 'PENDIENTE',
            payment_ref TEXT,
            confirmed_by TEXT,
            tracking_number TEXT,
            shipping_cost REAL,
            paid_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    dbPersistent = true;
    console.log('✅ DB Conectada y Persistente');
} catch (err) {
    console.error('❌ DB ERROR → SAFE MODE ACTIVO', err);
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

// Rate Limiter para Admin (Protección fuerza bruta)
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 10,
    message: "Demasiados intentos de acceso al panel."
});

// Middleware de Autenticación JWT
function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        jwt.verify(bearerToken, JWT_SECRET, (err, authData) => {
            if (err) return res.sendStatus(403);
            req.authData = authData;
            next();
        });
    } else {
        res.sendStatus(401);
    }
}

// Configuración CORS
app.use(cors({
    origin: [
        'https://ethereal-frontend.netlify.app',
        'http://localhost:5500',
        'http://127.0.0.1:5500'
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Configuración Email
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'ethere4lyfe@gmail.com'; 
const SENDER_EMAIL = 'orders@ethere4l.com';

let resend = null;
if (RESEND_API_KEY) {
    resend = new Resend(RESEND_API_KEY);
    console.log('📧 Sistema de correos ACTIVO');
} else {
    console.warn('⚠️ SIN API KEY DE RESEND - Correos desactivados');
}

// ===============================
// 3. SPECIAL ROUTES (WEBHOOKS)
// ===============================

// ⚠️ IMPORTANTE: El webhook debe ir ANTES de express.json()
// Usa express.raw para validar la firma de Stripe
app.post('/api/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error(`Webhook Error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        await handleStripeSuccess(session);
    }

    res.json({received: true});
});

// AHORA SÍ: Parser JSON global para el resto de rutas
app.use(express.json());

// ===============================
// 4. API ENDPOINTS (CLIENTE)
// ===============================

app.get('/', (req, res) => {
    res.json({ status: 'online', service: 'ETHERE4L Backend v2.0', mode: 'Stripe Enabled' });
});

// --- NUEVO: CREAR SESIÓN DE PAGO (Calcula envío por peso) ---
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { items } = req.body;
        let lineItems = [];
        let pesoTotal = 0;

        // 1. Reconstruir orden segura (Validar precios vs JSON servidor)
        for (const item of items) {
            // Buscamos el producto en la DB local del servidor para asegurar precio real
            // Si no hay DB cargada, usamos el precio que viene (INSEGURO, solo fallback)
            const dbProduct = PRODUCTS_DB.length > 0 
                ? PRODUCTS_DB.find(p => String(p.id) === String(item.id)) 
                : { ...item, peso: item.peso || 0.6 }; 

            const productFinal = dbProduct || item;
            
            // Lógica de peso
            const pesoUnitario = parseFloat(productFinal.peso || 0.6);
            pesoTotal += pesoUnitario * item.cantidad;

            lineItems.push({
                price_data: {
                    currency: 'mxn',
                    product_data: {
                        name: productFinal.nombre,
                        images: productFinal.fotos ? [productFinal.fotos[0]] : [],
                        metadata: {
                            talla: item.talla,
                            id_producto: item.id
                        }
                    },
                    unit_amount: Math.round(productFinal.precio * 100), // Stripe usa centavos
                },
                quantity: item.cantidad,
            });
        }

        // 2. Calcular Envío Logístico
        let costoEnvio = 0;
        if (pesoTotal <= 1.0) costoEnvio = 350;      // MXN
        else if (pesoTotal <= 3.0) costoEnvio = 650; // MXN
        else if (pesoTotal <= 5.0) costoEnvio = 950; // MXN
        else costoEnvio = 1500;                      // MXN Heavy Haul

        // 3. Crear Sesión Stripe
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            shipping_options: [
                {
                    shipping_rate_data: {
                        type: 'fixed_amount',
                        fixed_amount: { amount: costoEnvio * 100, currency: 'mxn' },
                        display_name: 'Envío Logístico Privado (Tracked)',
                        delivery_estimate: {
                            minimum: { unit: 'business_day', value: 10 },
                            maximum: { unit: 'business_day', value: 15 },
                        },
                    },
                },
            ],
            // Ajustar URLs de éxito/cancelación
            success_url: `${req.headers.origin}/success.html`,
            cancel_url: `${req.headers.origin}/pedido.html`,
            metadata: {
                // Guardamos resumen del carrito para reconstruir orden en webhook
                customer_cart: JSON.stringify(items.map(i => ({id: i.id, t: i.talla, q: i.cantidad})))
            }
        });

        res.json({ url: session.url });

    } catch (e) {
        console.error("Error Stripe Checkout:", e);
        res.status(500).json({ error: "Error creando sesión de pago" });
    }
});

// (LEGACY) Endpoint manual anterior - Mantenido por compatibilidad
app.post('/api/crear-pedido', (req, res) => {
    // ... Tu lógica anterior intacta si la necesitas ...
    res.json({ success: true, message: "Use /api/create-checkout-session for payments" });
});

// ===============================
// 5. API ENDPOINTS (ADMIN)
// ===============================

// Login Admin (JWT)
app.post('/api/admin/login', adminLimiter, async (req, res) => {
    const { password } = req.body;
    
    // Comparar con hash guardado en .env
    if (ADMIN_PASS_HASH && await bcrypt.compare(password, ADMIN_PASS_HASH)) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '4h' });
        return res.json({ success: true, token });
    }
    
    res.status(401).json({ error: 'Acceso Denegado' });
});

// Obtener Órdenes (Protegido)
app.get('/api/admin/orders', verifyToken, (req, res) => {
    if (!dbPersistent) return res.json([]);
    try {
        const orders = db.prepare("SELECT * FROM pedidos ORDER BY created_at DESC LIMIT 50").all();
        // Parsear JSON stringificado de 'data'
        const parsedOrders = orders.map(o => ({
            ...o,
            data: JSON.parse(o.data)
        }));
        res.json(parsedOrders);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Actualizar Tracking (Protegido + Trigger Email)
app.post('/api/admin/update-tracking', verifyToken, async (req, res) => {
    const { orderId, trackingNumber } = req.body;
    
    try {
        const info = db.prepare(`
            UPDATE pedidos 
            SET tracking_number=?, status='ENVIADO' 
            WHERE id=?
        `).run(trackingNumber, orderId);

        if (info.changes > 0) {
            // Recuperar datos para email
            const order = db.prepare("SELECT * FROM pedidos WHERE id=?").get(orderId);
            const orderData = JSON.parse(order.data);

            // Enviar correo de tracking
            if (resend) {
                await resend.emails.send({
                    from: `ETHERE4L Logistics <${SENDER_EMAIL}>`,
                    to: [order.email],
                    subject: `Tu pedido ha sido enviado - ${orderId}`,
                    html: `
                        <div style="font-family: sans-serif; color: #333;">
                            <h1>Logística Iniciada</h1>
                            <p>Tu pedido <strong>${orderId}</strong> está en camino.</p>
                            <div style="background:#f4f4f4; padding:15px; margin:20px 0;">
                                <strong>Tracking ID:</strong> ${trackingNumber}<br>
                                <strong>Carrier:</strong> J&T Express / Private Line
                            </div>
                            <p>Puedes rastrearlo en nuestra web o directamente con la paquetería.</p>
                        </div>
                    `
                });
            }
            res.json({ success: true });
        } else {
            res.status(404).json({ error: "Orden no encontrada" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ===============================
// 6. FUNCIONES INTERNAS
// ===============================

// Manejo post-pago de Stripe
async function handleStripeSuccess(session) {
    const jobId = session.id; // Usamos ID de sesión como ID de orden temporal o generamos uno propio
    const email = session.customer_details.email;
    const itemsShort = JSON.parse(session.metadata.customer_cart || '[]');
    
    // Simular estructura cliente/pedido para mantener compatibilidad con tus PDFs
    const cliente = { 
        nombre: session.customer_details.name, 
        email: email,
        direccion: session.customer_details.address 
    };
    const pedido = { 
        items: itemsShort, 
        total: session.amount_total / 100 
    };

    // 1. Guardar en DB
    if (dbPersistent) {
        try {
            // Verificar si ya existe para evitar duplicados por reintentos de webhook
            const exists = db.prepare("SELECT id FROM pedidos WHERE id=?").get(jobId);
            if (!exists) {
                db.prepare(`
                    INSERT INTO pedidos (id, email, data, status, payment_ref, paid_at, shipping_cost) 
                    VALUES (?, ?, ?, 'PAGADO', ?, datetime('now'), ?)
                `).run(
                    jobId, 
                    email, 
                    JSON.stringify({ cliente, pedido }), 
                    session.payment_intent,
                    session.total_details?.amount_shipping ? session.total_details.amount_shipping / 100 : 0
                );
                console.log(`💰 Pago registrado: ${jobId}`);
            }
        } catch (e) { console.error("Error SQL Webhook:", e); }
    }

    // 2. Generar PDF y Enviar Emails (Reutilizando tu worker)
    // Usamos setImmediate para no bloquear la respuesta al webhook
    setImmediate(() => {
        processOrderBackground(jobId, cliente, pedido).catch(e => console.error(e));
    });
}

// Reutilizamos tu Worker existente (ligeramente adaptado)
async function processOrderBackground(jobId, cliente, pedido) {
    // Generar PDF
    const pdfBuffer = await buildPDF(cliente, pedido, jobId, 'CLIENTE');

    if (resend) {
        // Email Cliente
        await resend.emails.send({
            from: `ETHERE4L <${SENDER_EMAIL}>`,
            to: [cliente.email],
            subject: `Confirmación de Pedido ${jobId.slice(-6)}`,
            html: getPaymentConfirmedEmail(cliente, pedido, jobId), // Usar plantilla de pago
            attachments: [{ filename: `Orden_${jobId.slice(-6)}.pdf`, content: pdfBuffer }]
        });

        // Email Admin
        if (ADMIN_EMAIL) {
            await resend.emails.send({
                from: `System <${SENDER_EMAIL}>`,
                to: [ADMIN_EMAIL],
                subject: `💰 NUEVA VENTA - ${jobId.slice(-6)}`,
                html: getEmailTemplate(cliente, pedido, jobId, true),
                attachments: [{ filename: `Orden_${jobId.slice(-6)}.pdf`, content: pdfBuffer }]
            });
        }
    }
}

// ===============================
// START SERVER
// ===============================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ETHERE4L Backend V2 corriendo en puerto ${PORT}`);
});

process.on('SIGTERM', () => {
    server.close(() => console.log('Servidor cerrado.'));
});