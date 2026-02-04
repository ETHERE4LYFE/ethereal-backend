// =========================================================
// SERVER.JS - ETHERE4L BACKEND (PRODUCTION MASTER - NaN FIXED)
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

/* --- DEPENDENCIAS (SEGURIDAD & PAGOS) --- */
const Stripe = require('stripe');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');


// ✅ IMPORTACIONES CLAVE
const { buildPDF } = require('./utils/pdfGenerator');
const {
    getEmailTemplate,
    getPaymentConfirmedEmail,
    getMagicLinkEmail
} = require('./utils/emailTemplates');


// ===============================
// 0. CONFIGURACIÓN DE SEGURIDAD
// ===============================
// .trim() es vital para evitar errores de conexión con Stripe
const stripe = Stripe((process.env.STRIPE_SECRET_KEY || '').trim());
const JWT_SECRET = process.env.JWT_SECRET || 'secret_dev_key_change_in_prod';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH; 
const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || '').trim();

// RATE LIMITER: MAGIC LINK
const magicLinkLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 5,
    message: "Demasiadas solicitudes. Intenta más tarde."
});





// ===============================
// 0.1 HELPER: SANITIZACIÓN NUMÉRICA (NUEVO - FIX NaN)
// ===============================
/**
 * Convierte cualquier entrada (texto con $, null, undefined) a un número flotante seguro.
 * Evita que Stripe crashee con "Invalid integer: NaN".
 */
function parseSafeNumber(value, fallback = 0) {
    if (typeof value === 'number' && !isNaN(value)) return value;
    if (!value) return fallback;
    // Eliminar todo lo que no sea número o punto (ej: "$2,800.00" -> "2800.00")
    const cleanString = String(value).replace(/[^0-9.]/g, '');
    const number = parseFloat(cleanString);
    return isNaN(number) ? fallback : number;
}

// ===============================
// 0.2 HELPER: TOKEN PASSWORDLESS POR PEDIDO
// ===============================
function generateOrderToken(orderId, email) {
    return jwt.sign(
        { o: orderId, e: email },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}


// ================= CATÁLOGO ESTÁTICO (VALIDACIÓN DE PRECIOS) =================
let PRODUCTS_DB = [];
let CATALOG_DB = [];

try {
    PRODUCTS_DB = require('./config/productos.json');
    console.log(`✅ productos.json cargado (${PRODUCTS_DB.length} productos)`);
} catch (err) {
    console.warn('⚠️ No se pudo cargar config/productos.json - Usando fallback frontend');
}

try {
    CATALOG_DB = require('./config/catalogo.json');
    console.log(`✅ catalogo.json cargado (${CATALOG_DB.length} items)`);
} catch (err) {
    console.warn('⚠️ No se pudo cargar config/catalogo.json');
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
    
    // ===============================
    // MIGRACIÓN SEGURA DE COLUMNAS (Railway-safe)
    // ===============================
    try {
        const columns = db
            .prepare(`PRAGMA table_info(pedidos)`)
            .all()
            .map(col => col.name);

        if (!columns.includes('tracking_number')) {
            db.exec(`ALTER TABLE pedidos ADD COLUMN tracking_number TEXT`);
            console.log('🧱 Columna tracking_number añadida');
        }

        if (!columns.includes('shipping_cost')) {
            db.exec(`ALTER TABLE pedidos ADD COLUMN shipping_cost REAL`);
            console.log('🧱 Columna shipping_cost añadida');
        }
    } catch (e) {
        console.error('⚠️ Error en migración segura:', e.message);
    }



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
/* ===============================
   FIX CRÍTICO RAILWAY + RATE LIMIT
   =============================== */
app.set('trust proxy', 1);

// ===============================
// OBSERVABILIDAD: LOGGER ESTRUCTURADO
// ===============================
const logger = {
    info: (msg, ctx = {}) =>
        console.log(`[INFO] ${new Date().toISOString()} | ${msg} | ${JSON.stringify(ctx)}`),
    warn: (msg, ctx = {}) =>
        console.warn(`[WARN] ${new Date().toISOString()} | ${msg} | ${JSON.stringify(ctx)}`),
    error: (msg, ctx = {}) =>
        console.error(`[ERROR] ${new Date().toISOString()} | ${msg} | ${JSON.stringify(ctx)}`)
};



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


// ===============================
// OBSERVABILIDAD: REQUEST CORRELATION
// ===============================
app.use((req, res, next) => {
    req.requestId = `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const start = Date.now();

    res.on('finish', () => {
        logger.info('HTTP_REQUEST', {
            requestId: req.requestId,
            method: req.method,
            path: req.originalUrl,
            status: res.statusCode,
            ip: req.ip,
            durationMs: Date.now() - start
        });
    });

    next();
});

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

// --- NUEVO: CREAR SESIÓN DE PAGO (CORREGIDO ERR_INVALID_CHAR + NaN FIX) ---
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { items, customer } = req.body;
        
        // 1. DEFINICIÓN SEGURA DEL DOMINIO
        const FRONTEND_URL = process.env.FRONTEND_URL || req.headers.origin || 'https://ethereal-frontend.netlify.app';

        let lineItems = [];
        let pesoTotal = 0;

        // 2. Reconstruir orden segura
        for (const item of items) {
            // Buscamos el producto en la DB local del servidor
            const dbProduct = PRODUCTS_DB.length > 0 
                ? PRODUCTS_DB.find(p => String(p.id) === String(item.id)) 
                : null; // Si no hay DB, es null

            // Fallback al item del frontend si no hay DB
            const productFinal = dbProduct || item;
            
            // --- FIX CRÍTICO NaN: SANITIZAR VALORES ---
            // Aseguramos que el precio sea un número puro (sin '$' ni texto)
            const rawPrice = dbProduct ? dbProduct.precio : item.precio;
            const precioLimpio = parseSafeNumber(rawPrice, 0);
            
            // Aseguramos que el peso sea un número
            const pesoLimpio = parseSafeNumber(productFinal.peso, 0.6);
            pesoTotal += pesoLimpio * item.cantidad;

            // --- Sanitización de imágenes ---
            let productImages = [];
            if (dbProduct && dbProduct.fotos && dbProduct.fotos.length > 0) {
                 // Prioridad: Fotos del servidor
                 productImages = [dbProduct.fotos[0]];
            } else if (item.imagen && item.imagen.startsWith('http')) { 
                // Fallback: Foto del frontend
                productImages = [item.imagen];
            }

            lineItems.push({
                price_data: {
                    currency: 'mxn',
                    product_data: {
                        name: productFinal.nombre,
                        images: productImages, // Array limpio
                        metadata: {
                            talla: item.talla,
                            id_producto: item.id
                        }
                    },
                    // Usamos el precio limpio multiplicado por 100
                    unit_amount: Math.round(precioLimpio * 100), 
                },
                quantity: parseSafeNumber(item.cantidad, 1),
            });
            }




        // 3. Calcular Envío Logístico
        // ... (dentro de /api/create-checkout-session, después del loop for)

        // 3. LOGICA DE ENVÍO COMERCIAL (Items + Peso)
        // Regla: 1 item ($45 USD), 2 items ($50 USD), 3 items ($65 USD), 4+ (Tarifa plana/gratis)
        // Asumiendo TC aprox 20 MXN por USD
        
        const totalItems = items.reduce((acc, item) => acc + item.cantidad, 0);
        let costoEnvio = 0;

        if (totalItems === 1) {
            costoEnvio = 900; // ~$45 USD (Envío unitario caro)
        } else if (totalItems === 2) {
            costoEnvio = 1000; // ~$50 USD (Baja considerablemente por pieza)
        } else if (totalItems === 3) {
            costoEnvio = 1300; // ~$65 USD
        } else {
            // 4+ Piezas (Lote grande): 
            // Opción A: Cobrar un cap (ej. 1500 MXN)
            // Opción B: Envío Gratis (descomentar si aplica)
            // costoEnvio = 0; 
            costoEnvio = 1500; // ~$75 USD Cap de Heavy Haul
        }

        // Safety Check: Si el peso es extraordinario (>10kg) cobrar extra
        if (pesoTotal > 10.0) {
            costoEnvio += 500; // Sobrecargo por exceso de dimensiones
        }

        // ... (continuar con session = await stripe...)

        // 4. Preparar Metadata (Sanitizada para evitar overflow)
        const metadata = {
            customer_cart_summary: JSON.stringify(items.map(i => `${i.id}(${i.cantidad})`)).substring(0, 500)
        };

        if (customer) {
            metadata.customer_email = customer.email || '';
            try {
                const customerString = JSON.stringify(customer);
                if (customerString.length < 450) {
                    metadata.customer_info = customerString;
                } else {
                    metadata.customer_info = JSON.stringify({
                        nombre: customer.nombre,
                        email: customer.email
                    });
                }
            } catch (e) {
                console.warn("Error serializando metadata cliente", e);
            }
        }

        // 5. Crear Sesión Stripe
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            customer_email: customer?.email, 
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
            success_url: `${FRONTEND_URL}/success.html`,
            cancel_url: `${FRONTEND_URL}/pedido.html`,
            metadata: metadata
        });

        res.json({ url: session.url });

    } catch (e) {
        console.error("❌ Error Stripe Checkout:", e);
        res.status(500).json({ error: "Error creando sesión de pago: " + e.message });
    }
});

// (LEGACY) Endpoint manual anterior
app.post('/api/crear-pedido', (req, res) => {
    res.json({ success: true, message: "Use /api/create-checkout-session for payments" });
});


// ===============================
// 4.1 API TRACKING (SESSION-LOCKED)
// ===============================
const trackingLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: "Demasiadas solicitudes de tracking."
});

app.get('/api/orders/track/:orderId', trackingLimiter, (req, res) => {
    const { orderId } = req.params;

    // 🔐 Authorization Header obligatorio
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Authorization requerido' });
    }

    const token = authHeader.split(' ')[1];

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch {
        return res.status(401).json({ error: 'Token inválido o expirado' });
    }

    if (!dbPersistent) {
        return res.status(503).json({ error: 'DB no disponible' });
    }

    // 🔎 Buscar pedido
    const orderRow = db.prepare(`
        SELECT id, email, status, tracking_number, shipping_cost, data
        FROM pedidos
        WHERE id = ?
    `).get(orderId);

    if (!orderRow) {
        return res.status(404).json({ error: 'Orden no encontrada' });
    }

    // 🔒 Seguridad: el pedido debe pertenecer al email del token
    if (orderRow.email !== decoded.email && decoded.scope !== 'read_orders') {
        return res.status(403).json({ error: 'Acceso denegado' });
    }

    // 🧠 Parse defensivo
    let parsedData = {};
    try {
        parsedData = JSON.parse(orderRow.data);
    } catch {
        parsedData = {};
    }

    res.json({
        id: orderRow.id,
        status: orderRow.status,
        tracking_number: orderRow.tracking_number,
        carrier: orderRow.carrier_code || null,
        tracking_history: orderRow.tracking_history
            ? JSON.parse(orderRow.tracking_history)
            : [],
        shipping_cost: orderRow.shipping_cost,
        data: orderRow.data, // 👈 necesario para tu hydration layer
        total: parsedData?.pedido?.total || 0,
        date: orderRow.created_at
    });
});



// ===============================
// 5. API ENDPOINTS (ADMIN)
// ===============================

// Login Admin (JWT)
app.post('/api/admin/login', adminLimiter, async (req, res) => {
    try {
        const { password } = req.body;

        // LOG CLAVE: confirma que el request YA NO MUERE en rate-limit
        console.log(`🔐 Admin login attempt | IP: ${req.ip}`);

        if (!process.env.ADMIN_PASS_HASH || !process.env.JWT_SECRET) {
            console.error("❌ Faltan ADMIN_PASS_HASH o JWT_SECRET en Railway");
            return res.status(500).json({ error: 'Server misconfigured' });
        }

        // LIMPIEZA CRÍTICA (evita espacios invisibles)
        const cleanPassword = String(password || '').trim();
        const cleanHash = String(process.env.ADMIN_PASS_HASH).trim();

        const match = await bcrypt.compare(cleanPassword, cleanHash);

        if (!match) {
            console.warn("⛔ Password incorrecto");
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        console.log("✅ Login correcto, generando JWT");

        const token = jwt.sign(
            { role: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '4h' }
        );

        return res.json({ success: true, token });

    } catch (err) {
        console.error("💥 Error login admin:", err);
        return res.status(500).json({ error: 'Login error' });
    }
});



app.post('/api/magic-link', magicLinkLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        const cleanEmail = String(email || '').trim().toLowerCase();

        if (!cleanEmail || !cleanEmail.includes('@')) {
            return res.json({ success: true });
        }

        const hasOrders = db
            .prepare("SELECT 1 FROM pedidos WHERE email = ? LIMIT 1")
            .get(cleanEmail);

        if (hasOrders && resend) {
            const magicToken = jwt.sign(
                { email: cleanEmail, scope: 'read_orders' },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            const FRONTEND_URL =
                process.env.FRONTEND_URL || 'https://ethereal-frontend.netlify.app';

            const link = `${FRONTEND_URL}/mis-pedidos.html?token=${magicToken}`;

            await resend.emails.send({
                from: `ETHERE4L <${SENDER_EMAIL}>`,
                to: [cleanEmail],
                subject: "Accede a tus pedidos – ETHERE4L",
                html: getMagicLinkEmail(link)
            });

            logger.info('MAGIC_LINK_SENT', { email: cleanEmail });
        }

        // 🔐 Respuesta SIEMPRE positiva (anti-enumeración)
        res.json({ success: true });

    } catch (err) {
        logger.error('MAGIC_LINK_ERROR', { error: err.message });
        res.json({ success: true });
    }
});


app.get('/api/my-orders', (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.sendStatus(401);

    const token = auth.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.scope !== 'read_orders') {
            return res.sendStatus(403);
        }

        const orders = db.prepare(`
            SELECT id, status, created_at, data, tracking_number
            FROM pedidos
            WHERE email = ?
            ORDER BY created_at DESC
        `).all(decoded.email);

        const response = orders.map(row => {
            const parsed = JSON.parse(row.data);

            const orderToken = generateOrderToken(
                row.id,
                decoded.email
            );

            return {
                id: row.id,
                status: row.status,
                date: row.created_at,
                total: parsed.pedido.total,
                item_count: parsed.pedido.items.length,
                tracking_number: row.tracking_number,
                access_token: orderToken
            };
        });

        res.json({ orders: response });

    } catch (err) {
        console.error('My orders error:', err);
        res.sendStatus(403);
    }
});



// Obtener Órdenes (Protegido)
app.get('/api/admin/orders', verifyToken, (req, res) => {
    if (!dbPersistent) return res.json([]);
    try {
        const orders = db.prepare("SELECT * FROM pedidos ORDER BY created_at DESC LIMIT 50").all();
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
            const order = db.prepare("SELECT * FROM pedidos WHERE id=?").get(orderId);
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
// 6. FUNCIONES INTERNAS (WEBHOOK LOGIC)
// ===============================

// Manejo post-pago de Stripe
async function handleStripeSuccess(session) {
    const start = Date.now();
logger.info('WEBHOOK_START', {
    orderId: session.id,
    amount: session.amount_total
});

    const jobId = session.id; 
    const email = session.customer_details.email; // Email confirmado por Stripe
    const itemsShort = JSON.parse(session.metadata.customer_cart_summary || '[]'); 
    
    // 1. RECONSTRUCCIÓN INTELIGENTE DEL CLIENTE
    let cliente = {};
    if (session.metadata.customer_info) {
        try {
            cliente = JSON.parse(session.metadata.customer_info);
            cliente.email = email; 
        } catch (e) {
            console.warn("Error parseando customer_info de metadata", e);
        }
    }

    if (!cliente.nombre) cliente.nombre = session.customer_details.name;
    if (!cliente.direccion) cliente.direccion = session.customer_details.address;
    if (!cliente.email) cliente.email = email;

    const pedido = { 
        items: itemsShort, 
        total: session.amount_total / 100 
    };

    // 2. Guardar en DB
    if (dbPersistent) {
        try {
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
                console.log(`💰 Pago registrado y guardado: ${jobId}`);
            }
            } catch (e) {
                logger.error('DB_WRITE_ERROR', {
                    orderId: jobId,
                    error: e.message
    });
}

    }

    // 3. Generar PDF y Enviar Emails
    setImmediate(() => {
        processOrderBackground(jobId, cliente, pedido).catch(e => console.error(e));
    });
}

// Reutilizamos tu Worker existente
async function processOrderBackground(jobId, cliente, pedido) {
    const pdfBuffer = await buildPDF(cliente, pedido, jobId, 'CLIENTE');

    const accessToken = generateOrderToken(jobId, cliente.email);
    const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ethereal-frontend.netlify.app';
    const trackingUrl = `${FRONTEND_URL}/pedido.html?order=${jobId}&token=${accessToken}`;

    if (resend) {
        await resend.emails.send({
            from: `ETHERE4L <${SENDER_EMAIL}>`,
            to: [cliente.email],
            subject: `Confirmación de Pedido ${jobId.slice(-6)}`,
            html: getPaymentConfirmedEmail(cliente, pedido, jobId, trackingUrl),
            attachments: [
                { filename: `Orden_${jobId.slice(-6)}.pdf`, content: pdfBuffer }
            ]
        });

        if (ADMIN_EMAIL) {
            await resend.emails.send({
                from: `System <${SENDER_EMAIL}>`,
                to: [ADMIN_EMAIL],
                subject: `💰 NUEVA VENTA - ${jobId.slice(-6)}`,
                html: getEmailTemplate(cliente, pedido, jobId, true),
                attachments: [
                    { filename: `Orden_${jobId.slice(-6)}.pdf`, content: pdfBuffer }
                ]
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




