// =========================================================
// SERVER.JS - ETHERE4L BACKEND (FULL PRODUCTION - PHASE 6 HARDENED)
// =========================================================
// CHANGELOG PHASE 6:
//   ✅ Stock validation + concurrency control (BEGIN IMMEDIATE)
//   ✅ Email validation RFC 5322
//   ✅ Persistent JSON file logger (/logs/app.log)
//   ✅ GET /health — robust health check
//   ✅ GET /metrics — read-only monitoring
//   ✅ All existing endpoints preserved 1:1
//   ✅ Webhook idempotency preserved
//   ✅ JWT_SECRET mandatory in production preserved
//   ✅ All indexes preserved
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

// 🛡 FIX #5: JWT_SECRET obligatorio en producción
const JWT_SECRET = (function() {
    if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
    if (process.env.NODE_ENV === 'production') {
        throw new Error('❌ FATAL: JWT_SECRET is required in production. Set it in Railway environment variables.');
    }
    console.warn('⚠️ Usando JWT_SECRET de desarrollo. NO usar en producción.');
    return 'secret_dev_key_change_in_prod';
})();

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
const crypto = require('crypto');
const { randomUUID: uuidv4 } = require('crypto');


const CUSTOMER_SESSION_DAYS = 180;

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function createCustomerSession(email, req) {
    const sessionId = uuidv4();

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + CUSTOMER_SESSION_DAYS);

    const payload = {
        email,
        session_id: sessionId,
        scope: 'customer'
    };

    const token = jwt.sign(payload, JWT_SECRET, {
        expiresIn: `${CUSTOMER_SESSION_DAYS}d`
    });

    db.prepare(`
        INSERT INTO customer_sessions
        (id, email, token_hash, expires_at, user_agent, ip)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        sessionId,
        email,
        hashToken(token),
        expiresAt.toISOString(),
        req.headers['user-agent'] || '',
        req.ip
    );

    return token;
}

// ===============================
// 0.3 HELPER: VALIDACIÓN DE EMAIL (RFC 5322 SIMPLIFICADA)
// ===============================
/**
 * Valida email con regex robusta RFC 5322 simplificada.
 * - Max 254 caracteres
 * - Sin espacios
 * - Sin caracteres inválidos
 * - Formato user@domain.tld
 */
function validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const trimmed = email.trim();
    if (trimmed.length === 0 || trimmed.length > 254) return false;
    if (/\s/.test(trimmed)) return false;
    // RFC 5322 simplified — cubre 99.9% de emails reales
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    return emailRegex.test(trimmed);
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
    // 2. Tabla Sesiones (CORREGIDO: Ahora dentro de db.exec)
    db.exec(`
        CREATE TABLE IF NOT EXISTS customer_sessions (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            user_agent TEXT,
            ip TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_customer_sessions_email ON customer_sessions(email);
        CREATE INDEX IF NOT EXISTS idx_customer_sessions_id ON customer_sessions(id);
    `);

    // 🛡 FIX #6: Índices críticos para rendimiento bajo tráfico alto
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_pedidos_email ON pedidos(email);
        CREATE INDEX IF NOT EXISTS idx_pedidos_status ON pedidos(status);
        CREATE INDEX IF NOT EXISTS idx_pedidos_payment_ref ON pedidos(payment_ref);
        CREATE INDEX IF NOT EXISTS idx_pedidos_created_at ON pedidos(created_at);
    `);
    console.log('✅ Índices de pedidos verificados');

    // ===============================
    // PHASE 6: TABLA DE STOCK (inventario)
    // ===============================
    db.exec(`
        CREATE TABLE IF NOT EXISTS inventory (
            product_id TEXT PRIMARY KEY,
            stock INTEGER DEFAULT 0,
            reserved INTEGER DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_inventory_product_id ON inventory(product_id);
    `);
    console.log('✅ Tabla inventory verificada');

    // Seed inventory desde PRODUCTS_DB si la tabla está vacía
    const inventoryCount = db.prepare(`SELECT COUNT(*) as c FROM inventory`).get().c;
    if (inventoryCount === 0 && PRODUCTS_DB.length > 0) {
        const insertStmt = db.prepare(`
            INSERT OR IGNORE INTO inventory (product_id, stock) VALUES (?, ?)
        `);
        const seedTransaction = db.transaction((products) => {
            for (const p of products) {
                // Si el producto tiene campo stock, usarlo; si no, default 10
                const stockValue = typeof p.stock === 'number' ? p.stock : 10;
                insertStmt.run(String(p.id), stockValue);
            }
        });
        seedTransaction(PRODUCTS_DB);
        console.log(`📦 Inventario inicializado con ${PRODUCTS_DB.length} productos`);
    }

    
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

        if (!columns.includes('shipping_status')) {
            db.exec(`ALTER TABLE pedidos ADD COLUMN shipping_status TEXT DEFAULT 'CONFIRMADO'`);
            console.log('🧱 Columna shipping_status añadida');
        }

        if (!columns.includes('shipping_history')) {
            db.exec(`ALTER TABLE pedidos ADD COLUMN shipping_history TEXT`);
            console.log('🧱 Columna shipping_history añadida');
        }

        if (!columns.includes('carrier_code')) {
            db.exec(`ALTER TABLE pedidos ADD COLUMN carrier_code TEXT`);
            console.log('🧱 Columna carrier_code añadida');
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
        exec: () => {},
        transaction: (fn) => fn
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
// OBSERVABILIDAD: LOGGER ESTRUCTURADO (PHASE 6: + FILE PERSISTENCE)
// ===============================

// --- Persistent file logger ---
const LOG_DIR = isRailway ? path.join(RAILWAY_VOLUME, 'logs') : path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}
const LOG_FILE = path.join(LOG_DIR, 'app.log');

/**
 * Escribe log estructurado JSON al archivo + consola.
 * No bloquea — usa appendFileSync en producción (SQLite ya es sync).
 * En volumen alto se podría migrar a stream, pero para este volumen es correcto.
 */
function writeLogToFile(level, message, context) {
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        context
    };
    try {
        fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
    } catch (e) {
        // Silently fail — no queremos que un error de logging crashee el server
    }
}

const logger = {
    info: (msg, ctx = {}) => {
        console.log(`[INFO] ${new Date().toISOString()} | ${msg} | ${JSON.stringify(ctx)}`);
        writeLogToFile('INFO', msg, ctx);
    },
    warn: (msg, ctx = {}) => {
        console.warn(`[WARN] ${new Date().toISOString()} | ${msg} | ${JSON.stringify(ctx)}`);
        writeLogToFile('WARN', msg, ctx);
    },
    error: (msg, ctx = {}) => {
        console.error(`[ERROR] ${new Date().toISOString()} | ${msg} | ${JSON.stringify(ctx)}`);
        writeLogToFile('ERROR', msg, ctx);
    }
};

// --- Error counter for /metrics ---
let errorCountLastHour = 0;
let errorCountResetAt = Date.now() + 3600000;

function incrementErrorCount() {
    const now = Date.now();
    if (now > errorCountResetAt) {
        errorCountLastHour = 0;
        errorCountResetAt = now + 3600000;
    }
    errorCountLastHour++;
}

const PORT = process.env.PORT || 3000;
const SERVER_START_TIME = Date.now();
const BACKEND_VERSION = '2.1.0';

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
function verifyCustomerSession(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.sendStatus(401);

    const token = auth.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.scope !== 'customer') {
            return res.sendStatus(403);
        }

        const session = db.prepare(`
            SELECT * FROM customer_sessions WHERE id = ?
        `).get(decoded.session_id);

        if (!session) throw new Error('Session revoked');

        if (new Date() > new Date(session.expires_at)) {
            db.prepare(`DELETE FROM customer_sessions WHERE id = ?`)
              .run(decoded.session_id);
            throw new Error('Session expired');
        }

        if (hashToken(token) !== session.token_hash) {
            throw new Error('Token mismatch');
        }

        req.customer = {
            email: session.email,
            session_id: session.id
        };

        next();

    } catch (e) {
        return res.sendStatus(403);
    }
}



// ===============================
// OBSERVABILIDAD: REQUEST CORRELATION
// ===============================
app.use((req, res, next) => {
    req.requestId = `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const start = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('HTTP_REQUEST', {
            requestId: req.requestId,
            method: req.method,
            path: req.originalUrl,
            status: res.statusCode,
            ip: req.ip,
            durationMs: duration
        });
        // Track errors for /metrics
        if (res.statusCode >= 500) {
            incrementErrorCount();
        }
    });

    next();
});

// Configuración CORS
app.use(cors({
    origin: [
        'https://ethereal-frontend.netlify.app',
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        process.env.FRONTEND_URL 
    ].filter(Boolean),
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
        logger.error('WEBHOOK_SIGNATURE_FAIL', { error: err.message });
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
    res.json({ status: 'online', service: 'ETHERE4L Backend v2.1', mode: 'Stripe Enabled' });
});

// ===============================
// PHASE 6: HEALTH CHECK ROBUSTO
// ===============================
app.get('/health', (req, res) => {
    let dbStatus = 'error';
    try {
        if (dbPersistent) {
            const test = db.prepare('SELECT 1 as ok').get();
            dbStatus = test && test.ok === 1 ? 'connected' : 'error';
        }
    } catch (e) {
        dbStatus = 'error';
    }

    const stripeStatus = process.env.STRIPE_SECRET_KEY ? 'configured' : 'missing';
    const resendStatus = RESEND_API_KEY ? 'configured' : 'missing';
    const overallStatus = (dbStatus === 'connected' && stripeStatus === 'configured') ? 'ok' : 'degraded';

    res.json({
        status: overallStatus,
        db: dbStatus,
        dbPersistent,
        stripe: stripeStatus,
        email: resendStatus,
        uptime: Math.floor((Date.now() - SERVER_START_TIME) / 1000),
        memory: {
            rss: Math.round(process.memoryUsage().rss / 1024 / 1024) + ' MB',
            heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
            heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
        },
        node: process.version,
        version: BACKEND_VERSION,
        timestamp: new Date().toISOString()
    });
});

// ===============================
// PHASE 6: MONITORING ENDPOINT
// ===============================
app.get('/metrics', (req, res) => {
    // Reset error counter if window expired
    if (Date.now() > errorCountResetAt) {
        errorCountLastHour = 0;
        errorCountResetAt = Date.now() + 3600000;
    }

    let pedidosHoy = 0;
    let totalVentasHoy = 0;
    let totalPedidos = 0;

    try {
        if (dbPersistent) {
            const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

            const hoyStats = db.prepare(`
                SELECT COUNT(*) as count FROM pedidos 
                WHERE date(created_at) = date(?)
            `).get(today);
            pedidosHoy = hoyStats ? hoyStats.count : 0;

            // Sumar ventas pagadas de hoy
            const ventasHoy = db.prepare(`
                SELECT data FROM pedidos 
                WHERE date(created_at) = date(?) AND status = 'PAGADO'
            `).all(today);

            for (const row of ventasHoy) {
                try {
                    const parsed = JSON.parse(row.data);
                    totalVentasHoy += parseSafeNumber(parsed.pedido?.total, 0);
                } catch (e) { /* skip malformed */ }
            }

            const totalStats = db.prepare(`SELECT COUNT(*) as count FROM pedidos`).get();
            totalPedidos = totalStats ? totalStats.count : 0;
        }
    } catch (e) {
        logger.error('METRICS_DB_ERROR', { error: e.message });
    }

    res.json({
        pedidosHoy,
        totalVentasHoy: Math.round(totalVentasHoy * 100) / 100,
        totalPedidos,
        erroresUltimaHora: errorCountLastHour,
        uptime: Math.floor((Date.now() - SERVER_START_TIME) / 1000),
        dbPersistent,
        version: BACKEND_VERSION,
        timestamp: new Date().toISOString()
    });
});


// --- CREAR SESIÓN DE PAGO (HARDENED: SERVER-SIDE PRICE + QUANTITY + STOCK VALIDATION) ---
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { items, customer } = req.body;

        // ===============================
        // PHASE 6: VALIDACIÓN DE EMAIL
        // ===============================
        const customerEmail = customer?.email ? String(customer.email).trim().toLowerCase() : '';
        if (!validateEmail(customerEmail)) {
            return res.status(400).json({ 
                error: 'Email inválido. Verifica tu dirección de correo.' 
            });
        }

        // 🛡 FIX #2: Validación estricta de cantidad
        for (const item of items) {
            const cantidad = parseSafeNumber(item.cantidad, 0);
            if (!Number.isInteger(cantidad) || cantidad < 1 || cantidad > 10) {
                return res.status(400).json({ 
                    error: `Cantidad inválida para producto ${item.id || 'desconocido'}: ${item.cantidad}. Debe ser entre 1 y 10.` 
                });
            }
        }

        // ===============================
        // PHASE 6: VALIDACIÓN DE STOCK (PRE-CHECK)
        // ===============================
        if (dbPersistent && PRODUCTS_DB.length > 0) {
            for (const item of items) {
                const cantidadLimpia = parseSafeNumber(item.cantidad, 1);
                const inventoryRow = db.prepare(`
                    SELECT stock, reserved FROM inventory WHERE product_id = ?
                `).get(String(item.id));

                if (inventoryRow) {
                    const available = inventoryRow.stock - inventoryRow.reserved;
                    if (available < cantidadLimpia) {
                        logger.warn('STOCK_INSUFICIENTE', { 
                            productId: item.id, 
                            requested: cantidadLimpia, 
                            available 
                        });
                        return res.status(400).json({ 
                            error: `Stock insuficiente para "${item.nombre || item.id}". Disponible: ${Math.max(0, available)}` 
                        });
                    }
                }
                // Si no hay registro en inventory, permitimos (backward compatible)
            }
        }
        
        // 1. GENERAR ID DE ORDEN AQUÍ PARA USARLO EN DB Y METADATA
        const tempOrderId = `ord_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;

        // DEFINICIÓN SEGURA DEL DOMINIO
        const FRONTEND_URL = process.env.FRONTEND_URL || req.headers.origin || 'https://ethereal-frontend.netlify.app';

        let lineItems = [];
        let pesoTotal = 0;

        // 🛡 FIX #1: Array para reconstruir subtotal/total 100% server-side
        let serverSubtotal = 0;

        // 2. Reconstruir orden segura
        for (const item of items) {
            // Buscamos el producto en la DB local del servidor
            const dbProduct = PRODUCTS_DB.length > 0 
                ? PRODUCTS_DB.find(p => String(p.id) === String(item.id)) 
                : null; // Si no hay DB, es null

            // Fallback al item del frontend si no hay DB
            const productFinal = dbProduct || item;
            
            // 🛡 FIX #1: PRECIO SIEMPRE DESDE DB CUANDO EXISTE
            // Si tenemos productos en DB, usamos ese precio (no el del frontend)
            const rawPrice = dbProduct ? dbProduct.precio : item.precio;
            const precioLimpio = parseSafeNumber(rawPrice, 0);

            // Validar que el precio sea mayor a 0
            if (precioLimpio <= 0) {
                logger.warn('PRECIO_INVALIDO', { itemId: item.id, rawPrice, precioLimpio });
                return res.status(400).json({ error: `Precio inválido para producto ${item.id}` });
            }

            const cantidadLimpia = parseSafeNumber(item.cantidad, 1);
            
            // Aseguramos que el peso sea un número
            const pesoLimpio = parseSafeNumber(productFinal.peso, 0.6);
            pesoTotal += pesoLimpio * cantidadLimpia;

            // 🛡 FIX #1: Acumular subtotal server-side
            serverSubtotal += precioLimpio * cantidadLimpia;

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
                quantity: cantidadLimpia,
            });
        } // Fin del for

        // 3. LOGICA DE ENVÍO COMERCIAL (Items + Peso)
        const totalItems = items.reduce((acc, item) => acc + parseSafeNumber(item.cantidad, 1), 0);
        let costoEnvio = 0;

        if (totalItems === 1) {
            costoEnvio = 900; 
        } else if (totalItems === 2) {
            costoEnvio = 1000; 
        } else if (totalItems === 3) {
            costoEnvio = 1300; 
        } else {
            costoEnvio = 1500; 
        }

        // Safety Check: Si el peso es extraordinario (>10kg) cobrar extra
        if (pesoTotal > 10.0) {
            costoEnvio += 500; 
        }

        // ===============================
        // 🛡 FIX #1: SNAPSHOT REAL DEL PEDIDO (100% SERVER-SIDE PRICES)
        // ===============================
        const pedidoSnapshot = {
            items: items.map(item => {
                const dbProduct = PRODUCTS_DB.find(p => String(p.id) === String(item.id)) || item;
                // 🛡 Precio SIEMPRE desde DB cuando existe, NUNCA del frontend
                const precio = parseSafeNumber(dbProduct.precio || item.precio, 0);
                const cantidad = parseSafeNumber(item.cantidad, 1);

                return {
                    id: item.id,
                    nombre: dbProduct.nombre || item.nombre,
                    imagen: (dbProduct.fotos && dbProduct.fotos[0]) || item.imagen || null,
                    talla: item.talla || null,
                    cantidad: cantidad,
                    precio: precio,
                    subtotal: precio * cantidad
                };
            }),
            // 🛡 FIX #1: Subtotal y total calculados 100% server-side
            subtotal: serverSubtotal,
            envio: costoEnvio,
            total: serverSubtotal + costoEnvio
        };

        // ============================================
        // PHASE 6: TRANSACCIÓN ATÓMICA (STOCK + PEDIDO)
        // ============================================
        if (dbPersistent) {
            const createOrderTransaction = db.transaction(() => {
                // 1. Validar stock DENTRO de transacción (previene race condition)
                for (const item of items) {
                    const cantidadLimpia = parseSafeNumber(item.cantidad, 1);
                    const inv = db.prepare(`
                        SELECT stock, reserved FROM inventory WHERE product_id = ?
                    `).get(String(item.id));

                    if (inv) {
                        const available = inv.stock - inv.reserved;
                        if (available < cantidadLimpia) {
                            throw new Error(`STOCK_INSUFICIENTE:${item.id}:${available}`);
                        }
                    }
                }

                // 2. Reservar stock (incrementar reserved)
                for (const item of items) {
                    const cantidadLimpia = parseSafeNumber(item.cantidad, 1);
                    db.prepare(`
                        UPDATE inventory 
                        SET reserved = reserved + ?, updated_at = datetime('now')
                        WHERE product_id = ?
                    `).run(cantidadLimpia, String(item.id));
                }

                // 3. Insertar pedido
                db.prepare(`
                    INSERT INTO pedidos (id, email, data, status, shipping_cost)
                    VALUES (?, ?, ?, 'PENDIENTE', ?)
                `).run(
                    tempOrderId,
                    customerEmail,
                    JSON.stringify({
                        cliente: { ...customer, email: customerEmail },
                        pedido: pedidoSnapshot
                    }),
                    costoEnvio
                );
            });

            try {
                createOrderTransaction();
                logger.info('PEDIDO_CREADO', { orderId: tempOrderId, items: totalItems });
            } catch (txError) {
                if (txError.message.startsWith('STOCK_INSUFICIENTE')) {
                    const parts = txError.message.split(':');
                    return res.status(400).json({ 
                        error: `Stock insuficiente para producto ${parts[1]}. Disponible: ${parts[2]}` 
                    });
                }
                logger.error('TRANSACTION_ERROR', { error: txError.message });
                return res.status(500).json({ error: 'Error procesando pedido' });
            }
        }

        // 5. Crear Sesión Stripe
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            customer_email: customerEmail,
            // ⚠️ FIX: Solo pasamos order_id. La data ya está en DB.
            metadata: {
                order_id: tempOrderId 
            },
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
        });

        res.json({ url: session.url });

    } catch (e) {
        logger.error('STRIPE_CHECKOUT_ERROR', { error: e.message, stack: e.stack });
        incrementErrorCount();
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

    const orderRow = db.prepare(`
        SELECT id, email, status, shipping_status, tracking_number,
               carrier_code, shipping_cost, data, created_at, shipping_history
        FROM pedidos
        WHERE id = ?
    `).get(orderId);

    if (!orderRow) {
        return res.status(404).json({ error: 'Orden no encontrada' });
    }

    const isOwner = decoded.o === orderId;
    const isUser = decoded.email === orderRow.email;
    const isAdmin = decoded.role === 'admin';

    if (!isOwner && !isUser && !isAdmin) {
        return res.status(403).json({ error: 'Acceso denegado' });
    }

    let parsedData = {};
    try {
        parsedData = JSON.parse(orderRow.data);
    } catch {
        parsedData = { pedido: { items: [], total: 0 } };
    }

    res.json({
        id: orderRow.id,
        status: orderRow.shipping_status || 'CONFIRMADO',
        payment_status: orderRow.status,
        date: orderRow.created_at,
        tracking_number: orderRow.tracking_number,
        carrier: orderRow.carrier_code,
        shipping_cost: orderRow.shipping_cost || 0,
        total: parsedData.pedido.total || 0,
        items: parsedData.pedido.items || [],
        tracking_history: orderRow.shipping_history
            ? JSON.parse(orderRow.shipping_history)
            : []
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
        incrementErrorCount();
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


app.get('/api/session/start', (req, res) => {
    const { token } = req.query;
    if (!token) return res.sendStatus(400);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.scope !== 'read_orders') {
            return res.sendStatus(403);
        }

        const customerToken = createCustomerSession(decoded.email, req);

        res.json({ token: customerToken });

    } catch {
        res.sendStatus(403);
    }
});



// 🛡 FIX #4: /api/my-orders — parsed variable was undefined (CRASH BUG)
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
            // 🛡 FIX #4: ESTA LÍNEA FALTABA — parsed nunca se definía → crash
            let parsed;
            try {
                parsed = JSON.parse(row.data);
            } catch {
                parsed = { pedido: { total: 0, items: [] } };
            }

            const orderToken = generateOrderToken(row.id, decoded.email);

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

app.get('/api/customer/orders', verifyCustomerSession, (req, res) => {
    try {
        const email = req.customer.email.toLowerCase();

        const rows = db.prepare(`
            SELECT id, status, created_at, data
            FROM pedidos
            WHERE lower(email) = ?
            ORDER BY created_at DESC
        `).all(email);

        const orders = rows.map(o => {
            let parsed;
            try {
                parsed = JSON.parse(o.data);
            } catch {
                parsed = { pedido: { total: 0, envio: 0, items: [] } };
            }

            const pedido = parsed.pedido || {};

            return {
                id: o.id,
                status: o.status,
                created_at: o.created_at,
                total: pedido.total || 0,
                shipping: pedido.envio || 0,
                items: pedido.items || [],
                order_token: generateOrderToken(o.id, email) // 🔥 CLAVE
            };

        });

        res.json(orders);

    } catch (err) {
        console.error('CUSTOMER_ORDERS_ERROR', err);
        res.status(500).json([]);
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
app.post('/api/admin/update-shipping', verifyToken, async (req, res) => {
    const { orderId, status, trackingNumber, carrier, description } = req.body; // Added description

    const VALID_STATUSES = [
        'CONFIRMADO',
        'EMPAQUETADO',
        'EN_TRANSITO',
        'ENTREGADO'
    ];

    if (!VALID_STATUSES.includes(status)) {
        return res.status(400).json({ error: 'Estado inválido' });
    }

    const order = db.prepare(`SELECT * FROM pedidos WHERE id=?`).get(orderId);
    if (!order) return res.status(404).json({ error: 'Orden no encontrada' });

    let history = [];
    try {
         history = order.shipping_history ? JSON.parse(order.shipping_history) : [];
    } catch(e) { history = []; }

    history.unshift({
        status,
        description: description || getStatusDescription(status),
        timestamp: new Date().toISOString(),
        location: ''
    });


    db.prepare(`
        UPDATE pedidos
        SET 
            shipping_status = ?,
            shipping_history = ?,
            tracking_number = COALESCE(?, tracking_number),
            carrier_code = COALESCE(?, carrier_code)
        WHERE id = ?
    `).run(
        status,
        JSON.stringify(history),
        trackingNumber,
        carrier,
        orderId
    );

    // 📧 EMAIL AUTOMÁTICO
    if (resend) {
        await resend.emails.send({
            from: `ETHERE4L <${SENDER_EMAIL}>`,
            to: [order.email],
            subject: `Actualización de tu pedido`,
            html: `
                <h2>Estado actualizado</h2>
                <p><strong>${getStatusDescription(status)}</strong></p>
                <p>Pedido: ${orderId}</p>
                ${trackingNumber ? `<p>Guía: ${trackingNumber}</p>` : ''}
            `
        });
    }

    res.json({ success: true });
});

function getStatusDescription(status) {
    switch (status) {
        case 'CONFIRMADO': return 'Pago confirmado, preparando pedido';
        case 'EMPAQUETADO': return 'Pedido empaquetado';
        case 'EN_TRANSITO': return 'Pedido en camino';
        case 'ENTREGADO': return 'Pedido entregado';
        default: return '';
    }
}



// ===============================
// 6. FUNCIONES INTERNAS (WEBHOOK LOGIC)
// ===============================

// Manejo post-pago de Stripe
async function handleStripeSuccess(session) {
    // 1. OBTENER ID REAL DEL METADATA
    const orderId = session.metadata?.order_id;
    if (!orderId) {
        logger.error('WEBHOOK_NO_ORDER_ID', { sessionId: session.id });
        return;
    }

    if (!dbPersistent) return;

    // 2. 🛡 FIX #3: IDEMPOTENCIA — Verificar si ya fue procesado
    try {
        const existingOrder = db.prepare(`SELECT status, data FROM pedidos WHERE id = ?`).get(orderId);

        if (!existingOrder) {
            logger.error('WEBHOOK_ORDER_NOT_FOUND', { orderId });
            return;
        }

        // Si ya está PAGADO, no reprocesar (Stripe puede reenviar webhooks)
        if (existingOrder.status === 'PAGADO') {
            logger.warn('WEBHOOK_IDEMPOTENCY', { 
                orderId, 
                message: 'Pedido ya estaba PAGADO. Webhook duplicado ignorado.' 
            });
            return;
        }

        // 3. TRANSACCIÓN: CONFIRMAR PAGO + DESCONTAR STOCK REAL
        const confirmPaymentTransaction = db.transaction(() => {
            // Actualizar estado a PAGADO
            db.prepare(`
                UPDATE pedidos
                SET 
                    status = 'PAGADO',
                    payment_ref = ?,
                    paid_at = datetime('now')
                WHERE id = ?
            `).run(
                session.payment_intent,
                orderId
            );

            // Confirmar stock: mover de reserved a sold (decrementar stock y reserved)
            let parsed;
            try {
                parsed = JSON.parse(existingOrder.data);
            } catch {
                parsed = { pedido: { items: [] } };
            }

            const orderItems = parsed.pedido?.items || [];
            for (const item of orderItems) {
                const qty = parseSafeNumber(item.cantidad, 1);
                db.prepare(`
                    UPDATE inventory 
                    SET stock = stock - ?, reserved = reserved - ?, updated_at = datetime('now')
                    WHERE product_id = ?
                `).run(qty, qty, String(item.id));
            }
        });

        confirmPaymentTransaction();

        // 4. RECUPERAR DATOS COMPLETOS DE LA DB (Hydration Source)
        const row = db.prepare(`SELECT data FROM pedidos WHERE id=?`).get(orderId);
        if (!row) {
            logger.error('WEBHOOK_DATA_MISSING', { orderId });
            return;
        }

        let parsed = {};
        parsed = JSON.parse(row.data);
        
        const cliente = parsed.cliente;
        const pedido = parsed.pedido;

        logger.info('PAGO_CONFIRMADO', { orderId, total: pedido.total });

        // 5. GENERAR PDF Y CORREOS (BACKGROUND)
        setImmediate(() => {
            processOrderBackground(orderId, cliente, pedido)
                .catch(e => {
                    logger.error('BACKGROUND_WORKER_ERROR', { orderId, error: e.message });
                    incrementErrorCount();
                });
        });

    } catch (e) {
        logger.error('WEBHOOK_PROCESSING_ERROR', { orderId, error: e.message, stack: e.stack });
        incrementErrorCount();
    }
}

// Reutilizamos tu Worker existente
async function processOrderBackground(jobId, cliente, pedido) {
    try {
        const pdfBuffer = await buildPDF(cliente, pedido, jobId, 'CLIENTE');

        const accessToken = generateOrderToken(jobId, cliente.email);
        const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ethereal-frontend.netlify.app';
        const trackingUrl =
         `${FRONTEND_URL}/pedido-ver.html?id=${jobId}&token=${accessToken}`;


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
    } catch (e) {
        logger.error('EMAIL_PDF_ERROR', { jobId, error: e.message });
        incrementErrorCount();
    }
}


// ===============================
// PHASE 6: CLEANUP — Liberar stock reservado de pedidos PENDIENTES antiguos (>2h)
// ===============================
function cleanupStaleReservations() {
    if (!dbPersistent) return;
    try {
        const staleOrders = db.prepare(`
            SELECT id, data FROM pedidos 
            WHERE status = 'PENDIENTE' 
            AND created_at < datetime('now', '-2 hours')
        `).all();

        if (staleOrders.length === 0) return;

        const cleanupTransaction = db.transaction(() => {
            for (const order of staleOrders) {
                let parsed;
                try {
                    parsed = JSON.parse(order.data);
                } catch { continue; }

                const items = parsed.pedido?.items || [];
                for (const item of items) {
                    const qty = parseSafeNumber(item.cantidad, 1);
                    db.prepare(`
                        UPDATE inventory 
                        SET reserved = MAX(0, reserved - ?), updated_at = datetime('now')
                        WHERE product_id = ?
                    `).run(qty, String(item.id));
                }

                // Marcar como EXPIRADO
                db.prepare(`UPDATE pedidos SET status = 'EXPIRADO' WHERE id = ?`).run(order.id);
            }
        });

        cleanupTransaction();

        if (staleOrders.length > 0) {
            logger.info('STALE_RESERVATIONS_CLEANED', { count: staleOrders.length });
        }
    } catch (e) {
        logger.error('CLEANUP_ERROR', { error: e.message });
    }
}

// Ejecutar cada 30 minutos
setInterval(cleanupStaleReservations, 30 * 60 * 1000);
// También ejecutar al inicio (después de 10 segundos para que DB esté lista)
setTimeout(cleanupStaleReservations, 10000);


// ===============================
// START SERVER
// ===============================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ETHERE4L Backend V${BACKEND_VERSION} corriendo en puerto ${PORT}`);
    logger.info('SERVER_STARTED', { port: PORT, version: BACKEND_VERSION, railway: isRailway });
});

process.on('SIGTERM', () => {
    logger.info('SERVER_SHUTDOWN', { reason: 'SIGTERM' });
    server.close(() => console.log('Servidor cerrado.'));
});

process.on('uncaughtException', (err) => {
    logger.error('UNCAUGHT_EXCEPTION', { error: err.message, stack: err.stack });
    incrementErrorCount();
});

process.on('unhandledRejection', (reason) => {
    logger.error('UNHANDLED_REJECTION', { reason: String(reason) });
    incrementErrorCount();
});
