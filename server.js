// =========================================================
// SERVER.JS - ETHERE4L BACKEND (PHASE 0: HTTPONLY COOKIE AUTH)
// =========================================================
// CHANGELOG PHASE 0 (SECURITY):
//   ✅ JWT moved from localStorage to HttpOnly cookie
//   ✅ Cookie: HttpOnly, Secure, SameSite=None (cross-origin Netlify↔Railway)
//   ✅ CORS: credentials: true, explicit origin
//   ✅ POST /api/session/logout — server-side session revocation + cookie clear
//   ✅ GET /api/session/start — now sets HttpOnly cookie instead of returning JWT
//   ✅ GET /api/customer/orders — reads from cookie, returns { email, orders }
//   ✅ verifyCustomerSession reads from cookie OR Authorization header (backward compat)
//   ✅ All existing endpoints preserved 1:1
//   ✅ Stripe webhook unaffected (server-to-server, no cookies)
//   ✅ Admin endpoints unaffected (still use Authorization header)
//   ✅ Per-order tokens (order_token) still via Authorization header (not stored client-side)
// =========================================================
// CHANGELOG FIX (EMAIL OBSERVABILITY):
//   ✅ Added Resend response logging in processOrderBackground
//   ✅ Added specific error handling for email failures
//   ✅ Added Resend response logging in magic link endpoint
//   ✅ Improved debugging capabilities without breaking functionality
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
const cookieParser = require('cookie-parser');

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
const stripe = Stripe((process.env.STRIPE_SECRET_KEY || '').trim());

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

// ===============================
// 0.0 COOKIE CONFIGURATION (PHASE 0)
// ===============================
const COOKIE_NAME = 'ethere4l_session';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

/**
 * Returns cookie options for the session cookie.
 * 
 * SECURITY RATIONALE:
 * - httpOnly: true → JavaScript cannot read the cookie (XSS protection)
 * - secure: true in production → Cookie only sent over HTTPS
 * - sameSite: 'None' → Required for cross-origin (Netlify frontend ↔ Railway backend)
 *   NOTE: SameSite=Strict would BLOCK the cookie because frontend and backend are different domains.
 *   SameSite=None + Secure is the correct combination for cross-origin cookie auth.
 * - path: '/' → Cookie sent to all API routes
 * - maxAge: matches session expiry
 * 
 * FUTURE: If frontend and backend move to same domain (e.g., api.ethere4l.com),
 *         switch to SameSite=Strict and set domain='.ethere4l.com'
 */
function getSessionCookieOptions(maxAgeDays) {
    return {
        httpOnly: true,
        secure: IS_PRODUCTION,          // HTTPS only in production
        sameSite: IS_PRODUCTION ? 'None' : 'Lax',  // None for cross-origin prod; Lax for localhost
        path: '/',
        maxAge: maxAgeDays * 24 * 60 * 60 * 1000  // Convert days to milliseconds
    };
}

/**
 * Returns cookie options to CLEAR the session cookie.
 * Must match the options used to SET it (except maxAge).
 */
function getClearCookieOptions() {
    return {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: IS_PRODUCTION ? 'None' : 'Lax',
        path: '/'
    };
}

// RATE LIMITER: MAGIC LINK
const magicLinkLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: "Demasiadas solicitudes. Intenta más tarde."
});

// ===============================
// 0.1 HELPER: SANITIZACIÓN NUMÉRICA
// ===============================
function parseSafeNumber(value, fallback = 0) {
    if (typeof value === 'number' && !isNaN(value)) return value;
    if (!value) return fallback;
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
function validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const trimmed = email.trim();
    if (trimmed.length === 0 || trimmed.length > 254) return false;
    if (/\s/.test(trimmed)) return false;
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    return emailRegex.test(trimmed);
}


// ================= CATÁLOGO ESTÁTICO =================
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

    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_pedidos_email ON pedidos(email);
        CREATE INDEX IF NOT EXISTS idx_pedidos_status ON pedidos(status);
        CREATE INDEX IF NOT EXISTS idx_pedidos_payment_ref ON pedidos(payment_ref);
        CREATE INDEX IF NOT EXISTS idx_pedidos_created_at ON pedidos(created_at);
    `);
    console.log('✅ Índices de pedidos verificados');

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

    const inventoryCount = db.prepare(`SELECT COUNT(*) as c FROM inventory`).get().c;
    if (inventoryCount === 0 && PRODUCTS_DB.length > 0) {
        const insertStmt = db.prepare(`
            INSERT OR IGNORE INTO inventory (product_id, stock) VALUES (?, ?)
        `);
        const seedTransaction = db.transaction((products) => {
            for (const p of products) {
                const stockValue = typeof p.stock === 'number' ? p.stock : 10;
                insertStmt.run(String(p.id), stockValue);
            }
        });
        seedTransaction(PRODUCTS_DB);
        console.log(`📦 Inventario inicializado con ${PRODUCTS_DB.length} productos`);
    }

    // MIGRACIÓN SEGURA DE COLUMNAS
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
app.set('trust proxy', 1);

// ===============================
// COOKIE PARSER (PHASE 0: Required to read HttpOnly cookies)
// ===============================
// Must be added BEFORE routes that read cookies
// No secret needed — we don't use signed cookies (JWT is self-validating)
app.use(cookieParser());

// ===============================
// OBSERVABILIDAD: LOGGER ESTRUCTURADO
// ===============================
const LOG_DIR = isRailway ? path.join(RAILWAY_VOLUME, 'logs') : path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}
const LOG_FILE = path.join(LOG_DIR, 'app.log');

function writeLogToFile(level, message, context) {
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        context
    };
    try {
        fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
    } catch (e) { /* silent */ }
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
const BACKEND_VERSION = '2.2.1';

// Rate Limiter para Admin
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Demasiados intentos de acceso al panel."
});

// ===============================
// MIDDLEWARE: Admin JWT (Authorization header — unchanged)
// ===============================
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
// MIDDLEWARE: Customer Session (PHASE 0: COOKIE-FIRST, Authorization header fallback)
// ===============================
/**
 * PHASE 0 CHANGE:
 * - PRIMARY: Read JWT from HttpOnly cookie (COOKIE_NAME)
 * - FALLBACK: Read from Authorization header (backward compatibility during migration)
 * 
 * This allows:
 * 1. New frontend (cookie-based) to work immediately
 * 2. Old clients / API consumers that still send Authorization header to keep working
 * 3. Gradual migration without breaking anything
 * 
 * After full migration, the Authorization header fallback can be removed.
 */
function verifyCustomerSession(req, res, next) {
    // 1. Try cookie first (new secure flow)
    let token = req.cookies[COOKIE_NAME];

    // 2. Fallback to Authorization header (backward compatibility)
    if (!token) {
        const auth = req.headers.authorization;
        if (auth && auth.startsWith('Bearer ')) {
            token = auth.split(' ')[1];
        }
    }

    if (!token) {
        return res.sendStatus(401);
    }

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
        // If cookie auth failed, clear the invalid cookie
        res.clearCookie(COOKIE_NAME, getClearCookieOptions());
        return res.sendStatus(403);
    }
}


// ===============================
// REQUEST CORRELATION
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
        if (res.statusCode >= 500) {
            incrementErrorCount();
        }
    });

    next();
});

// ===============================
// CORS CONFIGURATION (PHASE 0: credentials: true)
// ===============================
/**
 * PHASE 0 CRITICAL CHANGE:
 * - credentials: true → Required for cross-origin cookie transmission
 * - origin must be EXPLICIT (not '*') when credentials is true
 * - This is a browser requirement per the Fetch specification
 * 
 * WHY SameSite=None works here:
 * - Frontend: https://ethereal-frontend.netlify.app (Netlify)
 * - Backend: https://ethere4l-backend-production.up.railway.app (Railway)
 * - These are DIFFERENT origins → cross-origin → requires SameSite=None
 * - SameSite=None requires Secure=true (HTTPS only)
 * - Railway serves over HTTPS by default ✓
 * 
 * WHY this doesn't affect Stripe webhooks:
 * - Stripe webhooks are server-to-server HTTP POST requests
 * - They don't use cookies or CORS — they use signature verification
 * - The webhook endpoint (/api/webhook) is hit directly by Stripe servers
 */
const ALLOWED_ORIGINS = [
    'https://ethereal-frontend.netlify.app',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3001',
    process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (Stripe webhooks, server-to-server, curl, etc.)
        if (!origin) return callback(null, true);
        
        if (ALLOWED_ORIGINS.indexOf(origin) !== -1) {
            return callback(null, true);
        }
        
        logger.warn('CORS_BLOCKED', { origin });
        return callback(new Error('CORS not allowed'), false);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true  // ← PHASE 0: Required for Set-Cookie / Cookie headers cross-origin
}));

// Email config
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

// AHORA SÍ: Parser JSON global
app.use(express.json());

// ===============================
// 4. API ENDPOINTS (CLIENTE)
// ===============================

app.get('/', (req, res) => {
    res.json({ status: 'online', service: 'ETHERE4L Backend v2.2.1', mode: 'Stripe Enabled + HttpOnly Cookies + Email Observability' });
});

// ===============================
// HEALTH CHECK
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
// METRICS
// ===============================
app.get('/metrics', (req, res) => {
    if (Date.now() > errorCountResetAt) {
        errorCountLastHour = 0;
        errorCountResetAt = Date.now() + 3600000;
    }

    let pedidosHoy = 0;
    let totalVentasHoy = 0;
    let totalPedidos = 0;

    try {
        if (dbPersistent) {
            const today = new Date().toISOString().split('T')[0];
            const hoyStats = db.prepare(`
                SELECT COUNT(*) as count FROM pedidos 
                WHERE date(created_at) = date(?)
            `).get(today);
            pedidosHoy = hoyStats ? hoyStats.count : 0;

            const ventasHoy = db.prepare(`
                SELECT data FROM pedidos 
                WHERE date(created_at) = date(?) AND status = 'PAGADO'
            `).all(today);

            for (const row of ventasHoy) {
                try {
                    const parsed = JSON.parse(row.data);
                    totalVentasHoy += parseSafeNumber(parsed.pedido?.total, 0);
                } catch (e) { /* skip */ }
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


// ===============================
// CHECKOUT SESSION (unchanged — no auth cookies involved)
// ===============================
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { items, customer } = req.body;

        const customerEmail = customer?.email ? String(customer.email).trim().toLowerCase() : '';
        if (!validateEmail(customerEmail)) {
            return res.status(400).json({ 
                error: 'Email inválido. Verifica tu dirección de correo.' 
            });
        }

        for (const item of items) {
            const cantidad = parseSafeNumber(item.cantidad, 0);
            if (!Number.isInteger(cantidad) || cantidad < 1 || cantidad > 10) {
                return res.status(400).json({ 
                    error: `Cantidad inválida para producto ${item.id || 'desconocido'}: ${item.cantidad}. Debe ser entre 1 y 10.` 
                });
            }
        }

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
            }
        }
        
        const tempOrderId = `ord_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
        const FRONTEND_URL = process.env.FRONTEND_URL || req.headers.origin || 'https://ethereal-frontend.netlify.app';

        let lineItems = [];
        let pesoTotal = 0;
        let serverSubtotal = 0;

        for (const item of items) {
            const dbProduct = PRODUCTS_DB.length > 0 
                ? PRODUCTS_DB.find(p => String(p.id) === String(item.id)) 
                : null;

            const productFinal = dbProduct || item;
            const rawPrice = dbProduct ? dbProduct.precio : item.precio;
            const precioLimpio = parseSafeNumber(rawPrice, 0);

            if (precioLimpio <= 0) {
                logger.warn('PRECIO_INVALIDO', { itemId: item.id, rawPrice, precioLimpio });
                return res.status(400).json({ error: `Precio inválido para producto ${item.id}` });
            }

            const cantidadLimpia = parseSafeNumber(item.cantidad, 1);
            const pesoLimpio = parseSafeNumber(productFinal.peso, 0.6);
            pesoTotal += pesoLimpio * cantidadLimpia;
            serverSubtotal += precioLimpio * cantidadLimpia;

            let productImages = [];
            if (dbProduct && dbProduct.fotos && dbProduct.fotos.length > 0) {
                productImages = [dbProduct.fotos[0]];
            } else if (item.imagen && item.imagen.startsWith('http')) { 
                productImages = [item.imagen];
            }

            lineItems.push({
                price_data: {
                    currency: 'mxn',
                    product_data: {
                        name: productFinal.nombre,
                        images: productImages,
                        metadata: {
                            talla: item.talla,
                            id_producto: item.id
                        }
                    },
                    unit_amount: Math.round(precioLimpio * 100), 
                },
                quantity: cantidadLimpia,
            });
        }

        const totalItems = items.reduce((acc, item) => acc + parseSafeNumber(item.cantidad, 1), 0);
        let costoEnvio = 0;

        if (totalItems === 1) costoEnvio = 900; 
        else if (totalItems === 2) costoEnvio = 1000; 
        else if (totalItems === 3) costoEnvio = 1300; 
        else costoEnvio = 1500; 

        if (pesoTotal > 10.0) costoEnvio += 500; 

        const pedidoSnapshot = {
            items: items.map(item => {
                const dbProduct = PRODUCTS_DB.find(p => String(p.id) === String(item.id)) || item;
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
            subtotal: serverSubtotal,
            envio: costoEnvio,
            total: serverSubtotal + costoEnvio
        };

        if (dbPersistent) {
            const createOrderTransaction = db.transaction(() => {
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

                for (const item of items) {
                    const cantidadLimpia = parseSafeNumber(item.cantidad, 1);
                    db.prepare(`
                        UPDATE inventory 
                        SET reserved = reserved + ?, updated_at = datetime('now')
                        WHERE product_id = ?
                    `).run(cantidadLimpia, String(item.id));
                }

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

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            customer_email: customerEmail,
            metadata: { order_id: tempOrderId },
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

// (LEGACY)
app.post('/api/crear-pedido', (req, res) => {
    res.json({ success: true, message: "Use /api/create-checkout-session for payments" });
});


// ===============================
// TRACKING (per-order token via Authorization header — unchanged)
// ===============================
const trackingLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: "Demasiadas solicitudes de tracking."
});

app.get('/api/orders/track/:orderId', trackingLimiter, (req, res) => {
    const { orderId } = req.params;

    // This endpoint uses per-order tokens (Authorization header)
    // NOT session cookies — because order detail links are shared via email
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

app.post('/api/admin/login', adminLimiter, async (req, res) => {
    try {
        const { password } = req.body;
        console.log(`🔐 Admin login attempt | IP: ${req.ip}`);

        if (!process.env.ADMIN_PASS_HASH || !process.env.JWT_SECRET) {
            console.error("❌ Faltan ADMIN_PASS_HASH o JWT_SECRET en Railway");
            return res.status(500).json({ error: 'Server misconfigured' });
        }

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


// ===============================
// MAGIC LINK (with Resend response logging)
// ===============================
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

            try {
                const magicRes = await resend.emails.send({
                    from: `ETHERE4L <${SENDER_EMAIL}>`,
                    to: [cleanEmail],
                    subject: "Accede a tus pedidos – ETHERE4L",
                    html: getMagicLinkEmail(link)
                });

                logger.info('MAGIC_LINK_SENT', { 
                    email: cleanEmail,
                    resendId: magicRes.id,
                    resendFrom: magicRes.from,
                    resendTo: magicRes.to
                });
            } catch (emailErr) {
                logger.error('MAGIC_LINK_EMAIL_FAILED', { 
                    email: cleanEmail, 
                    error: emailErr.message,
                    statusCode: emailErr.statusCode || 'N/A',
                    name: emailErr.name
                });
                // Still return success (anti-enumeration)
            }
        } else if (hasOrders && !resend) {
            logger.warn('MAGIC_LINK_RESEND_NOT_CONFIGURED', { email: cleanEmail });
        }

        res.json({ success: true });

    } catch (err) {
        logger.error('MAGIC_LINK_ERROR', { error: err.message, stack: err.stack });
        res.json({ success: true });
    }
});


// ===============================
// SESSION START (PHASE 0: NOW SETS HTTPONLY COOKIE)
// ===============================
/**
 * PHASE 0 CRITICAL CHANGE:
 * 
 * BEFORE: Returns { token: "jwt..." } → frontend stores in localStorage
 * AFTER:  Sets HttpOnly cookie + returns { success: true, email: "..." }
 * 
 * The JWT is NEVER exposed to JavaScript.
 * The browser stores it as an HttpOnly cookie automatically.
 * All subsequent requests include it via credentials: 'include'.
 */
app.get('/api/session/start', (req, res) => {
    const { token } = req.query;
    if (!token) return res.sendStatus(400);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.scope !== 'read_orders') {
            return res.sendStatus(403);
        }

        // Create persistent session in DB
        const customerToken = createCustomerSession(decoded.email, req);

        // SET HTTPONLY COOKIE instead of returning token in body
        res.cookie(COOKIE_NAME, customerToken, getSessionCookieOptions(CUSTOMER_SESSION_DAYS));

        logger.info('SESSION_STARTED_COOKIE', { email: decoded.email });

        // Return success + email for display (NOT the token)
        res.json({ 
            success: true, 
            email: decoded.email 
        });

    } catch (e) {
        logger.warn('SESSION_START_FAILED', { error: e.message });
        res.sendStatus(403);
    }
});


// ===============================
// SESSION LOGOUT (PHASE 0: NEW ENDPOINT)
// ===============================
/**
 * Clears the HttpOnly session cookie and revokes the session in DB.
 * 
 * This is called by:
 * 1. The logout button on mis-pedidos.html
 * 2. The login.html page on load (to clear stale sessions)
 */
app.post('/api/session/logout', (req, res) => {
    const token = req.cookies[COOKIE_NAME];

    if (token) {
        // Revoke session in DB
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.session_id) {
                db.prepare(`DELETE FROM customer_sessions WHERE id = ?`)
                  .run(decoded.session_id);
                logger.info('SESSION_REVOKED', { sessionId: decoded.session_id });
            }
        } catch (e) {
            // Token might be expired/invalid — that's fine, still clear the cookie
        }
    }

    // Clear the cookie regardless
    res.clearCookie(COOKIE_NAME, getClearCookieOptions());

    res.json({ success: true });
});


// ===============================
// CUSTOMER ORDERS (PHASE 0: COOKIE AUTH + returns email)
// ===============================
/**
 * PHASE 0 CHANGE:
 * - Now uses verifyCustomerSession which reads from cookie first
 * - Returns { email, orders } so frontend can display user email
 *   without needing to decode JWT (which it can't access anymore)
 */
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
                order_token: generateOrderToken(o.id, email)
            };
        });

        // PHASE 0: Return email alongside orders for frontend display
        res.json({
            email: email,
            orders: orders
        });

    } catch (err) {
        console.error('CUSTOMER_ORDERS_ERROR', err);
        res.status(500).json({ email: '', orders: [] });
    }
});


// ===============================
// MY-ORDERS (legacy — still uses Authorization header for backward compat)
// ===============================
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


// Admin orders
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

// Update shipping
app.post('/api/admin/update-shipping', verifyToken, async (req, res) => {
    const { orderId, status, trackingNumber, carrier, description } = req.body;

    const VALID_STATUSES = ['CONFIRMADO', 'EMPAQUETADO', 'EN_TRANSITO', 'ENTREGADO'];

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

async function handleStripeSuccess(session) {
    const orderId = session.metadata?.order_id;
    if (!orderId) {
        logger.error('WEBHOOK_NO_ORDER_ID', { sessionId: session.id });
        return;
    }

    if (!dbPersistent) return;

    try {
        const existingOrder = db.prepare(`SELECT status, data FROM pedidos WHERE id = ?`).get(orderId);

        if (!existingOrder) {
            logger.error('WEBHOOK_ORDER_NOT_FOUND', { orderId });
            return;
        }

        if (existingOrder.status === 'PAGADO') {
            logger.warn('WEBHOOK_IDEMPOTENCY', { 
                orderId, 
                message: 'Pedido ya estaba PAGADO. Webhook duplicado ignorado.' 
            });
            return;
        }

        const confirmPaymentTransaction = db.transaction(() => {
            db.prepare(`
                UPDATE pedidos
                SET 
                    status = 'PAGADO',
                    payment_ref = ?,
                    paid_at = datetime('now')
                WHERE id = ?
            `).run(session.payment_intent, orderId);

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

async function processOrderBackground(jobId, cliente, pedido) {
    try {
        const pdfBuffer = await buildPDF(cliente, pedido, jobId, 'CLIENTE');

        const accessToken = generateOrderToken(jobId, cliente.email);
        const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ethereal-frontend.netlify.app';
        const trackingUrl = `${FRONTEND_URL}/pedido-ver.html?id=${jobId}&token=${accessToken}`;

        if (resend) {
            try {
                const clientEmailRes = await resend.emails.send({
                    from: `ETHERE4L <${SENDER_EMAIL}>`,
                    to: [cliente.email],
                    subject: `Confirmación de Pedido ${jobId.slice(-6)}`,
                    html: getPaymentConfirmedEmail(cliente, pedido, jobId, trackingUrl),
                    attachments: [
                        { filename: `Orden_${jobId.slice(-6)}.pdf`, content: pdfBuffer }
                    ]
                });

                logger.info('CLIENT_EMAIL_SENT', { 
                    orderId: jobId, 
                    email: cliente.email, 
                    resendId: clientEmailRes.id,
                    resendFrom: clientEmailRes.from,
                    resendTo: clientEmailRes.to
                });

                if (ADMIN_EMAIL) {
                    const adminEmailRes = await resend.emails.send({
                        from: `System <${SENDER_EMAIL}>`,
                        to: [ADMIN_EMAIL],
                        subject: `💰 NUEVA VENTA - ${jobId.slice(-6)}`,
                        html: getEmailTemplate(cliente, pedido, jobId, true),
                        attachments: [
                            { filename: `Orden_${jobId.slice(-6)}.pdf`, content: pdfBuffer }
                        ]
                    });

                    logger.info('ADMIN_EMAIL_SENT', { 
                        orderId: jobId, 
                        resendId: adminEmailRes.id 
                    });
                }
            } catch (emailError) {
                // Specific email error logging
                logger.error('RESEND_API_ERROR', { 
                    orderId: jobId, 
                    error: emailError.message,
                    statusCode: emailError.statusCode || 'N/A',
                    name: emailError.name
                });
                // Don't throw — allow process to continue
            }
        }
    } catch (e) {
        logger.error('EMAIL_PDF_ERROR', { jobId, error: e.message });
        incrementErrorCount();
    }
}


// ===============================
// CLEANUP: Liberar stock de pedidos PENDIENTES antiguos
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

setInterval(cleanupStaleReservations, 30 * 60 * 1000);
setTimeout(cleanupStaleReservations, 10000);


// ===============================
// START SERVER
// ===============================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ETHERE4L Backend V${BACKEND_VERSION} corriendo en puerto ${PORT}`);
    console.log(`🔒 Auth: HttpOnly Cookie (Phase 0 Security)`);
    console.log(`🍪 Cookie: ${COOKIE_NAME} | SameSite=${IS_PRODUCTION ? 'None' : 'Lax'} | Secure=${IS_PRODUCTION}`);
    logger.info('SERVER_STARTED', { port: PORT, version: BACKEND_VERSION, railway: isRailway, authMode: 'httponly_cookie' });
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