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
// CHANGELOG FIX (CORS PREFLIGHT + MIDDLEWARE ORDER):
//   ✅ Fixed middleware order: trust proxy → CORS → preflight → webhook(raw) → json → cookie → routes
//   ✅ Added explicit OPTIONS preflight handler: app.options('*', cors())
//   ✅ Fixed CORS origin callback to use (null, false) instead of Error
//   ✅ Added CORS error handler and global error handler
//   ✅ Logger declared before any middleware that uses it
//   ✅ Added maxAge and optionsSuccessStatus to CORS config
//   ✅ ALLOWED_ORIGINS includes ethere4l.com for future migration
// =========================================================
// CHANGELOG FASE 3 (CORRECCIONES):
//   ✅ FIX 1: Cookie 'domain' added for Safari iOS cross-site
//   ✅ FIX 2: FRONTEND_URL env var validation
//   ✅ FIX 3: Added /api/catalogo endpoint for future resilience
//   ✅ FIX 4: Vary header for proper CORS caching
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
const Stripe = require('stripe');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { randomUUID: uuidv4 } = require('crypto');

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
// 0.0 COOKIE CONFIGURATION (FIXED)
// ===============================
const COOKIE_NAME = 'ethere4l_session';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ✅ FIX 1: Cookie domain for Safari iOS cross-site support
// Safari iOS REQUIRES explicit domain for SameSite=None cookies
// to be accepted in cross-origin contexts (Netlify → Railway)
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
// Set COOKIE_DOMAIN=.api.ethere4l.com in Railway env vars

function getSessionCookieOptions(maxAgeDays) {
    var options = {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: IS_PRODUCTION ? 'None' : 'Lax',
        path: '/',
        maxAge: maxAgeDays * 24 * 60 * 60 * 1000
    };

    // ✅ FIX 1: Add domain in production for Safari iOS compatibility
    if (IS_PRODUCTION && COOKIE_DOMAIN) {
        options.domain = COOKIE_DOMAIN;
    }

    return options;
}

function getClearCookieOptions() {
    var options = {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: IS_PRODUCTION ? 'None' : 'Lax',
        path: '/'
    };

    // ✅ FIX 1: Must match domain used when setting the cookie
    if (IS_PRODUCTION && COOKIE_DOMAIN) {
        options.domain = COOKIE_DOMAIN;
    }

    return options;
}

// ===============================
// 0.1 HELPERS
// ===============================
function parseSafeNumber(value, fallback = 0) {
    if (typeof value === 'number' && !isNaN(value)) return value;
    if (!value) return fallback;
    const cleanString = String(value).replace(/[^0-9.]/g, '');
    const number = parseFloat(cleanString);
    return isNaN(number) ? fallback : number;
}

function generateOrderToken(orderId, email) {
    return jwt.sign(
        { o: orderId, e: email },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

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
// 1. DATABASE SETUP
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
// 2. APP INITIALIZATION
// ===============================
const app = express();

// ===============================
// LOGGER (declared early — used by middleware below)
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
const BACKEND_VERSION = '2.3.0';

// ===============================
// CORS CONFIG (ENHANCED)
// ===============================
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ethere4l.com';

const ALLOWED_ORIGINS = [
    'https://ethere4l.com',
    'https://www.ethere4l.com',
    'https://ethereal-frontend.netlify.app',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3001',
    'http://localhost:3000',
    FRONTEND_URL
].filter(Boolean);

const UNIQUE_ORIGINS = [...new Set(ALLOWED_ORIGINS)];

const corsOptions = {
    origin: function(origin, callback) {
        if (!origin) return callback(null, true);
        if (UNIQUE_ORIGINS.indexOf(origin) !== -1) {
            return callback(null, true);
        }
        logger.warn('CORS_BLOCKED', { origin });
        return callback(null, false);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 204
};


// =========================================================
// MIDDLEWARE CHAIN — CORRECT ORDER
// =========================================================
//   1. trust proxy
//   2. CORS middleware (headers on ALL responses)
//   3. Vary header (FIX 4)
//   4. OPTIONS preflight handler (responds to all OPTIONS)
//   5. Stripe webhook (raw body, BEFORE express.json)
//   6. express.json()
//   7. cookieParser()
//   8. Request correlation / logging
//   9. Routes
//   10. Error handlers
// =========================================================

// --- STEP 1: Trust proxy ---
app.set('trust proxy', 1);

// --- STEP 2: CORS middleware ---
app.use(cors(corsOptions));

// --- STEP 3: ✅ FIX 4: Add Vary header for proper CDN/proxy caching ---
app.use(function(req, res, next) {
    res.setHeader('Vary', 'Origin');
    next();
});

// --- STEP 4: Explicit preflight handler ---
app.options('*', cors(corsOptions));

// --- STEP 5: Stripe webhook (BEFORE express.json) ---
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        logger.error('WEBHOOK_SIGNATURE_FAIL', { error: err.message });
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    logger.info('WEBHOOK_RECEIVED', { type: event.type, eventId: event.id });

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        try {
            await handleStripeSuccess(session);
            logger.info('WEBHOOK_PROCESSED', { orderId: session.metadata?.order_id });
        } catch (e) {
            logger.error('WEBHOOK_HANDLER_ERROR', { error: e.message, stack: e.stack });
        }
    }

    res.json({ received: true });
});

// --- STEP 6: JSON body parser ---
app.use(express.json());

// --- STEP 7: Cookie parser ---
app.use(cookieParser());

// --- STEP 8: Request correlation & logging ---
app.use((req, res, next) => {
    req.requestId = `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const start = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - start;
        if (req.originalUrl !== '/health' && req.originalUrl !== '/metrics') {
            logger.info('HTTP_REQUEST', {
                requestId: req.requestId,
                method: req.method,
                path: req.originalUrl,
                status: res.statusCode,
                ip: req.ip,
                durationMs: duration
            });
        }
        if (res.statusCode >= 500) {
            incrementErrorCount();
        }
    });

    next();
});

// ===============================
// RATE LIMITERS
// ===============================
const magicLinkLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: "Demasiadas solicitudes. Intenta más tarde."
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Demasiados intentos de acceso al panel."
});

const trackingLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: "Demasiadas solicitudes de tracking."
});

// ===============================
// RESEND CONFIG
// ===============================
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
// AUTH MIDDLEWARES
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

function verifyCustomerSession(req, res, next) {
    let token = req.cookies[COOKIE_NAME];

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
        res.clearCookie(COOKIE_NAME, getClearCookieOptions());
        return res.sendStatus(403);
    }
}


// ===============================
// ROUTES
// ===============================

app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'ETHERE4L Backend v' + BACKEND_VERSION,
        mode: 'Stripe + HttpOnly Cookies + CORS Fixed + Safari iOS Compatible'
    });
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
        cors: { originsCount: UNIQUE_ORIGINS.length, preflightEnabled: true },
        cookieDomain: COOKIE_DOMAIN || 'not set',
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
// ✅ FIX 3: CATALOG ENDPOINTS (NEW — for mobile resilience)
// ===============================
app.get('/api/catalogo', function(req, res) {
    try {
        if (CATALOG_DB.length > 0) {
            return res.json(CATALOG_DB);
        }
        if (PRODUCTS_DB.length > 0) {
            return res.json(PRODUCTS_DB);
        }
        res.status(404).json({ error: 'Catálogo no disponible' });
    } catch (e) {
        logger.error('CATALOG_ENDPOINT_ERROR', { error: e.message });
        res.status(500).json({ error: 'Error cargando catálogo' });
    }
});

app.get('/api/productos', function(req, res) {
    try {
        if (PRODUCTS_DB.length > 0) {
            return res.json(PRODUCTS_DB);
        }
        res.status(404).json({ error: 'Productos no disponibles' });
    } catch (e) {
        logger.error('PRODUCTS_ENDPOINT_ERROR', { error: e.message });
        res.status(500).json({ error: 'Error cargando productos' });
    }
});

// ===============================
// CHECKOUT SESSION
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

app.post('/api/crear-pedido', (req, res) => {
    res.json({ success: true, message: "Use /api/create-checkout-session for payments" });
});


// ===============================
// TRACKING
// ===============================
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
// ADMIN
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
// MAGIC LINK
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
                JWT_SECRET,
                { expiresIn: '24h' }
            );

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
                    resendId: magicRes?.id || 'unknown'
                });
            } catch (emailErr) {
                logger.error('MAGIC_LINK_EMAIL_FAILED', {
                    email: cleanEmail,
                    error: emailErr.message,
                    statusCode: emailErr.statusCode || 'N/A',
                    name: emailErr.name
                });
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
// SESSION START
// ===============================
app.get('/api/session/start', (req, res) => {
    const { token } = req.query;
    if (!token) return res.sendStatus(400);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.scope !== 'read_orders') {
            return res.sendStatus(403);
        }

        const customerToken = createCustomerSession(decoded.email, req);

        res.cookie(COOKIE_NAME, customerToken, getSessionCookieOptions(CUSTOMER_SESSION_DAYS));

        logger.info('SESSION_STARTED_COOKIE', { email: decoded.email });

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
// SESSION LOGOUT
// ===============================
app.post('/api/session/logout', (req, res) => {
    const token = req.cookies ? req.cookies[COOKIE_NAME] : null;

    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.session_id) {
                db.prepare(`DELETE FROM customer_sessions WHERE id = ?`)
                  .run(decoded.session_id);
                logger.info('SESSION_REVOKED', { sessionId: decoded.session_id });
            }
        } catch (e) {
            // Token might be expired/invalid — still clear the cookie
        }
    }

    res.clearCookie(COOKIE_NAME, getClearCookieOptions());
    res.json({ success: true });
});


// ===============================
// CUSTOMER ORDERS
// ===============================
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
// MY-ORDERS (legacy)
// ===============================
app.get('/api/my-orders', (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.sendStatus(401);

    const token = auth.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

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
        try {
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
        } catch (emailErr) {
            logger.error('SHIPPING_UPDATE_EMAIL_FAILED', { orderId, error: emailErr.message });
        }
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
// WEBHOOK HANDLER
// ===============================
async function handleStripeSuccess(session) {
    const orderId = session.metadata?.order_id;
    if (!orderId) {
        logger.error('WEBHOOK_NO_ORDER_ID', { sessionId: session.id });
        return;
    }

    if (!dbPersistent) {
        logger.error('WEBHOOK_DB_NOT_PERSISTENT', { orderId });
        return;
    }

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

        logger.info('PAYMENT_CONFIRMED_DB', { orderId, paymentIntent: session.payment_intent });

        const row = db.prepare(`SELECT data FROM pedidos WHERE id=?`).get(orderId);
        if (!row) {
            logger.error('WEBHOOK_DATA_MISSING_AFTER_UPDATE', { orderId });
            return;
        }

        let parsed = {};
        parsed = JSON.parse(row.data);

        const cliente = parsed.cliente;
        const pedido = parsed.pedido;

        logger.info('PAGO_CONFIRMADO', { orderId, total: pedido.total, email: cliente.email });

        // Process emails synchronously to ensure they complete before webhook response
        try {
            await processOrderBackground(orderId, cliente, pedido);
            logger.info('WEBHOOK_EMAILS_COMPLETED', { orderId });
        } catch (e) {
            logger.error('WEBHOOK_EMAIL_ERROR', { orderId, error: e.message });
        }

    } catch (e) {
        logger.error('WEBHOOK_PROCESSING_ERROR', { orderId, error: e.message, stack: e.stack });
        incrementErrorCount();
    }
}

async function processOrderBackground(jobId, cliente, pedido) {
    try {
        logger.info('EMAIL_PROCESS_START', { orderId: jobId, email: cliente.email, resendConfigured: !!resend });

        const pdfBuffer = await buildPDF(cliente, pedido, jobId, 'CLIENTE');
        logger.info('PDF_GENERATED', { orderId: jobId, pdfSize: pdfBuffer.length });

        const accessToken = generateOrderToken(jobId, cliente.email);
        const trackingUrl = `${FRONTEND_URL}/pedido-ver.html?id=${jobId}&token=${accessToken}`;

        if (resend) {
            // Client email
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
                    resendId: clientEmailRes?.id || 'unknown'
                });
            } catch (clientEmailErr) {
                logger.error('CLIENT_EMAIL_FAILED', {
                    orderId: jobId,
                    email: cliente.email,
                    error: clientEmailErr.message,
                    statusCode: clientEmailErr.statusCode || 'N/A'
                });
            }

            // Admin email
            if (ADMIN_EMAIL) {
                try {
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
                        resendId: adminEmailRes?.id || 'unknown'
                    });
                } catch (adminEmailErr) {
                    logger.error('ADMIN_EMAIL_FAILED', {
                        orderId: jobId,
                        error: adminEmailErr.message
                    });
                }
            }
        } else {
            logger.warn('RESEND_NOT_CONFIGURED_SKIPPING_EMAILS', { orderId: jobId });
        }
    } catch (e) {
        logger.error('EMAIL_PDF_ERROR', { jobId, error: e.message, stack: e.stack });
        incrementErrorCount();
    }
}


// ===============================
// CLEANUP
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
// ERROR HANDLERS (after all routes)
// ===============================
app.use((err, req, res, next) => {
    if (err.message && err.message.toLowerCase().includes('cors')) {
        logger.warn('CORS_ERROR_HANDLED', { origin: req.headers.origin, path: req.originalUrl });
        return res.status(403).json({ error: 'Origin not allowed' });
    }
    next(err);
});

app.use((err, req, res, next) => {
    logger.error('UNHANDLED_ROUTE_ERROR', {
        error: err.message,
        stack: err.stack,
        path: req.originalUrl,
        method: req.method
    });
    incrementErrorCount();
    res.status(500).json({ error: 'Internal server error' });
});


// ===============================
// START SERVER
// ===============================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ETHERE4L Backend V${BACKEND_VERSION} corriendo en puerto ${PORT}`);
    console.log(`🔒 Auth: HttpOnly Cookie (Phase 0 Security + Safari iOS Fix)`);
    console.log(`🍪 Cookie: ${COOKIE_NAME} | SameSite=${IS_PRODUCTION ? 'None' : 'Lax'} | Secure=${IS_PRODUCTION} | Domain=${COOKIE_DOMAIN || 'not set'}`);
    console.log(`🌐 CORS: ${UNIQUE_ORIGINS.length} origins | preflight: explicit | credentials: true | Vary: Origin`);
    console.log(`📧 Email: ${resend ? 'Resend ACTIVE' : 'DISABLED'}`);
    console.log(`💳 Stripe: ${STRIPE_WEBHOOK_SECRET ? 'Webhook configured' : 'NO webhook secret'}`);
    console.log(`📦 API Endpoints: /api/catalogo, /api/productos (resilience layer added)`);
    logger.info('SERVER_STARTED', {
        port: PORT,
        version: BACKEND_VERSION,
        railway: isRailway,
        authMode: 'httponly_cookie',
        corsOrigins: UNIQUE_ORIGINS.length,
        emailActive: !!resend,
        stripeWebhook: !!STRIPE_WEBHOOK_SECRET,
        cookieDomain: COOKIE_DOMAIN || 'not_set',
        safariIOSFix: true
    });
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