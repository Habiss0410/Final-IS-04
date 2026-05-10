// dummy-server/server.js
// ─────────────────────────────────────────────────────────────
// Hardened HTTPS Server — Project 4 MITM Lab
// Nâng cấp bảo mật so với version gốc:
//   [1] TLS 1.2+ only  — block TLS 1.0, 1.1
//   [2] HSTS header    — force HTTPS cho mọi request
//   [3] Security headers — X-Content-Type, X-Frame, CSP
//   [4] Rate limiting  — chống brute force login
//   [5] Token expiry   — JWT-style token có thời hạn 15 phút
//   [6] Request validation — kiểm tra input trước khi xử lý
//   [7] Proxy detection — log cảnh báo nếu có proxy header
// ─────────────────────────────────────────────────────────────

'use strict';

const https      = require('https');
const express    = require('express');
const selfsigned = require('selfsigned');
const crypto     = require('crypto');
const fs         = require('fs');         
const forge      = require('node-forge');
const app = express();
app.use(express.json({ limit: '10kb' }));


// ─────────────────────────────────────────────
// [2][3] Security Headers Middleware
// ─────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'); // [2] HSTS
    res.setHeader('X-Content-Type-Options',    'nosniff');
    res.setHeader('X-Frame-Options',           'DENY');
    res.setHeader('X-XSS-Protection',          '1; mode=block');
    res.setHeader('Content-Security-Policy',   "default-src 'none'");
    res.setHeader('Cache-Control',             'no-store');
    next();
});


// ─────────────────────────────────────────────
// [7] Runtime Proxy Detection Middleware
// Log cảnh báo nếu phát hiện dấu hiệu bị intercept
// ─────────────────────────────────────────────
app.use((req, res, next) => {
    const suspiciousHeaders = ['x-forwarded-for', 'via', 'x-real-ip', 'forwarded', 'proxy-connection'];
    const detected = suspiciousHeaders.filter(h => req.headers[h]);
    if (detected.length > 0) {
        console.warn('[SECURITY] Proxy/Intercept headers detected:', detected.map(h => `${h}: ${req.headers[h]}`));
    }
    next();
});


// ─────────────────────────────────────────────
// [4] Rate Limiting — max 5 login / IP / 15 phút
// ─────────────────────────────────────────────
const loginAttempts = new Map();
const RATE_LIMIT    = 5;
const RATE_WINDOW   = 15 * 60 * 1000;

function checkRateLimit(ip) {
    const now   = Date.now();
    const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + RATE_WINDOW };
    if (now > entry.resetAt) {
        loginAttempts.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
        return { allowed: true, remaining: RATE_LIMIT - 1 };
    }
    if (entry.count >= RATE_LIMIT) {
        return { allowed: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    entry.count++;
    loginAttempts.set(ip, entry);
    return { allowed: true, remaining: RATE_LIMIT - entry.count };
}


// ─────────────────────────────────────────────
// [5] Token Store — expiry 15 phút
// ─────────────────────────────────────────────
const tokenStore = new Map();
const TOKEN_TTL  = 15 * 60 * 1000;

function generateToken(username) {
    const raw    = crypto.randomBytes(32).toString('hex');
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const token  = `${header}.${raw}`;
    tokenStore.set(token, { username, expiresAt: Date.now() + TOKEN_TTL, issuedAt: Date.now() });
    return token;
}

function validateToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7);
    const entry = tokenStore.get(token);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { tokenStore.delete(token); return null; }
    return entry;
}

// Dọn token hết hạn mỗi 5 phút
setInterval(() => {
    const now = Date.now();
    for (const [t, e] of tokenStore.entries()) { if (now > e.expiresAt) tokenStore.delete(t); }
}, 5 * 60 * 1000);


// ─────────────────────────────────────────────
// [6] Input Validation
// ─────────────────────────────────────────────
function validateLoginInput(body) {
    const errors = [];
    if (!body.username || typeof body.username !== 'string' || body.username.length < 1 || body.username.length > 64)
        errors.push('username: required string, 1–64 chars');
    if (!body.password || typeof body.password !== 'string' || body.password.length < 1 || body.password.length > 128)
        errors.push('password: required string, 1–128 chars');
    return errors;
}


// ─────────────────────────────────────────────
// POST /api/login
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';

    // [4] Rate limit
    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
        console.warn(`[SECURITY] Rate limit exceeded — IP: ${ip}`);
        return res.status(429).json({ status: 'error', message: 'Too many attempts', retryAfter: rate.retryAfter });
    }

    // [6] Validate input
    const errs = validateLoginInput(req.body);
    if (errs.length > 0) return res.status(400).json({ status: 'error', message: 'Invalid input', errors: errs });

    const { username, password } = req.body;

    // Log credentials — đây là điểm Burp intercept được khi chưa hardened
    console.log(`[SERVER] Login — username: ${username} | password: ${password} | IP: ${ip} | remaining: ${rate.remaining}`);

    const VALID_USERS = { 'admin': 'Secret@123' };
    if (!VALID_USERS[username] || VALID_USERS[username] !== password) {
        return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }

    // [5] Tạo token có thời hạn
    const token = generateToken(username);
    console.log(`[SERVER] Token issued for: ${username}`);

    return res.status(200).json({
        status:    'ok',
        message:   'Login successful',
        token,
        expiresIn: TOKEN_TTL / 1000,
        user:      username,
        issuedAt:  new Date().toISOString(),
    });
});


// ─────────────────────────────────────────────
// GET /api/profile — yêu cầu token hợp lệ
// Demo: dùng token đánh cắp → giả mạo được (trước hardening)
// ─────────────────────────────────────────────
app.get('/api/profile', (req, res) => {
    const entry = validateToken(req.headers['authorization']);
    if (!entry) return res.status(401).json({ status: 'error', message: 'Unauthorized — token invalid or expired' });
    console.log(`[SERVER] Profile accessed by: ${entry.username}`);
    return res.status(200).json({
        status:    'ok',
        username:  entry.username,
        role:      'admin',
        issuedAt:  new Date(entry.issuedAt).toISOString(),
        expiresAt: new Date(entry.expiresAt).toISOString(),
    });
});


// ─────────────────────────────────────────────
// GET /api/health
// ─────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
    res.status(200).json({ status: 'ok', tls: 'TLS 1.2+', timestamp: new Date().toISOString() });
});


// 404
app.use((_req, res) => res.status(404).json({ status: 'error', message: 'Not found' }));


// ─────────────────────────────────────────────
// [1] TLS 1.2+ với cơ chế SPKI Pinning tối ưu
// ─────────────────────────────────────────────
const attrs = [{ name: 'commonName', value: '10.0.2.2' }];
const CERT_PATH = './cert.pem';
const KEY_PATH  = './key.pem';

/**
 * Hàm tính toán mã PIN SHA-256 từ Public Key của chứng chỉ
 */
function calculateSPKIPin(pemCert) {
    try {
        const certData = pemCert.trim();
        const certForge = forge.pki.certificateFromPem(certData);
        const der = forge.asn1.toDer(forge.pki.certificateToAsn1(certForge)).getBytes();
        return crypto.createHash('sha256').update(Buffer.from(der, 'binary')).digest('base64');
    } catch (err) {
        throw new Error(`Pin Calculation Failed: ${err.message}`);
    }
}

async function startServer() {
    let pems;

    try {
        if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH) && fs.statSync(CERT_PATH).size > 10) {
            pems = {
                cert: fs.readFileSync(CERT_PATH, 'utf8'),
                key:  fs.readFileSync(KEY_PATH, 'utf8')
            };
            console.log('[SERVER] Loaded existing certificate');
        } else {
            console.log('[DEBUG] Running on Mac M2 - Node v24. Generating certificate...');
            const keys = forge.pki.rsa.generateKeyPair(2048);
            const cert = forge.pki.createCertificate();
            cert.publicKey = keys.publicKey;
            cert.serialNumber = '01';
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        
            const attrs = [{ name: 'commonName', value: 'localhost' }];
            cert.setSubject(attrs);
            cert.setIssuer(attrs);
            cert.setExtensions([{
                name: 'subjectAltName',
                altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '10.0.2.2' }]
            }]);
        
            cert.sign(keys.privateKey, forge.md.sha256.create());
        
            pems = {
                cert: forge.pki.certificateToPem(cert),
                key:  forge.pki.privateKeyToPem(keys.privateKey)
            };
        
            fs.writeFileSync(CERT_PATH, pems.cert);
            fs.writeFileSync(KEY_PATH,  pems.key);
            console.log('[SERVER] Certificate created successfully!');
        }

        const hash = calculateSPKIPin(pems.cert);

        https.createServer({
            key:  pems.key,
            cert: pems.cert,
            minVersion: 'TLSv1.2',
            ciphers: [
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
            ].join(':'),
            honorCipherOrder: true,
        }, app).listen(3000, '0.0.0.0', () => {
            console.log('\n[SERVER] 🛡️  Hardened HTTPS Server — Active');
            console.log(`[SERVER]  SHA-256 PIN: sha256/${hash}`);
            console.log('[SERVER] ──────────────────────────────────────────\n');
        });

    } catch (criticalErr) {
        console.error('[CRITICAL] Server failed to initialize:', criticalErr.message);
        process.exit(1);
    }
}

// Chạy server
startServer();