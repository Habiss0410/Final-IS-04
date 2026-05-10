'use strict';

const https   = require('https');
const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const selfsigned = require('selfsigned');

const app = express();
app.use(express.json());

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    console.log(`[SERVER] Received credentials: { username: '${username}', password: '${password}' }`);

    const VALID_USERS = { 'admin': 'Secret@123' };
    if (!VALID_USERS[username] || VALID_USERS[username] !== password) {
        return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }

    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const token  = `${header}.eyJ1c2VyIjoiYWRtaW4ifQ.secret123`;

    console.log(`[SERVER] Issuing token: ${token}`);
    return res.json({ status: 'ok', message: 'Login received', token, user: username });
});

app.get('/api/profile', (req, res) => {
    const auth = req.headers['authorization'];
    if (auth && auth.startsWith('Bearer ')) {
        return res.json({ status: 'ok', user: 'admin', role: 'superuser' });
    }
    return res.status(401).json({ status: 'error', message: 'Unauthorized' });
});

// Dùng cert cố định nếu có, tạo mới nếu chưa có
let pems;
if (fs.existsSync('cert.pem') && fs.existsSync('key.pem')) {
    pems = {
        cert: fs.readFileSync('cert.pem', 'utf8'),
        private: fs.readFileSync('key.pem', 'utf8')
    };
    console.log('[SERVER] Loaded existing certificate');
} else {
    pems = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
        days: 365, keySize: 2048, algorithm: 'sha256',
        extensions: [{
            name: 'subjectAltName',
            altNames: [
                { type: 2, value: 'localhost' },
                { type: 7, ip: '10.0.2.2' },
            ],
        }],
    });
    fs.writeFileSync('cert.pem', pems.cert);
    fs.writeFileSync('key.pem', pems.private);
    console.log('[SERVER] Generated new certificate');
}

https.createServer({
    key:  pems.private,
    cert: pems.cert,
}, app).listen(3000, '0.0.0.0', () => {
    console.log('[SERVER] HTTPS Listening on port 3000');
    console.log('[SERVER] Vulnerable server — ready for MITM demo');
});
