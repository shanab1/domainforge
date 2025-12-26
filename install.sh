#!/bin/bash
#
# DomainForge CloudPanel Agent Installer v1.1
# Run on your CloudPanel server: curl -sL URL | sudo bash
#

set -e

echo ""
echo "============================================"
echo "  DomainForge CloudPanel Agent Installer"
echo "============================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root: sudo bash $0"
    exit 1
fi

echo "[1/7] Checking Node.js..."
if ! command -v node &> /dev/null; then
    echo "       Node.js not found. Installing..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1
    apt-get install -y nodejs > /dev/null 2>&1
fi
echo "       Node.js $(node -v) installed"

echo "[2/7] Creating directories..."
mkdir -p /opt/domainforge-agent
mkdir -p /etc/domainforge-agent
mkdir -p /var/log

echo "[3/7] Generating authentication token..."
TOKEN_FILE="/etc/domainforge-agent/token"
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
    echo "       Using existing token"
else
    TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
    echo "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "       New token generated"
fi

echo "[4/7] Installing agent..."
cat > /opt/domainforge-agent/agent.js << 'AGENT_EOF'
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PORT = process.env.AGENT_PORT || 8443;
const TOKEN = fs.existsSync('/etc/domainforge-agent/token') 
    ? fs.readFileSync('/etc/domainforge-agent/token', 'utf8').trim() 
    : '';
const CLPCTL = '/usr/bin/clpctl';
const SITES_PATH = '/home';
const SSL_KEY = '/etc/domainforge-agent/server.key';
const SSL_CERT = '/etc/domainforge-agent/server.crt';

function log(msg) {
    const ts = new Date().toISOString();
    console.log(`[${ts}] ${msg}`);
}

function runCmd(cmd) {
    try {
        return { ok: true, out: execSync(cmd, { encoding: 'utf8', timeout: 60000 }).trim() };
    } catch (e) {
        return { ok: false, err: e.message };
    }
}

function ensureSSL() {
    if (fs.existsSync(SSL_KEY) && fs.existsSync(SSL_CERT)) return;
    log('Generating SSL certificate...');
    runCmd(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${SSL_KEY} -out ${SSL_CERT} -subj "/CN=domainforge-agent" 2>/dev/null`);
}

function getSites() {
    const result = runCmd(`${CLPCTL} site:list 2>/dev/null`);
    if (result.ok && result.out) {
        return result.out.split('\n').filter(l => l.trim()).map(l => {
            const p = l.trim().split(/\s+/);
            return { domain: p[0], type: p[1] || 'static', created: new Date().toISOString() };
        });
    }
    // Fallback: scan /home
    try {
        return fs.readdirSync(SITES_PATH).filter(d => {
            return fs.existsSync(path.join(SITES_PATH, d, 'htdocs'));
        }).map(d => {
            const stat = fs.statSync(path.join(SITES_PATH, d));
            return { domain: d, type: 'static', created: stat.birthtime.toISOString() };
        });
    } catch (e) { return []; }
}

function createSite(domain) {
    let r = runCmd(`${CLPCTL} site:add:static --domainName="${domain}" 2>&1`);
    if (!r.ok) r = runCmd(`${CLPCTL} site:add --domainName="${domain}" --siteType="static" 2>&1`);
    return r;
}

function deleteSite(domain) {
    return runCmd(`${CLPCTL} site:delete --domainName="${domain}" --force 2>&1`);
}

function requestSSL(domain) {
    return runCmd(`${CLPCTL} lets-encrypt:install --domainName="${domain}" 2>&1`);
}

function writeFile(domain, filePath, content) {
    const sitePath = path.join(SITES_PATH, domain, 'htdocs');
    const fullPath = path.join(sitePath, filePath);
    if (!path.resolve(fullPath).startsWith(path.resolve(sitePath))) {
        return { ok: false, err: 'Invalid path' };
    }
    try {
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, content);
        runCmd(`chown -R www-data:www-data "${sitePath}" 2>/dev/null`);
        return { ok: true };
    } catch (e) { return { ok: false, err: e.message }; }
}

function extractZip(domain, filename, base64Data) {
    const sitePath = path.join(SITES_PATH, domain, 'htdocs');
    const tmpZip = `/tmp/${filename}`;
    try {
        fs.writeFileSync(tmpZip, Buffer.from(base64Data, 'base64'));
        const r = runCmd(`unzip -o "${tmpZip}" -d "${sitePath}" 2>&1`);
        fs.unlinkSync(tmpZip);
        runCmd(`chown -R www-data:www-data "${sitePath}" 2>/dev/null`);
        return r;
    } catch (e) { return { ok: false, err: e.message }; }
}

function send(res, code, data) {
    res.writeHead(code, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Agent-Token'
    });
    res.end(JSON.stringify(data));
}

function getBody(req) {
    return new Promise(resolve => {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            try { resolve(JSON.parse(body)); } catch (e) { resolve({}); }
        });
    });
}

async function handler(req, res) {
    if (req.method === 'OPTIONS') { send(res, 200, {}); return; }
    
    // Auth check
    if (TOKEN && req.headers['x-agent-token'] !== TOKEN) {
        log(`Unauthorized: ${req.url}`);
        send(res, 401, { error: 'Unauthorized' });
        return;
    }
    
    const url = req.url.split('?')[0];
    const method = req.method;
    log(`${method} ${url}`);
    
    // Routes
    if (url === '/api/health' && method === 'GET') {
        send(res, 200, { status: 'ok', version: '1.1.0', node: process.version });
        return;
    }
    
    if (url === '/api/sites' && method === 'GET') {
        send(res, 200, { sites: getSites() });
        return;
    }
    
    if (url === '/api/sites' && method === 'POST') {
        const body = await getBody(req);
        if (!body.domain) { send(res, 400, { error: 'Missing domain' }); return; }
        const r = createSite(body.domain);
        send(res, r.ok ? 201 : 500, r.ok ? { message: 'Created', domain: body.domain } : { error: r.err || r.out });
        return;
    }
    
    // /api/sites/:domain
    const siteMatch = url.match(/^\/api\/sites\/([^\/]+)$/);
    if (siteMatch && method === 'DELETE') {
        const domain = decodeURIComponent(siteMatch[1]);
        const r = deleteSite(domain);
        send(res, r.ok ? 200 : 500, r.ok ? { message: 'Deleted' } : { error: r.err || r.out });
        return;
    }
    
    // /api/sites/:domain/ssl
    const sslMatch = url.match(/^\/api\/sites\/([^\/]+)\/ssl$/);
    if (sslMatch && method === 'POST') {
        const domain = decodeURIComponent(sslMatch[1]);
        const r = requestSSL(domain);
        send(res, r.ok ? 200 : 500, r);
        return;
    }
    
    // /api/sites/:domain/files
    const fileMatch = url.match(/^\/api\/sites\/([^\/]+)\/files$/);
    if (fileMatch && method === 'POST') {
        const domain = decodeURIComponent(fileMatch[1]);
        const body = await getBody(req);
        if (!body.path || body.content === undefined) { send(res, 400, { error: 'Missing path/content' }); return; }
        const r = writeFile(domain, body.path, body.content);
        send(res, r.ok ? 200 : 500, r);
        return;
    }
    
    // /api/sites/:domain/upload-zip
    const zipMatch = url.match(/^\/api\/sites\/([^\/]+)\/upload-zip$/);
    if (zipMatch && method === 'POST') {
        const domain = decodeURIComponent(zipMatch[1]);
        const body = await getBody(req);
        if (!body.filename || !body.content) { send(res, 400, { error: 'Missing filename/content' }); return; }
        const r = extractZip(domain, body.filename, body.content);
        send(res, r.ok ? 200 : 500, r);
        return;
    }
    
    // /api/sites/:domain/pagespeed
    const psMatch = url.match(/^\/api\/sites\/([^\/]+)\/pagespeed$/);
    if (psMatch && method === 'POST') {
        const domain = decodeURIComponent(psMatch[1]);
        const r = runCmd(`${CLPCTL} site:pagespeed:enable --domainName="${domain}" 2>&1`);
        send(res, r.ok ? 200 : 500, r);
        return;
    }
    
    // /api/sites/:domain/cloudflare-only
    const cfMatch = url.match(/^\/api\/sites\/([^\/]+)\/cloudflare-only$/);
    if (cfMatch && method === 'POST') {
        send(res, 200, { ok: true, message: 'Configure via CloudPanel UI' });
        return;
    }
    
    send(res, 404, { error: 'Not found' });
}

// Start server
ensureSSL();
const server = https.createServer({
    key: fs.readFileSync(SSL_KEY),
    cert: fs.readFileSync(SSL_CERT)
}, handler);

server.listen(PORT, '0.0.0.0', () => {
    log('========================================');
    log('DomainForge CloudPanel Agent v1.1');
    log(`Listening on https://0.0.0.0:${PORT}`);
    log(`Token: ${TOKEN ? 'CONFIGURED' : 'NOT SET'}`);
    log('========================================');
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
AGENT_EOF

echo "[5/7] Creating systemd service..."
cat > /etc/systemd/system/domainforge-agent.service << 'SERVICE_EOF'
[Unit]
Description=DomainForge CloudPanel Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/domainforge-agent
ExecStart=/usr/bin/node /opt/domainforge-agent/agent.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
SERVICE_EOF

echo "[6/7] Starting service..."
systemctl daemon-reload
systemctl enable domainforge-agent > /dev/null 2>&1
systemctl restart domainforge-agent

sleep 2

echo "[7/7] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow 8443/tcp > /dev/null 2>&1
    echo "       Port 8443 opened"
fi

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "============================================"
echo "  INSTALLATION COMPLETE"
echo "============================================"
echo ""
echo "  Status: $(systemctl is-active domainforge-agent)"
echo ""
echo "  YOUR CONNECTION DETAILS:"
echo "  -------------------------"
echo "  Server IP: $SERVER_IP"
echo "  Port:      8443"
echo "  Token:     $TOKEN"
echo ""
echo "  Copy these into DomainForge Integrations!"
echo ""
echo "  Test locally:"
echo "  curl -k https://localhost:8443/api/health"
echo ""
echo "============================================"
