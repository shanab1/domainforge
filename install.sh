#!/bin/bash
#
# DomainForge CloudPanel Agent Installer
# 
# Run this on your CloudPanel server via SSH/PuTTY:
#   curl -sL https://raw.githubusercontent.com/YOUR_REPO/install-agent.sh | bash
#   OR
#   Copy and paste this entire script into PuTTY
#

set -e

echo "============================================"
echo "DomainForge CloudPanel Agent Installer"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use: sudo bash)"
    exit 1
fi

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Installing..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
fi

NODE_VERSION=$(node -v)
echo "✓ Node.js version: $NODE_VERSION"

# Create directories
echo ""
echo "Creating directories..."
mkdir -p /opt/domainforge-agent
mkdir -p /etc/domainforge-agent
mkdir -p /var/log

# Generate token if not exists
TOKEN_FILE="/etc/domainforge-agent/token"
if [ ! -f "$TOKEN_FILE" ]; then
    TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
    echo "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "✓ Generated new authentication token"
else
    TOKEN=$(cat "$TOKEN_FILE")
    echo "✓ Using existing authentication token"
fi

# Download/create the agent script
echo ""
echo "Installing agent..."
cat > /opt/domainforge-agent/agent.js << 'AGENTCODE'
#!/usr/bin/env node
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const CONFIG = {
    port: process.env.AGENT_PORT || 8443,
    token: process.env.AGENT_TOKEN || fs.existsSync('/etc/domainforge-agent/token') ? fs.readFileSync('/etc/domainforge-agent/token', 'utf8').trim() : '',
    clpctl: '/usr/bin/clpctl',
    sitesPath: '/home',
    sslKey: '/etc/domainforge-agent/server.key',
    sslCert: '/etc/domainforge-agent/server.crt',
    logFile: '/var/log/domainforge-agent.log'
};

function log(level, msg, data = null) {
    const ts = new Date().toISOString();
    const line = `[${ts}] [${level.toUpperCase()}] ${msg}${data ? ' ' + JSON.stringify(data) : ''}`;
    console.log(line);
    try { fs.appendFileSync(CONFIG.logFile, line + '\n'); } catch (e) {}
}

function runCmd(cmd, opts = {}) {
    try {
        return { success: true, output: execSync(cmd, { encoding: 'utf8', timeout: 60000, ...opts }).trim() };
    } catch (e) {
        return { success: false, error: e.message, output: e.stdout?.toString() || '' };
    }
}

function ensureDir(dir) { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); }

function generateCert() {
    ensureDir(path.dirname(CONFIG.sslCert));
    if (fs.existsSync(CONFIG.sslKey) && fs.existsSync(CONFIG.sslCert)) return;
    log('info', 'Generating SSL certificate...');
    runCmd(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${CONFIG.sslKey} -out ${CONFIG.sslCert} -subj "/CN=domainforge-agent"`);
}

function clpctl(args) { return runCmd(`${CONFIG.clpctl} ${args}`); }

function getSites() {
    const result = clpctl('site:list');
    if (!result.success) {
        try {
            const dirs = fs.readdirSync(CONFIG.sitesPath);
            const sites = [];
            for (const dir of dirs) {
                const htdocs = path.join(CONFIG.sitesPath, dir, 'htdocs');
                if (fs.existsSync(htdocs)) {
                    const stat = fs.statSync(path.join(CONFIG.sitesPath, dir));
                    sites.push({ domain: dir, type: 'static', created: stat.birthtime.toISOString(), path: htdocs });
                }
            }
            return { success: true, sites };
        } catch (e) { return { success: false, error: e.message }; }
    }
    const sites = result.output.split('\n').filter(l => l.trim()).map(line => {
        const parts = line.split(/\s+/);
        return { domain: parts[0], type: parts[1] || 'static', created: new Date().toISOString() };
    });
    return { success: true, sites };
}

function createSite(domain, type = 'static') {
    let result = clpctl(`site:add:static --domainName="${domain}"`);
    if (!result.success) result = clpctl(`site:add --domainName="${domain}" --siteType="static"`);
    return result;
}

function deleteSite(domain) { return clpctl(`site:delete --domainName="${domain}" --force`); }
function requestSSL(domain) { return clpctl(`lets-encrypt:install --domainName="${domain}"`); }

function writeFile(domain, filePath, content) {
    const sitePath = path.join(CONFIG.sitesPath, domain, 'htdocs');
    const fullPath = path.join(sitePath, filePath);
    const resolved = path.resolve(fullPath);
    if (!resolved.startsWith(path.resolve(sitePath))) return { success: false, error: 'Path traversal not allowed' };
    try {
        ensureDir(path.dirname(fullPath));
        fs.writeFileSync(fullPath, content, 'utf8');
        runCmd(`chown -R www-data:www-data "${path.dirname(fullPath)}"`);
        return { success: true };
    } catch (e) { return { success: false, error: e.message }; }
}

function extractZip(domain, filename, base64Content) {
    const sitePath = path.join(CONFIG.sitesPath, domain, 'htdocs');
    const tempZip = `/tmp/${filename}`;
    try {
        fs.writeFileSync(tempZip, Buffer.from(base64Content, 'base64'));
        const result = runCmd(`unzip -o "${tempZip}" -d "${sitePath}"`);
        fs.unlinkSync(tempZip);
        runCmd(`chown -R www-data:www-data "${sitePath}"`);
        return result;
    } catch (e) { return { success: false, error: e.message }; }
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(new Error('Invalid JSON')); } });
        req.on('error', reject);
    });
}

function sendJSON(res, status, data) {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Agent-Token'
    });
    res.end(JSON.stringify(data));
}

function auth(req) {
    if (!CONFIG.token) return true;
    return req.headers['x-agent-token'] === CONFIG.token;
}

async function handle(req, res) {
    if (req.method === 'OPTIONS') { sendJSON(res, 200, {}); return; }
    if (!auth(req)) { sendJSON(res, 401, { error: 'Unauthorized' }); return; }
    
    const url = new URL(req.url, `https://${req.headers.host}`);
    const p = url.pathname, m = req.method;
    log('info', `${m} ${p}`);
    
    try {
        if (p === '/api/health' && m === 'GET') {
            sendJSON(res, 200, { status: 'ok', version: '1.0.0', uptime: process.uptime(), cloudpanel: fs.existsSync(CONFIG.clpctl) });
            return;
        }
        if (p === '/api/sites' && m === 'GET') {
            const r = getSites();
            sendJSON(res, r.success ? 200 : 500, r.success ? { sites: r.sites } : { error: r.error });
            return;
        }
        if (p === '/api/sites' && m === 'POST') {
            const body = await parseBody(req);
            if (!body.domain) { sendJSON(res, 400, { error: 'Missing domain' }); return; }
            const r = createSite(body.domain, body.type);
            sendJSON(res, r.success ? 201 : 500, r.success ? { message: 'Site created', domain: body.domain } : { error: r.error || r.output });
            return;
        }
        
        let match;
        if ((match = p.match(/^\/api\/sites\/([^\/]+)$/)) && m === 'DELETE') {
            const r = deleteSite(decodeURIComponent(match[1]));
            sendJSON(res, r.success ? 200 : 500, r.success ? { message: 'Site deleted' } : { error: r.error || r.output });
            return;
        }
        if ((match = p.match(/^\/api\/sites\/([^\/]+)\/pagespeed$/)) && m === 'POST') {
            const r = clpctl(`site:pagespeed:enable --domainName="${decodeURIComponent(match[1])}"`);
            sendJSON(res, r.success ? 200 : 500, r);
            return;
        }
        if ((match = p.match(/^\/api\/sites\/([^\/]+)\/cloudflare-only$/)) && m === 'POST') {
            sendJSON(res, 200, { success: true, message: 'Configure in CloudPanel UI' });
            return;
        }
        if ((match = p.match(/^\/api\/sites\/([^\/]+)\/ssl$/)) && m === 'POST') {
            const r = requestSSL(decodeURIComponent(match[1]));
            sendJSON(res, r.success ? 200 : 500, r);
            return;
        }
        if ((match = p.match(/^\/api\/sites\/([^\/]+)\/files$/)) && m === 'POST') {
            const body = await parseBody(req);
            if (!body.path || body.content === undefined) { sendJSON(res, 400, { error: 'Missing path or content' }); return; }
            const r = writeFile(decodeURIComponent(match[1]), body.path, body.content);
            sendJSON(res, r.success ? 200 : 500, r);
            return;
        }
        if ((match = p.match(/^\/api\/sites\/([^\/]+)\/upload-zip$/)) && m === 'POST') {
            const body = await parseBody(req);
            if (!body.filename || !body.content) { sendJSON(res, 400, { error: 'Missing filename or content' }); return; }
            const r = extractZip(decodeURIComponent(match[1]), body.filename, body.content);
            sendJSON(res, r.success ? 200 : 500, r);
            return;
        }
        sendJSON(res, 404, { error: 'Not found' });
    } catch (e) {
        log('error', 'Request error', { error: e.message });
        sendJSON(res, 500, { error: e.message });
    }
}

generateCert();
const server = https.createServer({ key: fs.readFileSync(CONFIG.sslKey), cert: fs.readFileSync(CONFIG.sslCert) }, handle);
server.listen(CONFIG.port, '0.0.0.0', () => {
    log('info', '============================================');
    log('info', 'DomainForge CloudPanel Agent v1.0');
    log('info', `Listening on https://0.0.0.0:${CONFIG.port}`);
    log('info', `Token: ${CONFIG.token ? 'CONFIGURED' : 'NOT SET (INSECURE)'}`);
    log('info', '============================================');
});
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
AGENTCODE

chmod +x /opt/domainforge-agent/agent.js

# Create systemd service
echo ""
echo "Creating systemd service..."
cat > /etc/systemd/system/domainforge-agent.service << 'SERVICEEOF'
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
SERVICEEOF

# Reload systemd and start service
systemctl daemon-reload
systemctl enable domainforge-agent
systemctl restart domainforge-agent

# Open firewall port
if command -v ufw &> /dev/null; then
    ufw allow 8443/tcp
    echo "✓ Opened port 8443 in UFW firewall"
fi

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "============================================"
echo "✅ Installation Complete!"
echo "============================================"
echo ""
echo "Agent Status: $(systemctl is-active domainforge-agent)"
echo ""
echo "🔑 YOUR AUTHENTICATION TOKEN:"
echo "   $TOKEN"
echo ""
echo "📋 COPY THESE VALUES TO DOMAINFORGE:"
echo "   Server IP: $SERVER_IP"
echo "   Port: 8443"
echo "   Token: $TOKEN"
echo ""
echo "🔧 Useful Commands:"
echo "   View logs:    journalctl -u domainforge-agent -f"
echo "   Restart:      systemctl restart domainforge-agent"
echo "   Stop:         systemctl stop domainforge-agent"
echo "   Status:       systemctl status domainforge-agent"
echo ""
echo "🧪 Test the agent:"
echo "   curl -k https://localhost:8443/api/health"
echo ""
echo "============================================"
