#!/bin/bash
#
# DomainForge CloudPanel Agent Installer v1.3
# 
# Usage: curl -sL YOUR_URL/install.sh | sudo bash
#
# This script installs a lightweight HTTP API agent on your CloudPanel server
# that allows DomainForge to manage sites, SSL certificates, and files.
#
# Requirements:
#   - CloudPanel installed
#   - Root access
#   - Port 8080 available
#
# After installation:
#   1. Create a DNS record pointing to this server (e.g., agent.yourdomain.com)
#   2. Make sure the DNS record is NOT proxied through Cloudflare (gray cloud)
#   3. Enter the hostname, port (8080), and token in DomainForge
#

set -e

echo ""
echo "============================================"
echo "  DomainForge CloudPanel Agent Installer"
echo "  Version 1.3"
echo "============================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root: sudo bash install.sh"
    exit 1
fi

echo "[1/6] Checking Node.js..."
if ! command -v node &> /dev/null; then
    echo "       Installing Node.js 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1
    apt-get install -y nodejs > /dev/null 2>&1
fi
echo "       ✓ Node.js $(node -v)"

echo "[2/6] Creating directories..."
mkdir -p /opt/domainforge-agent
mkdir -p /etc/domainforge-agent
echo "       ✓ Directories created"

echo "[3/6] Generating authentication token..."
TOKEN_FILE="/etc/domainforge-agent/token"
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
    echo "       ✓ Using existing token"
else
    TOKEN=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
    echo "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "       ✓ New token generated"
fi

echo "[4/6] Installing agent..."
cat > /opt/domainforge-agent/agent.js << 'AGENT_EOF'
// DomainForge CloudPanel Agent v1.3
// HTTP API for managing CloudPanel sites

const http = require('http');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const PORT = 8080;
const TOKEN = fs.existsSync('/etc/domainforge-agent/token') 
    ? fs.readFileSync('/etc/domainforge-agent/token', 'utf8').trim() 
    : '';
const CLPCTL = '/usr/bin/clpctl';
const SITES_PATH = '/home';

// Logging
const log = (level, msg) => {
    const ts = new Date().toISOString();
    console.log(`[${ts}] [${level}] ${msg}`);
};

// Execute shell command
const run = cmd => {
    try {
        const out = execSync(cmd, { encoding: 'utf8', timeout: 120000 }).trim();
        return { ok: true, out };
    } catch (e) {
        return { ok: false, err: e.stderr || e.message, out: e.stdout || '' };
    }
};

// Get list of sites
const getSites = () => {
    const r = run(`${CLPCTL} site:list 2>/dev/null`);
    if (r.ok && r.out) {
        return r.out.split('\n').filter(l => l.trim()).map(l => {
            const parts = l.trim().split(/\s+/);
            return { domain: parts[0], type: parts[1] || 'static' };
        });
    }
    // Fallback: scan /home directory
    try {
        return fs.readdirSync(SITES_PATH)
            .filter(d => fs.existsSync(path.join(SITES_PATH, d, 'htdocs')))
            .map(d => ({ domain: d, type: 'static' }));
    } catch { 
        return []; 
    }
};

// Create a new site
const createSite = domain => {
    // Generate a site user from the domain (remove dots, truncate to 32 chars)
    const siteUser = domain.replace(/\./g, '').substring(0, 32).toLowerCase();
    // Generate a random password
    const sitePass = require('crypto').randomBytes(16).toString('hex');
    
    // CloudPanel 6.x requires: --domainName, --siteUser, --siteUserPassword
    let r = run(`${CLPCTL} site:add:static --domainName="${domain}" --siteUser="${siteUser}" --siteUserPassword="${sitePass}" 2>&1`);
    return r;
};

// Delete a site
const deleteSite = domain => {
    return run(`${CLPCTL} site:delete --domainName="${domain}" --force 2>&1`);
};

// Request SSL certificate
const requestSSL = domain => {
    return run(`${CLPCTL} lets-encrypt:install --domainName="${domain}" 2>&1`);
};

// Enable PageSpeed (not available in CloudPanel 6.x - just return success)
const enablePageSpeed = domain => {
    // CloudPanel 6.x doesn't have pagespeed commands
    // Return success so provisioning continues
    return { ok: true, out: 'PageSpeed not available in CloudPanel 6.x' };
};

// Find the actual site directory (CloudPanel uses siteUser as directory name)
const findSiteDir = domain => {
    // First try exact domain match
    let sitePath = path.join(SITES_PATH, domain, 'htdocs');
    if (fs.existsSync(sitePath)) return sitePath;
    
    // Try siteUser format (domain without dots)
    const siteUser = domain.replace(/\./g, '').toLowerCase();
    sitePath = path.join(SITES_PATH, siteUser, 'htdocs');
    if (fs.existsSync(sitePath)) return sitePath;
    
    // Search for directory containing the domain in clp config or by pattern
    try {
        const dirs = fs.readdirSync(SITES_PATH);
        for (const dir of dirs) {
            const htdocs = path.join(SITES_PATH, dir, 'htdocs');
            if (fs.existsSync(htdocs)) {
                // Check if this might be our site
                if (dir.toLowerCase() === siteUser || 
                    dir.toLowerCase().includes(domain.split('.')[0].toLowerCase())) {
                    return htdocs;
                }
            }
        }
    } catch {}
    
    return null;
};

// Write a file to a site
const writeFile = (domain, filePath, content) => {
    const basePath = findSiteDir(domain);
    if (!basePath) {
        return { ok: false, err: `Site directory not found for ${domain}` };
    }
    
    const fullPath = path.join(basePath, filePath);
    
    // Security: prevent path traversal
    if (!path.resolve(fullPath).startsWith(path.resolve(basePath))) {
        return { ok: false, err: 'Invalid path - traversal not allowed' };
    }
    
    try {
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, content);
        run(`chown -R www-data:www-data "${basePath}" 2>/dev/null`);
        return { ok: true };
    } catch (e) {
        return { ok: false, err: e.message };
    }
};

// Extract ZIP file to a site
const extractZip = (domain, filename, base64Content) => {
    const basePath = findSiteDir(domain);
    if (!basePath) {
        return { ok: false, err: `Site directory not found for ${domain}` };
    }
    
    const tempPath = `/tmp/${Date.now()}-${filename}`;
    
    try {
        // Decode and write ZIP
        fs.writeFileSync(tempPath, Buffer.from(base64Content, 'base64'));
        
        // Extract
        const r = run(`unzip -o "${tempPath}" -d "${basePath}" 2>&1`);
        
        // Cleanup
        try { fs.unlinkSync(tempPath); } catch {}
        
        // Fix permissions
        run(`chown -R www-data:www-data "${basePath}" 2>/dev/null`);
        
        return r;
    } catch (e) {
        try { fs.unlinkSync(tempPath); } catch {}
        return { ok: false, err: e.message };
    }
};

// Send JSON response with CORS headers
const sendJSON = (res, statusCode, data) => {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Agent-Token'
    });
    res.end(JSON.stringify(data));
};

// Parse request body as JSON
const parseBody = req => new Promise(resolve => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        try {
            resolve(JSON.parse(body));
        } catch {
            resolve({});
        }
    });
});

// Main request handler
const handleRequest = async (req, res) => {
    const url = req.url.split('?')[0];
    const method = req.method;
    
    // CORS preflight
    if (method === 'OPTIONS') {
        sendJSON(res, 204, {});
        return;
    }
    
    // Authentication
    if (TOKEN && req.headers['x-agent-token'] !== TOKEN) {
        log('WARN', `Unauthorized request to ${url}`);
        sendJSON(res, 401, { error: 'Unauthorized' });
        return;
    }
    
    log('INFO', `${method} ${url}`);
    
    try {
        // Health check
        if (url === '/api/health' && method === 'GET') {
            sendJSON(res, 200, { 
                status: 'ok', 
                version: '1.3.0',
                cloudpanel: fs.existsSync(CLPCTL)
            });
            return;
        }
        
        // List sites
        if (url === '/api/sites' && method === 'GET') {
            sendJSON(res, 200, { sites: getSites() });
            return;
        }
        
        // Create site
        if (url === '/api/sites' && method === 'POST') {
            const body = await parseBody(req);
            if (!body.domain) {
                sendJSON(res, 400, { error: 'Missing domain' });
                return;
            }
            const r = createSite(body.domain);
            sendJSON(res, r.ok ? 201 : 500, 
                r.ok ? { message: 'Site created', domain: body.domain } : { error: r.err || r.out }
            );
            return;
        }
        
        // Route: /api/sites/:domain
        let match;
        
        // Delete site
        if ((match = url.match(/^\/api\/sites\/([^\/]+)$/)) && method === 'DELETE') {
            const domain = decodeURIComponent(match[1]);
            const r = deleteSite(domain);
            sendJSON(res, r.ok ? 200 : 500, 
                r.ok ? { message: 'Site deleted' } : { error: r.err || r.out }
            );
            return;
        }
        
        // Request SSL
        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/ssl$/)) && method === 'POST') {
            const domain = decodeURIComponent(match[1]);
            const r = requestSSL(domain);
            sendJSON(res, r.ok ? 200 : 500, r);
            return;
        }
        
        // Write file
        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/files$/)) && method === 'POST') {
            const domain = decodeURIComponent(match[1]);
            const body = await parseBody(req);
            if (!body.path || body.content === undefined) {
                sendJSON(res, 400, { error: 'Missing path or content' });
                return;
            }
            const r = writeFile(domain, body.path, body.content);
            sendJSON(res, r.ok ? 200 : 500, r);
            return;
        }
        
        // Upload ZIP
        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/upload-zip$/)) && method === 'POST') {
            const domain = decodeURIComponent(match[1]);
            const body = await parseBody(req);
            if (!body.filename || !body.content) {
                sendJSON(res, 400, { error: 'Missing filename or content' });
                return;
            }
            const r = extractZip(domain, body.filename, body.content);
            sendJSON(res, r.ok ? 200 : 500, r);
            return;
        }
        
        // Enable PageSpeed
        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/pagespeed$/)) && method === 'POST') {
            const domain = decodeURIComponent(match[1]);
            const r = enablePageSpeed(domain);
            sendJSON(res, r.ok ? 200 : 500, r);
            return;
        }
        
        // Cloudflare-only mode (placeholder)
        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/cloudflare-only$/)) && method === 'POST') {
            sendJSON(res, 200, { ok: true, message: 'Configure via CloudPanel UI' });
            return;
        }
        
        // 404
        sendJSON(res, 404, { error: 'Endpoint not found' });
        
    } catch (e) {
        log('ERROR', `Request failed: ${e.message}`);
        sendJSON(res, 500, { error: e.message });
    }
};

// Start server
http.createServer(handleRequest).listen(PORT, '0.0.0.0', () => {
    log('INFO', '========================================');
    log('INFO', 'DomainForge CloudPanel Agent v1.3');
    log('INFO', `Listening on http://0.0.0.0:${PORT}`);
    log('INFO', `Token: ${TOKEN ? 'CONFIGURED' : 'NOT SET (insecure)'}`);
    log('INFO', `CloudPanel: ${fs.existsSync(CLPCTL) ? 'Found' : 'Not found'}`);
    log('INFO', '========================================');
});

// Handle shutdown
process.on('SIGTERM', () => { log('INFO', 'Shutting down...'); process.exit(0); });
process.on('SIGINT', () => { log('INFO', 'Shutting down...'); process.exit(0); });
AGENT_EOF

echo "       ✓ Agent installed"

echo "[5/6] Creating systemd service..."
cat > /etc/systemd/system/domainforge-agent.service << 'SERVICE_EOF'
[Unit]
Description=DomainForge CloudPanel Agent
Documentation=https://github.com/shanab1/domainforge
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/domainforge-agent
ExecStart=/usr/bin/node /opt/domainforge-agent/agent.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable domainforge-agent >/dev/null 2>&1
systemctl restart domainforge-agent
sleep 2
echo "       ✓ Service created and started"

echo "[6/6] Configuring firewall..."
if command -v ufw &>/dev/null; then
    ufw allow 8080/tcp >/dev/null 2>&1
    echo "       ✓ Port 8080 opened in UFW"
else
    echo "       ⚠ UFW not found, manually open port 8080 if needed"
fi

# Get server IP
SERVER_IP=$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
SERVICE_STATUS=$(systemctl is-active domainforge-agent 2>/dev/null || echo "unknown")

echo ""
echo "============================================"
echo "  ✅ INSTALLATION COMPLETE"
echo "============================================"
echo ""
echo "  Service Status: $SERVICE_STATUS"
echo ""
echo "  ┌─────────────────────────────────────────┐"
echo "  │  COPY THESE TO DOMAINFORGE:             │"
echo "  ├─────────────────────────────────────────┤"
echo "  │  Server: $SERVER_IP                     "
echo "  │  Port:   8080                           │"
echo "  │  Token:  $TOKEN"
echo "  └─────────────────────────────────────────┘"
echo ""
echo "  ⚠️  IMPORTANT: If using Cloudflare..."
echo "  Create a DNS record (e.g., agent.yourdomain.com)"
echo "  pointing to this server with PROXY DISABLED"
echo "  (gray cloud, not orange)"
echo ""
echo "  Test locally:"
echo "  curl -H \"X-Agent-Token: $TOKEN\" http://localhost:8080/api/health"
echo ""
echo "  View logs:"
echo "  journalctl -u domainforge-agent -f"
echo ""
echo "============================================"
