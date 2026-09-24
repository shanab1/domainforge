#!/bin/bash
#
# DomainForge CloudPanel Agent Installer v1.5
#
# Usage: curl -sL https://raw.githubusercontent.com/shanab1/domainforge/main/install.sh | sudo bash
#
# Changes from 1.3:
#   - Node.js step no longer hides its output. A hang and a failure used to
#     look identical because everything went to /dev/null.
#   - Waits for apt locks instead of appearing to freeze. On a fresh server
#     unattended-upgrades commonly holds them for several minutes on first boot.
#   - Every apt call reads from /dev/null. When the script is piped into bash,
#     stdin IS the script, so any prompt would otherwise eat the rest of it.
#   - Non-interactive frontends set, so needrestart cannot open a dialog and
#     wait forever on Ubuntu 22.04+.
#   - Installs a supported Node.js. Node 20 reached end of life on 2026-04-30.
#   - Falls back to IPv4 when the NodeSource fetch stalls, which is common on
#     hosts with broken IPv6.
#   - Verifies node actually works before continuing.
#   - Full transcript at /var/log/domainforge-install.log
#

set -euo pipefail

NODE_PREFERRED=24          # Active LTS
NODE_FALLBACK=22           # Maintenance LTS
NODE_MINIMUM=18            # the agent needs nothing newer than this
LOG=/var/log/domainforge-install.log
APT_OPTS=(-o DPkg::Lock::Timeout=600)

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

: > "$LOG" 2>/dev/null || LOG=/tmp/domainforge-install.log

say()  { echo "$@"; }
step() { echo ""; echo "$@"; }
ok()   { echo "       ✓ $*"; }
warn() { echo "       ⚠ $*"; }
die()  {
    echo ""
    echo "[ERROR] $*"
    echo "        Full log: $LOG"
    echo "        Last few lines:"
    tail -n 15 "$LOG" 2>/dev/null | sed 's/^/        | /'
    exit 1
}

echo ""
echo "============================================"
echo "  DomainForge CloudPanel Agent Installer"
echo "  Version 1.5"
echo "============================================"
echo ""
echo "  Log: $LOG"

[ "${EUID:-$(id -u)}" -eq 0 ] || die "Please run as root: curl -sL ... | sudo bash"

# ------------------------------------------------------------------
# apt locks
# ------------------------------------------------------------------
wait_for_apt() {
    command -v fuser >/dev/null 2>&1 || return 0
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock \
                /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ "$waited" -eq 0 ]; then
            say "       Another package manager holds the apt lock."
            say "       That is usually unattended-upgrades on a freshly built server."
            say "       Waiting for it to finish (up to 10 minutes)..."
        fi
        sleep 5
        waited=$((waited + 5))
        [ $((waited % 30)) -eq 0 ] && say "       still waiting... ${waited}s"
        if [ "$waited" -ge 600 ]; then
            say ""
            say "       Still locked after 10 minutes. Find the holder with:"
            say "         sudo fuser -v /var/lib/dpkg/lock-frontend"
            say "         ps aux | grep -E 'apt|dpkg|unattended'"
            die "apt is locked by another process"
        fi
    done
}

# ------------------------------------------------------------------
# 1. Node.js
# ------------------------------------------------------------------
step "[1/7] Checking Node.js..."

node_major() {
    command -v node >/dev/null 2>&1 || return 1
    node -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/'
}

fetch_nodesource() {
    local ver="$1" out="$2"
    # A stalled IPv6 route is the usual cause of an apparent freeze here, so
    # give it a short leash and then force IPv4.
    if curl -fsSL --connect-timeout 15 --max-time 90 \
         "https://deb.nodesource.com/setup_${ver}.x" -o "$out" 2>>"$LOG"; then
        return 0
    fi
    say "       Fetch stalled or failed, retrying over IPv4..."
    curl -4 -fsSL --connect-timeout 15 --max-time 90 \
         "https://deb.nodesource.com/setup_${ver}.x" -o "$out" 2>>"$LOG"
}

install_node() {
    local ver="$1"
    say "       Installing Node.js ${ver} from NodeSource..."
    local setup=/tmp/nodesource_setup.sh
    rm -f "$setup"

    fetch_nodesource "$ver" "$setup" || { warn "Could not download the NodeSource setup script for ${ver}"; return 1; }

    # Run from a file rather than 'bash -', which would read from stdin and
    # collide with this script being piped into bash.
    say "       Adding the repository (this updates apt, it can take a minute)..."
    wait_for_apt
    bash "$setup" </dev/null >>"$LOG" 2>&1 || { warn "NodeSource repository setup failed for ${ver}"; return 1; }

    say "       Installing the nodejs package..."
    wait_for_apt
    apt-get install -y "${APT_OPTS[@]}" nodejs </dev/null >>"$LOG" 2>&1 \
        || { warn "apt-get install nodejs failed for ${ver}"; return 1; }
    return 0
}

CURRENT_MAJOR="$(node_major || true)"

if [ -n "${CURRENT_MAJOR:-}" ] && [ "$CURRENT_MAJOR" -ge "$NODE_MINIMUM" ] 2>/dev/null; then
    ok "Node.js $(node -v) already present"
    if [ "$CURRENT_MAJOR" -lt 22 ]; then
        warn "Node.js ${CURRENT_MAJOR} is past end of life. The agent will run, but consider upgrading."
    fi
else
    if [ -n "${CURRENT_MAJOR:-}" ]; then
        say "       Found Node.js ${CURRENT_MAJOR}, which is too old. Upgrading..."
    fi
    wait_for_apt
    say "       Refreshing package lists..."
    apt-get update "${APT_OPTS[@]}" </dev/null >>"$LOG" 2>&1 || warn "apt-get update reported a problem, continuing"

    if ! install_node "$NODE_PREFERRED"; then
        say "       Falling back to Node.js ${NODE_FALLBACK}..."
        if ! install_node "$NODE_FALLBACK"; then
            say "       Falling back to the distribution's own nodejs package..."
            wait_for_apt
            apt-get install -y "${APT_OPTS[@]}" nodejs </dev/null >>"$LOG" 2>&1 \
                || die "Could not install Node.js by any route. See the log."
        fi
    fi

    CURRENT_MAJOR="$(node_major || true)"
    [ -n "${CURRENT_MAJOR:-}" ] || die "Node.js still is not on PATH after installing"
    [ "$CURRENT_MAJOR" -ge "$NODE_MINIMUM" ] 2>/dev/null \
        || die "Installed Node.js ${CURRENT_MAJOR} is older than the required ${NODE_MINIMUM}"
    ok "Node.js $(node -v) installed"
fi

node -e 'process.exit(0)' >>"$LOG" 2>&1 || die "Node.js is installed but will not run. See the log."

# ------------------------------------------------------------------
# 2. Directories
# ------------------------------------------------------------------
step "[2/7] Creating directories..."
mkdir -p /opt/domainforge-agent /etc/domainforge-agent
ok "Directories created"

# ------------------------------------------------------------------
# 3. Token
# ------------------------------------------------------------------
step "[3/7] Generating authentication token..."
TOKEN_FILE="/etc/domainforge-agent/token"
if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
    TOKEN="$(cat "$TOKEN_FILE")"
    ok "Using the existing token"
else
    TOKEN="$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 32)"
    [ "${#TOKEN}" -eq 32 ] || die "Could not generate a token (is openssl installed?)"
    printf '%s' "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    ok "New token generated"
fi

# ------------------------------------------------------------------
# 4. Agent
# ------------------------------------------------------------------
step "[4/7] Installing agent..."
cat > /opt/domainforge-agent/agent.js << 'AGENT_EOF'
// DomainForge CloudPanel Agent v1.6
// (+EIMS file-delete, +site creation dates, +PHP sites, +origin certificates)
// HTTP API for managing CloudPanel sites

const http = require('http');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PORT = 8080;
const TOKEN = fs.existsSync('/etc/domainforge-agent/token')
    ? fs.readFileSync('/etc/domainforge-agent/token', 'utf8').trim()
    : '';
const CLPCTL = '/usr/bin/clpctl';
const SITES_PATH = '/home';
const CERT_DIR = '/etc/domainforge-agent/certs';

// CloudPanel gives every site its own user and runs that site's PHP-FPM pool
// as that user. Writing files as www-data leaves PHP unable to read them,
// which shows up as 403s and blank pages, so always hand ownership back.
const ownerFor = basePath => {
    const rel = String(basePath).startsWith(SITES_PATH + '/')
        ? String(basePath).slice(SITES_PATH.length + 1)
        : '';
    const user = rel.split('/')[0];
    return /^[A-Za-z0-9._-]+$/.test(user) ? user : 'www-data';
};
const fixOwnership = basePath => {
    const owner = ownerFor(basePath);
    return run(`chown -R ${owner}:${owner} "${basePath}" 2>/dev/null`);
};

// Highest PHP version installed, which is what a new site should use.
const phpVersions = () => {
    const found = [];
    try {
        for (const d of fs.readdirSync('/etc/php')) {
            if (/^\d+\.\d+$/.test(d) && fs.existsSync(path.join('/etc/php', d, 'fpm'))) found.push(d);
        }
    } catch {}
    found.sort((a, b) => parseFloat(a) - parseFloat(b));
    return found;
};

const log = (level, msg) => {
    const ts = new Date().toISOString();
    console.log(`[${ts}] [${level}] ${msg}`);
};

const run = cmd => {
    try {
        const out = execSync(cmd, { encoding: 'utf8', timeout: 120000 }).trim();
        return { ok: true, out };
    } catch (e) {
        return { ok: false, err: e.stderr || e.message, out: e.stdout || '' };
    }
};

const getSites = () => {
    const sites = [];
    try {
        const dirs = fs.readdirSync(SITES_PATH);
        for (const dir of dirs) {
            if (dir === 'clp' || dir === 'mysql' || dir.startsWith('.')) continue;
            const htdocsPath = path.join(SITES_PATH, dir, 'htdocs');
            if (!fs.existsSync(htdocsPath)) continue;
            try {
                const subDirs = fs.readdirSync(htdocsPath);
                for (const sub of subDirs) {
                    const subPath = path.join(htdocsPath, sub);
                    if (!sub.includes('.')) continue;
                    let st;
                    try { st = fs.statSync(subPath); } catch { continue; }
                    if (!st.isDirectory()) continue;

                    // birthtime is the real creation date and ext4 keeps it.
                    // Where the filesystem does not, ctime is the closest thing,
                    // so say which one this is rather than pretend.
                    let created = null, createdFrom = 'unknown';
                    if (st.birthtimeMs && st.birthtimeMs > 0) {
                        created = Math.round(st.birthtimeMs);
                        createdFrom = 'created';
                    } else if (st.ctimeMs && st.ctimeMs > 0) {
                        created = Math.round(st.ctimeMs);
                        createdFrom = 'changed';
                    }

                    // Read the rendered vhost to tell a PHP site from a static one.
                    let type = 'static', phpVersion = null;
                    try {
                        const conf = fs.readFileSync('/etc/nginx/sites-enabled/' + sub + '.conf', 'utf8');
                        const fpm = conf.match(/php(\d+\.\d+)-fpm|php\/php(\d+\.\d+)-fpm/);
                        if (fpm || /fastcgi_pass/.test(conf)) {
                            type = 'php';
                            phpVersion = (fpm && (fpm[1] || fpm[2])) || null;
                        }
                    } catch {}

                    sites.push({ domain: sub, type, phpVersion, user: dir, created, createdFrom });
                }
            } catch {}
        }
    } catch (e) {
        log('ERROR', 'Failed to scan sites: ' + e.message);
    }
    return sites;
};

const createSite = (domain, opts = {}) => {
    const siteUser = domain.replace(/\./g, '').substring(0, 32).toLowerCase();
    const sitePass = require('crypto').randomBytes(16).toString('hex');
    const type = opts.type === 'php' ? 'php' : 'static';

    if (type === 'static') {
        return run(`${CLPCTL} site:add:static --domainName="${domain}" --siteUser="${siteUser}" --siteUserPassword="${sitePass}" 2>&1`);
    }

    const available = phpVersions();
    let version = String(opts.phpVersion || '').trim();
    if (version && !/^\d+\.\d+$/.test(version)) version = '';
    if (version && available.length && available.indexOf(version) < 0) {
        log('WARN', `PHP ${version} is not installed; using ${available[available.length - 1]}`);
        version = '';
    }
    if (!version) version = available.length ? available[available.length - 1] : '8.3';

    // Only what a template name can legitimately contain, so nothing here can
    // alter the command being run.
    const template = String(opts.vhostTemplate || 'Generic').replace(/[^A-Za-z0-9 ._-]/g, '') || 'Generic';
    const r = run(`${CLPCTL} site:add:php --domainName="${domain}" --phpVersion="${version}" --vhostTemplate="${template}" --siteUser="${siteUser}" --siteUserPassword="${sitePass}" 2>&1`);
    if (r.ok) r.phpVersion = version;
    return r;
};

const deleteSite = domain => run(`${CLPCTL} site:delete --domainName="${domain}" --force 2>&1`);

const requestSSL = domain => run(`${CLPCTL} lets-encrypt:install:certificate --domainName="${domain}" 2>&1`);

const enablePageSpeed = () => ({ ok: true, out: 'PageSpeed not available in CloudPanel 6.x' });

const findSiteDir = domain => {
    const siteUser = domain.replace(/\./g, '').toLowerCase();
    let sitePath = path.join(SITES_PATH, siteUser, 'htdocs', domain);
    if (fs.existsSync(sitePath)) return sitePath;
    sitePath = path.join(SITES_PATH, siteUser, 'htdocs');
    if (fs.existsSync(sitePath) && !fs.existsSync(path.join(sitePath, domain))) return sitePath;
    sitePath = path.join(SITES_PATH, domain, 'htdocs');
    if (fs.existsSync(sitePath)) return sitePath;
    try {
        const dirs = fs.readdirSync(SITES_PATH);
        for (const dir of dirs) {
            const htdocsDomain = path.join(SITES_PATH, dir, 'htdocs', domain);
            if (fs.existsSync(htdocsDomain)) return htdocsDomain;
            const htdocs = path.join(SITES_PATH, dir, 'htdocs');
            if (fs.existsSync(htdocs) && dir.toLowerCase() === siteUser) return htdocs;
        }
    } catch {}
    return null;
};

const writeFile = (domain, filePath, content) => {
    const basePath = findSiteDir(domain);
    if (!basePath) return { ok: false, err: `Site directory not found for ${domain}` };
    const fullPath = path.join(basePath, filePath);
    if (!path.resolve(fullPath).startsWith(path.resolve(basePath))) {
        return { ok: false, err: 'Invalid path - traversal not allowed' };
    }
    try {
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, content);
        fixOwnership(basePath);
        return { ok: true };
    } catch (e) {
        return { ok: false, err: e.message };
    }
};

const extractZip = (domain, filename, base64Content, folder = '') => {
    const basePath = findSiteDir(domain);
    if (!basePath) return { ok: false, err: `Site directory not found for ${domain}` };
    let targetPath = basePath;
    if (folder) {
        const safeFolder = folder.replace(/\.\./g, '').replace(/[\/\\]/g, '').trim();
        if (safeFolder) {
            targetPath = path.join(basePath, safeFolder);
            fs.mkdirSync(targetPath, { recursive: true });
        }
    }
    const tempPath = `/tmp/${Date.now()}-${filename}`;
    try {
        fs.writeFileSync(tempPath, Buffer.from(base64Content, 'base64'));
        const r = run(`unzip -o "${tempPath}" -d "${targetPath}" 2>&1`);
        try { fs.unlinkSync(tempPath); } catch {}
        fixOwnership(basePath);
        return r;
    } catch (e) {
        try { fs.unlinkSync(tempPath); } catch {}
        return { ok: false, err: e.message };
    }
};

// Generate a key and CSR on the server. The private key never leaves the box,
// which is the whole point of doing it here rather than in a browser.
const makeCsr = domain => {
    try { fs.mkdirSync(CERT_DIR, { recursive: true, mode: 0o700 }); } catch {}
    const keyPath = path.join(CERT_DIR, domain + '.key');
    const csrPath = path.join(CERT_DIR, domain + '.csr');

    let r = run(`openssl genrsa -out "${keyPath}" 2048 2>&1`);
    if (!r.ok) return { ok: false, err: 'Could not generate a key: ' + r.err };
    try { fs.chmodSync(keyPath, 0o600); } catch {}

    // The subjectAltName carries the apex and the wildcard, so one certificate
    // covers every subdomain this tool provisions.
    const cnf = path.join(CERT_DIR, domain + '.cnf');
    fs.writeFileSync(cnf,
        '[req]\ndistinguished_name=dn\nreq_extensions=ext\nprompt=no\n' +
        '[dn]\nCN=' + domain + '\n' +
        '[ext]\nsubjectAltName=DNS:' + domain + ',DNS:*.' + domain + '\n');

    r = run(`openssl req -new -key "${keyPath}" -out "${csrPath}" -config "${cnf}" 2>&1`);
    try { fs.unlinkSync(cnf); } catch {}
    if (!r.ok) return { ok: false, err: 'Could not generate a CSR: ' + r.err };

    try {
        return { ok: true, csr: fs.readFileSync(csrPath, 'utf8'), hostnames: [domain, '*.' + domain] };
    } catch (e) {
        return { ok: false, err: e.message };
    }
};

// Install a certificate signed against the CSR above onto one or more sites.
const installCert = (domain, certificate, sites) => {
    const keyPath = path.join(CERT_DIR, domain + '.key');
    if (!fs.existsSync(keyPath)) {
        return { ok: false, err: 'No private key for ' + domain + '. Ask for a CSR first.' };
    }
    if (!/BEGIN CERTIFICATE/.test(String(certificate || ''))) {
        return { ok: false, err: 'That does not look like a PEM certificate' };
    }

    const certPath = path.join(CERT_DIR, domain + '.crt');
    fs.writeFileSync(certPath, certificate, { mode: 0o600 });

    const targets = Array.isArray(sites) && sites.length ? sites : [domain];
    const results = [];
    for (const site of targets) {
        const safe = String(site).replace(/["`$\\;|&]/g, '');
        const r = run(`${CLPCTL} site:install:certificate --domainName="${safe}" --privateKey="${keyPath}" --certificate="${certPath}" 2>&1`);
        results.push({ site: safe, ok: r.ok, out: (r.out || r.err || '').slice(0, 400) });
        log(r.ok ? 'INFO' : 'ERROR', `Certificate install for ${safe}: ${r.ok ? 'ok' : (r.err || '').slice(0, 200)}`);
    }

    const okCount = results.filter(x => x.ok).length;
    return { ok: okCount > 0, installed: okCount, total: results.length, results };
};

const sendJSON = (res, statusCode, data) => {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Agent-Token'
    });
    res.end(JSON.stringify(data));
};

const parseBody = req => new Promise(resolve => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
});

const handleRequest = async (req, res) => {
    const url = req.url.split('?')[0];
    const method = req.method;

    if (method === 'OPTIONS') { sendJSON(res, 204, {}); return; }

    if (TOKEN && req.headers['x-agent-token'] !== TOKEN) {
        log('WARN', `Unauthorized request to ${url}`);
        sendJSON(res, 401, { error: 'Unauthorized' });
        return;
    }

    log('INFO', `${method} ${url}`);

    try {
        if (url === '/api/health' && method === 'GET') {
            sendJSON(res, 200, {
                status: 'ok',
                version: '1.6.0',
                node: process.version,
                cloudpanel: fs.existsSync(CLPCTL),
                php: phpVersions()
            });
            return;
        }

        // Which PHP versions this box actually has
        if (url === '/api/php-versions' && method === 'GET') {
            const versions = phpVersions();
            sendJSON(res, 200, {
                versions,
                recommended: versions.length ? versions[versions.length - 1] : null
            });
            return;
        }

        // Ask for a CSR covering the domain and its wildcard
        if (url === '/api/certificates/csr' && method === 'POST') {
            const body = await parseBody(req);
            if (!body.domain) { sendJSON(res, 400, { error: 'Missing domain' }); return; }
            const r = makeCsr(String(body.domain).replace(/[^A-Za-z0-9.\-]/g, ''));
            sendJSON(res, r.ok ? 200 : 500, r);
            return;
        }

        // Install the signed certificate on one or more sites
        if (url === '/api/certificates/install' && method === 'POST') {
            const body = await parseBody(req);
            if (!body.domain || !body.certificate) {
                sendJSON(res, 400, { error: 'Missing domain or certificate' });
                return;
            }
            const r = installCert(
                String(body.domain).replace(/[^A-Za-z0-9.\-]/g, ''),
                body.certificate,
                body.sites
            );
            sendJSON(res, r.ok ? 200 : 500, r);
            return;
        }

        if (url === '/api/sites' && method === 'GET') {
            sendJSON(res, 200, { sites: getSites() });
            return;
        }

        if (url === '/api/sites' && method === 'POST') {
            const body = await parseBody(req);
            if (!body.domain) { sendJSON(res, 400, { error: 'Missing domain' }); return; }
            const r = createSite(body.domain, {
                type: body.type,
                phpVersion: body.phpVersion,
                vhostTemplate: body.vhostTemplate
            });
            sendJSON(res, r.ok ? 201 : 500,
                r.ok
                    ? { message: 'Site created', domain: body.domain, type: body.type === 'php' ? 'php' : 'static', phpVersion: r.phpVersion || null }
                    : { error: r.err || r.out });
            return;
        }

        let match;

        if ((match = url.match(/^\/api\/sites\/([^\/]+)$/)) && method === 'DELETE') {
            const domain = decodeURIComponent(match[1]);
            const r = deleteSite(domain);
            sendJSON(res, r.ok ? 200 : 500, r.ok ? { message: 'Site deleted' } : { error: r.err || r.out });
            return;
        }

        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/ssl$/)) && method === 'POST') {
            const domain = decodeURIComponent(match[1]);
            sendJSON(res, 200, requestSSL(domain));
            return;
        }

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

        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/upload-zip$/)) && method === 'POST') {
            const domain = decodeURIComponent(match[1]);
            const body = await parseBody(req);
            if (!body.filename || !body.content) {
                sendJSON(res, 400, { error: 'Missing filename or content' });
                return;
            }
            const r = extractZip(domain, body.filename, body.content, body.folder || '');
            sendJSON(res, r.ok ? 200 : 500, r);
            return;
        }

        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/pagespeed$/)) && method === 'POST') {
            sendJSON(res, 200, enablePageSpeed());
            return;
        }

        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/cloudflare-only$/)) && method === 'POST') {
            sendJSON(res, 200, { ok: true, message: 'Configure via CloudPanel UI' });
            return;
        }

        if ((match = url.match(/^\/api\/sites\/([^\/]+)\/files-delete$/)) && method === 'POST') {
            const domain = decodeURIComponent(match[1]);
            const body = await parseBody(req);
            const filenames = Array.isArray(body.files) ? body.files : [];
            const folder = (body.folder || 'media').replace(/\.\./g, '').replace(/\\/g, '').trim();
            const basePath = findSiteDir(domain);
            if (!basePath) { sendJSON(res, 404, { error: 'Site not found' }); return; }

            const results = filenames.map(fn => {
                const safeName = path.basename(fn);
                const fp = folder ? path.join(basePath, folder, safeName) : path.join(basePath, safeName);
                if (!path.resolve(fp).startsWith(path.resolve(basePath))) {
                    return { filename: safeName, ok: false, error: 'Path traversal denied' };
                }
                try {
                    fs.unlinkSync(fp);
                    return { filename: safeName, ok: true };
                } catch (e) {
                    return { filename: safeName, ok: false, error: e.message };
                }
            });

            const okCount = results.filter(r => r.ok).length;
            const failCount = results.filter(r => !r.ok).length;
            log('INFO', `Deleted ${okCount}/${filenames.length} files from ${domain}/${folder}`);
            sendJSON(res, 200, { ok: okCount, fail: failCount, results });
            return;
        }

        sendJSON(res, 404, { error: 'Endpoint not found' });

    } catch (e) {
        log('ERROR', `Request failed: ${e.message}`);
        sendJSON(res, 500, { error: e.message });
    }
};

http.createServer(handleRequest).listen(PORT, '0.0.0.0', () => {
    log('INFO', '========================================');
    log('INFO', 'DomainForge CloudPanel Agent v1.6');
    log('INFO', `Listening on http://0.0.0.0:${PORT}`);
    log('INFO', `Node: ${process.version}`);
    log('INFO', `Token: ${TOKEN ? 'CONFIGURED' : 'NOT SET (insecure)'}`);
    log('INFO', `CloudPanel: ${fs.existsSync(CLPCTL) ? 'Found' : 'Not found'}`);
    log('INFO', '========================================');
});

process.on('SIGTERM', () => { log('INFO', 'Shutting down...'); process.exit(0); });
process.on('SIGINT', () => { log('INFO', 'Shutting down...'); process.exit(0); });
AGENT_EOF

node --check /opt/domainforge-agent/agent.js >>"$LOG" 2>&1 || die "The agent file did not write correctly"
ok "Agent installed"

# ------------------------------------------------------------------
# 5. Service
# ------------------------------------------------------------------
step "[5/7] Creating systemd service..."
cat > /etc/systemd/system/domainforge-agent.service << SERVICE_EOF
[Unit]
Description=DomainForge CloudPanel Agent
Documentation=https://github.com/shanab1/domainforge
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/domainforge-agent
ExecStart=$(command -v node) /opt/domainforge-agent/agent.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable domainforge-agent >>"$LOG" 2>&1
systemctl restart domainforge-agent
sleep 2

if ! systemctl is-active --quiet domainforge-agent; then
    say ""
    say "       Service failed to start. Recent journal:"
    journalctl -u domainforge-agent -n 20 --no-pager 2>/dev/null | sed 's/^/       | /'
    die "The agent service is not running"
fi
ok "Service created and started"

# ------------------------------------------------------------------
# 6. Firewall
# ------------------------------------------------------------------
step "[6/7] Configuring firewall..."
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw allow 8080/tcp >>"$LOG" 2>&1 || true
    ok "Port 8080 opened in UFW"
elif command -v ufw >/dev/null 2>&1; then
    ok "UFW present but inactive, nothing to open"
else
    warn "UFW not found. Open port 8080 yourself if a firewall is in the way."
fi

# ------------------------------------------------------------------
# 7. Self-test
# ------------------------------------------------------------------
step "[7/7] Testing the agent..."
HEALTH="$(curl -s --max-time 10 -H "X-Agent-Token: $TOKEN" http://localhost:8080/api/health 2>>"$LOG" || true)"
if echo "$HEALTH" | grep -q '"status":"ok"'; then
    ok "Agent responded on localhost"
    echo "$HEALTH" | grep -q '"cloudpanel":true' \
        && ok "CloudPanel detected" \
        || warn "clpctl not found — site creation will fail until CloudPanel is installed"
else
    warn "No healthy response on localhost yet. Check: journalctl -u domainforge-agent -n 30"
fi

SERVER_IP="$(curl -4 -s --max-time 10 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"

echo ""
echo "============================================"
echo "  INSTALLATION COMPLETE"
echo "============================================"
echo ""
echo "  Copy these into DomainForge:"
echo ""
echo "    Agent IP : $SERVER_IP"
echo "    Port     : 8080"
echo "    Token    : $TOKEN"
echo ""
echo "  Node.js    : $(node -v)"
echo "  Service    : $(systemctl is-active domainforge-agent)"
echo "  Install log: $LOG"
echo ""
echo "  Test from your machine:"
echo "    curl -H \"X-Agent-Token: $TOKEN\" http://$SERVER_IP:8080/api/health"
echo ""
echo "  Live logs:"
echo "    journalctl -u domainforge-agent -f"
echo ""
echo "  If this server sits behind Cloudflare, any DNS record you point at"
echo "  it for the agent must be unproxied (grey cloud), because port 8080"
echo "  is not one Cloudflare proxies."
echo ""
echo "============================================"
