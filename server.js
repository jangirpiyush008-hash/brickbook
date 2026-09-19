/* Static server with SPA fallback + host-based routing for admin.bricbook.com */
const http = require('http');
const fs = require('fs');
const path = require('path');
const PORT = process.env.PORT || 8080;
const ROOT = __dirname;

const MIME = {
  '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8',
  '.js':'text/javascript; charset=utf-8', '.mjs':'text/javascript; charset=utf-8',
  '.json':'application/json; charset=utf-8', '.svg':'image/svg+xml',
  '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif',
  '.webp':'image/webp', '.ico':'image/x-icon', '.woff':'font/woff', '.woff2':'font/woff2',
  '.ttf':'font/ttf', '.otf':'font/otf', '.pdf':'application/pdf', '.txt':'text/plain; charset=utf-8',
  '.xml':'application/xml; charset=utf-8', '.webmanifest':'application/manifest+json'
};

/* SPA route table — known client-side routes get 200 on fallback; anything else gets 404 */
const SPA_ROUTES = new Set([
  '/', '/list-your-practice',
  '/login', '/signup', '/signup/client', '/signup/architect',
  '/welcome', '/forgot', '/reset',
  '/app', '/app/explore', '/app/profile', '/app/settings', '/app/pros', '/app/jobs',
  '/app/practice/setup', '/app/practice/projects', '/app/practice/projects/new'
]);
const SPA_ROUTE_PREFIXES = ['/app/', '/architect/', '/client/invite/', '/practice/'];
function isKnownSpaRoute(pathname){
  if(SPA_ROUTES.has(pathname)) return true;
  return SPA_ROUTE_PREFIXES.some(p => pathname.startsWith(p));
}

/* Security headers applied to every response */
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'accelerometer=(), autoplay=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
};

/* CSP is intentionally not over-restrictive because we load Supabase JS from jsdelivr */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https: blob:",
  "connect-src 'self' https://*.supabase.co wss://*.supabase.co",
  "frame-ancestors 'self'",
  "base-uri 'self'",
  "form-action 'self' https://accounts.google.com"
].join('; ');

function baseHeaders(){
  return { ...SECURITY_HEADERS, 'Content-Security-Policy': CSP };
}

function send(res, code, headers, body){
  const merged = { ...baseHeaders(), ...headers };
  res.writeHead(code, merged);
  if(body && body.pipe) body.pipe(res); else res.end(body);
}
function fileHeaders(ext, stat){
  const ct = MIME[ext] || 'application/octet-stream';
  const cache = (['.html'].includes(ext)) ? 'no-cache, no-store, must-revalidate'
              : (['.js','.css','.svg','.png','.jpg','.jpeg','.webp','.woff','.woff2','.ttf','.otf'].includes(ext))
                ? 'public, max-age=3600'
                : 'public, max-age=300';
  return {
    'Content-Type': ct,
    'Content-Length': stat.size,
    'Cache-Control': cache
  };
}

function serveFile(req, res, filePath, code){
  fs.stat(filePath, (err, stat) => {
    if(err || !stat.isFile()) return spaFallback(req, res, req.url.split('?')[0]);
    const ext = path.extname(filePath).toLowerCase();
    send(res, code || 200, fileHeaders(ext, stat), fs.createReadStream(filePath));
  });
}
function spaFallback(req, res, pathname){
  /* Known SPA route → 200 with the app shell */
  /* Unknown path → 404 status with the same shell (still lets SPA render a friendly error) */
  const code = isKnownSpaRoute(pathname) ? 200 : 404;
  const idx = path.join(ROOT, 'index.html');
  fs.stat(idx, (err, stat) => {
    if(err) return send(res, 404, {'Content-Type':'text/plain; charset=utf-8'}, 'Not found');
    send(res, code, fileHeaders('.html', stat), fs.createReadStream(idx));
  });
}
function safeJoin(root, urlPath){
  const decoded = decodeURIComponent(urlPath.split('?')[0].split('#')[0]);
  const resolved = path.normalize(path.join(root, decoded));
  return resolved.startsWith(root) ? resolved : null;
}

http.createServer((req, res) => {
  const host = (req.headers.host || '').toLowerCase().split(':')[0];
  let urlPath = req.url.split('?')[0].split('#')[0];

  /* Host-based routing: admin.bricbook.com forces the /admin/ tree */
  if(host === 'admin.bricbook.com' || host.startsWith('admin.')){
    if(urlPath === '/' || urlPath === ''){
      return send(res, 302, {'Location': '/admin/'}, '');
    }
    if(!urlPath.startsWith('/admin')){
      return send(res, 302, {'Location': '/admin' + urlPath}, '');
    }
  }

  /* Normalise trailing slash for known folder-index routes */
  if(urlPath !== '/' && urlPath.endsWith('/')){
    urlPath = urlPath.slice(0, -1);
  }

  const filePath = safeJoin(ROOT, urlPath);
  if(!filePath){ return send(res, 400, {'Content-Type':'text/plain; charset=utf-8'}, 'Bad path'); }

  fs.stat(filePath, (err, stat) => {
    if(!err && stat.isFile()){
      const ext = path.extname(filePath).toLowerCase();
      return send(res, 200, fileHeaders(ext, stat), fs.createReadStream(filePath));
    }
    if(!err && stat.isDirectory()){
      /* Serve <dir>/index.html if it exists */
      const idx = path.join(filePath, 'index.html');
      return serveFile(req, res, idx, 200);
    }
    /* Unknown path: 404 for obvious asset extensions; SPA fallback otherwise */
    const ext = path.extname(urlPath).toLowerCase();
    if(ext && !MIME[ext]){ return send(res, 404, {'Content-Type':'text/plain; charset=utf-8'}, 'Not found'); }
    if(ext && ext !== '.html'){ return send(res, 404, {'Content-Type':'text/plain; charset=utf-8'}, 'Not found'); }
    return spaFallback(req, res, urlPath);
  });
}).listen(PORT, () => console.log('BricBook server on :' + PORT));
