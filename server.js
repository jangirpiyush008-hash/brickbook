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

function send(res, code, headers, body){
  res.writeHead(code, headers);
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
    'Cache-Control': cache,
    'X-Content-Type-Options': 'nosniff'
  };
}

function serveFile(req, res, filePath){
  fs.stat(filePath, (err, stat) => {
    if(err || !stat.isFile()) return spaFallback(req, res);
    const ext = path.extname(filePath).toLowerCase();
    send(res, 200, fileHeaders(ext, stat), fs.createReadStream(filePath));
  });
}
function spaFallback(req, res){
  /* Any unknown path falls back to index.html so the SPA router can pick it up */
  const idx = path.join(ROOT, 'index.html');
  fs.stat(idx, (err, stat) => {
    if(err) return send(res, 404, {'Content-Type':'text/plain'}, 'Not found');
    send(res, 200, fileHeaders('.html', stat), fs.createReadStream(idx));
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
      /* Any non-admin path on the admin host redirects into /admin/ */
      return send(res, 302, {'Location': '/admin' + urlPath}, '');
    }
  }

  /* Normalise trailing slash for known folder-index routes */
  if(urlPath !== '/' && urlPath.endsWith('/')){
    urlPath = urlPath.slice(0, -1);
  }

  const filePath = safeJoin(ROOT, urlPath);
  if(!filePath){ return send(res, 400, {'Content-Type':'text/plain'}, 'Bad path'); }

  fs.stat(filePath, (err, stat) => {
    if(!err && stat.isFile()){
      const ext = path.extname(filePath).toLowerCase();
      return send(res, 200, fileHeaders(ext, stat), fs.createReadStream(filePath));
    }
    if(!err && stat.isDirectory()){
      /* Serve <dir>/index.html if it exists */
      const idx = path.join(filePath, 'index.html');
      return serveFile(req, res, idx);
    }
    /* Unknown path: SPA fallback for anything except obvious asset extensions */
    const ext = path.extname(urlPath).toLowerCase();
    if(ext && !MIME[ext]){ return send(res, 404, {'Content-Type':'text/plain'}, 'Not found'); }
    if(ext && ext !== '.html'){ return send(res, 404, {'Content-Type':'text/plain'}, 'Not found'); }
    return spaFallback(req, res);
  });
}).listen(PORT, () => console.log('BricBook server on :' + PORT));
