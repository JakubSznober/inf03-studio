'use strict';
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT  = process.env.PORT || 3000;
const ROOT  = __dirname;
const DATA  = path.join(ROOT, 'data');
const PROJ  = path.join(DATA, 'projects');
const USERS = path.join(DATA, 'users.json');

[DATA, PROJ].forEach(d => fs.mkdirSync(d, { recursive: true }));
if (!fs.existsSync(USERS)) fs.writeFileSync(USERS, '{}');

const MIME = {
  '.html':'text/html; charset=utf-8', '.htm':'text/html; charset=utf-8',
  '.css':'text/css',                  '.js':'application/javascript',
  '.json':'application/json',         '.pdf':'application/pdf',
  '.png':'image/png',                 '.jpg':'image/jpeg',
  '.jpeg':'image/jpeg',               '.gif':'image/gif',
  '.svg':'image/svg+xml',             '.ico':'image/x-icon',
  '.webp':'image/webp',               '.wasm':'application/wasm',
  '.txt':'text/plain; charset=utf-8', '.xml':'text/xml; charset=utf-8',
  '.php':'text/plain; charset=utf-8', '.sql':'text/plain; charset=utf-8',
};
const BIN_EXT = new Set(['.png','.jpg','.jpeg','.gif','.ico','.webp','.pdf','.wasm']);

const sessions = new Map();
setInterval(() => { const now = Date.now(); for (const [k,v] of sessions) if (v.exp < now) sessions.delete(k); }, 3600000);

const newToken   = () => crypto.randomBytes(32).toString('hex');
const hashPwd    = (p, s) => crypto.scryptSync(p, s, 64).toString('hex');
const loadUsers  = () => { try { return JSON.parse(fs.readFileSync(USERS,'utf8')); } catch { return {}; } };
const saveUsers  = u => fs.writeFileSync(USERS, JSON.stringify(u, null, 2));
const filesDir   = u => path.join(PROJ, u, 'files');
const tplDir     = u => path.join(PROJ, u, 'tpl');
const ensureDirs = u => [filesDir(u), tplDir(u)].forEach(d => fs.mkdirSync(d, { recursive:true }));

const parseCookies = str =>
  Object.fromEntries((str||'').split(';').map(c => {
    const [k,...v] = c.trim().split('=');
    return [k.trim(), decodeURIComponent(v.join('='))];
  }));

const getSess = req => {
  const { sid } = parseCookies(req.headers.cookie || '');
  const s = sid ? sessions.get(sid) : null;
  return s && s.exp > Date.now() ? s : null;
};

const respond = (res, code, data, ct = 'application/json; charset=utf-8') => {
  res.writeHead(code, { 'Content-Type': ct, 'X-Content-Type-Options': 'nosniff' });
  res.end(typeof data === 'string' ? data : JSON.stringify(data));
};

const validName = n =>
  typeof n === 'string' && n.length > 0 && n.length <= 100 &&
  /^[a-zA-Z0-9_\-.]+\.[a-zA-Z0-9]+$/.test(n) && !n.includes('..');

const validUser = n => typeof n === 'string' && /^[a-zA-Z0-9_]{3,30}$/.test(n);

const safeJoin = (base, name) => {
  const r = path.resolve(path.join(base, name));
  return r.startsWith(path.resolve(base)) ? r : null;
};

const parseBody = req => new Promise((ok, err) => {
  const chunks = []; let sz = 0;
  req.on('data', c => { sz += c.length; if (sz > 30*1024*1024) { req.destroy(); return; } chunks.push(c); });
  req.on('end', () => { try { ok(JSON.parse(Buffer.concat(chunks).toString())); } catch { ok({}); } });
  req.on('error', err);
});

const DEFAULTS = {
  'index.html':
`<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Moja strona</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <h1>Witaj!</h1>
  <p>Edytuj pliki w panelu po lewej.</p>
  <script src="script.js"><\/script>
</body>
</html>`,
  'style.css':
`* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: Arial, sans-serif;
  background: #f5f5f5;
  color: #333;
  padding: 24px;
}
h1 { color: #2563eb; margin-bottom: 12px; }
p  { line-height: 1.6; }`,
  'script.js': `// Twój JavaScript\nconsole.log('Strona załadowana!');`,
};

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p   = url.pathname;
  const m   = req.method;

  // ── API ──────────────────────────────────────────────────────────
  if (p.startsWith('/api/')) {
    let body = {};
    if (m === 'POST' || m === 'PUT') {
      try { body = await parseBody(req); } catch { return respond(res, 400, { error: 'Bad request' }); }
    }

    // Public
    if (p === '/api/register' && m === 'POST') {
      const { username, password } = body;
      if (!validUser(username))
        return respond(res, 400, { error: 'Nazwa użytkownika: 3–30 znaków, tylko litery/cyfry/_' });
      if (!password || password.length < 4)
        return respond(res, 400, { error: 'Hasło musi mieć co najmniej 4 znaki' });
      const users = loadUsers();
      if (users[username])
        return respond(res, 400, { error: 'Użytkownik o tej nazwie już istnieje' });
      const salt = crypto.randomBytes(16).toString('hex');
      users[username] = { salt, hash: hashPwd(password, salt), created: Date.now() };
      saveUsers(users);
      ensureDirs(username);
      const fd = filesDir(username);
      Object.entries(DEFAULTS).forEach(([n,c]) => { const fp = path.join(fd,n); if (!fs.existsSync(fp)) fs.writeFileSync(fp,c,'utf8'); });
      const tok = newToken();
      sessions.set(tok, { username, exp: Date.now() + 7*86400000 });
      res.setHeader('Set-Cookie', `sid=${tok}; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800`);
      return respond(res, 200, { ok: true, username });
    }

    if (p === '/api/login' && m === 'POST') {
      const { username, password } = body;
      const users = loadUsers(), u = users[username];
      if (!u || hashPwd(password, u.salt) !== u.hash)
        return respond(res, 401, { error: 'Nieprawidłowy login lub hasło' });
      ensureDirs(username);
      const tok = newToken();
      sessions.set(tok, { username, exp: Date.now() + 7*86400000 });
      res.setHeader('Set-Cookie', `sid=${tok}; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800`);
      return respond(res, 200, { ok: true, username });
    }

    if (p === '/api/me' && m === 'GET') {
      const s = getSess(req);
      return s ? respond(res, 200, { username: s.username }) : respond(res, 401, { error: 'Nie zalogowany' });
    }

    // Auth required
    const sess = getSess(req);
    if (!sess) return respond(res, 401, { error: 'Wymagane logowanie' });
    const un = sess.username;
    const fd = filesDir(un);
    const td = tplDir(un);
    ensureDirs(un);

    if (p === '/api/logout' && m === 'POST') {
      const { sid } = parseCookies(req.headers.cookie || '');
      if (sid) sessions.delete(sid);
      res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
      return respond(res, 200, { ok: true });
    }

    if (p === '/api/files' && m === 'GET') {
      const files = fs.existsSync(fd) ? fs.readdirSync(fd).map(n => ({ name: n })) : [];
      return respond(res, 200, { files });
    }

    if (p === '/api/file' && m === 'GET') {
      const n = url.searchParams.get('name');
      if (!validName(n)) return respond(res, 400, { error: 'Nieprawidłowa nazwa' });
      const fp = safeJoin(fd, n);
      if (!fp || !fs.existsSync(fp)) return respond(res, 404, { error: 'Nie znaleziono' });
      const ext = path.extname(n).toLowerCase();
      if (BIN_EXT.has(ext)) {
        res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
        return res.end(fs.readFileSync(fp));
      }
      return respond(res, 200, { content: fs.readFileSync(fp, 'utf8') });
    }

    if (p === '/api/file' && m === 'POST') {
      const { name, content } = body;
      if (!validName(name)) return respond(res, 400, { error: 'Nieprawidłowa nazwa pliku' });
      const fp = safeJoin(fd, name);
      if (!fp) return respond(res, 403, { error: 'Forbidden' });
      fs.writeFileSync(fp, content ?? '', 'utf8');
      return respond(res, 200, { ok: true });
    }

    if (p === '/api/upload' && m === 'POST') {
      const { name, dataUrl } = body;
      if (!validName(name)) return respond(res, 400, { error: 'Nieprawidłowa nazwa pliku' });
      const fp = safeJoin(fd, name);
      if (!fp) return respond(res, 403, { error: 'Forbidden' });
      const mx = typeof dataUrl === 'string' && dataUrl.match(/^data:[^;]+;base64,(.+)$/s);
      if (!mx) return respond(res, 400, { error: 'Nieprawidłowe dane obrazu' });
      fs.writeFileSync(fp, Buffer.from(mx[1], 'base64'));
      return respond(res, 200, { ok: true, name });
    }

    if (p === '/api/file' && m === 'DELETE') {
      const n = url.searchParams.get('name');
      if (!validName(n)) return respond(res, 400, { error: 'Nieprawidłowa nazwa' });
      const fp = safeJoin(fd, n);
      if (!fp) return respond(res, 403, { error: 'Forbidden' });
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
      return respond(res, 200, { ok: true });
    }

    if (p === '/api/rename' && m === 'POST') {
      const { oldName, newName } = body;
      if (!validName(oldName) || !validName(newName))
        return respond(res, 400, { error: 'Nieprawidłowa nazwa pliku' });
      const ofp = safeJoin(fd, oldName), nfp = safeJoin(fd, newName);
      if (!ofp || !nfp) return respond(res, 403, { error: 'Forbidden' });
      if (!fs.existsSync(ofp)) return respond(res, 404, { error: 'Plik nie istnieje' });
      if (fs.existsSync(nfp)) return respond(res, 400, { error: 'Plik o tej nazwie już istnieje' });
      fs.renameSync(ofp, nfp);
      return respond(res, 200, { ok: true });
    }

    if (p === '/api/export' && m === 'GET') {
      const names = fs.existsSync(fd) ? fs.readdirSync(fd) : [];
      const files = names.map(n => {
        const fp  = path.join(fd, n);
        const ext = path.extname(n).toLowerCase();
        const bin = BIN_EXT.has(ext);
        return { name: n, binary: bin, content: bin ? fs.readFileSync(fp).toString('base64') : fs.readFileSync(fp,'utf8') };
      });
      return respond(res, 200, { files });
    }

    if (p === '/api/templates' && m === 'GET') {
      // user's own templates
      const names = fs.existsSync(td) ? fs.readdirSync(td).filter(f => f.endsWith('.json')) : [];
      const own = names.map(f => { try { return JSON.parse(fs.readFileSync(path.join(td,f),'utf8')); } catch { return null; } }).filter(Boolean);
      // public templates from all other users
      const publicTpls = [];
      try {
        for (const u of fs.readdirSync(PROJ)) {
          if (u === sess.username) continue;
          const uTplDir = path.join(PROJ, u, 'tpl');
          if (!fs.existsSync(uTplDir)) continue;
          for (const f of fs.readdirSync(uTplDir).filter(f => f.endsWith('.json'))) {
            try {
              const t = JSON.parse(fs.readFileSync(path.join(uTplDir, f), 'utf8'));
              if (t && t.public) publicTpls.push({ ...t, _owner: u, _readonly: true });
            } catch {}
          }
        }
      } catch {}
      return respond(res, 200, { templates: own, publicTemplates: publicTpls });
    }

    if (p === '/api/templates' && m === 'POST') {
      const { name, content, lang, public: pub } = body;
      if (!name || typeof name !== 'string' || name.length > 80)
        return respond(res, 400, { error: 'Nieprawid\u0142owa nazwa szablonu' });
      const safe = name.replace(/[^a-zA-Z0-9_\- ]/g,'_').trim();
      const fp = safeJoin(td, safe + '.json');
      if (!fp) return respond(res, 403, { error: 'Forbidden' });
      fs.writeFileSync(fp, JSON.stringify({ name, content, lang, public: !!pub, created: Date.now() }));
      return respond(res, 200, { ok: true });
    }

    if (p.startsWith('/api/templates/') && m === 'DELETE') {
      const name = decodeURIComponent(p.slice('/api/templates/'.length));
      const safe = name.replace(/[^a-zA-Z0-9_\- ]/g,'_').trim();
      const fp = safeJoin(td, safe + '.json');
      if (!fp) return respond(res, 403, { error: 'Forbidden' });
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
      return respond(res, 200, { ok: true });
    }

    // PHP execution
    if (p === '/api/php-exec' && m === 'POST') {
      const { name: phpName, queryString, postData } = body;
      if (!validName(phpName)) return respond(res, 400, { error: 'Nieprałidłowa nazwa' });
      const phpFp = safeJoin(fd, phpName);
      if (!phpFp || !fs.existsSync(phpFp)) return respond(res, 404, { error: 'Plik nie istnieje' });
      const phpEnv = {
        ...process.env,
        QUERY_STRING:    queryString || '',
        REQUEST_METHOD:  postData ? 'POST' : 'GET',
        CONTENT_TYPE:    postData ? 'application/x-www-form-urlencoded' : '',
        CONTENT_LENGTH:  postData ? String(Buffer.byteLength(postData)) : '0',
        SCRIPT_FILENAME: phpFp,
        SCRIPT_NAME:     '/' + phpName,
        SERVER_NAME:     'localhost',
        SERVER_PORT:     String(PORT),
        HTTP_HOST:       'localhost:' + PORT,
        DOCUMENT_ROOT:   fd,
        REDIRECT_STATUS: '200',
      };
      const phpProc = spawn('php', [phpFp], { env: phpEnv });
      let output = '', errors = '', done = false;
      if (postData) { phpProc.stdin.write(postData); }
      phpProc.stdin.end();
      phpProc.stdout.on('data', d => { output += d; });
      phpProc.stderr.on('data', d => { errors += d; });
      const killTimer = setTimeout(() => { phpProc.kill(); errors += '\nPrzekroczono limit czasu (10s).'; }, 10000);
      phpProc.on('close', code => {
        if (done) return;
        done = true;
        clearTimeout(killTimer);
        respond(res, 200, { output, errors, code });
      });
      phpProc.on('error', e => {
        if (done) return;
        done = true;
        clearTimeout(killTimer);
        if (e.code === 'ENOENT') respond(res, 200, { phpNotFound: true });
        else respond(res, 500, { error: e.message });
      });
      return;
    }

    return respond(res, 404, { error: 'Endpoint nie istnieje' });
  }

  // ── Serve user project files (for iframe preview) ─────────────────
  if (p.startsWith('/project/')) {
    const s2 = getSess(req);
    if (!s2) { res.writeHead(401); return res.end('401'); }
    const n = decodeURIComponent(p.slice('/project/'.length));
    if (!validName(n)) { res.writeHead(400); return res.end('400'); }
    const fp = safeJoin(filesDir(s2.username), n);
    if (!fp || !fs.existsSync(fp)) { res.writeHead(404); return res.end('404'); }
    const ext = path.extname(n).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    return res.end(fs.readFileSync(fp));
  }

  // ── Static files ──────────────────────────────────────────────────
  const fp = path.resolve(path.join(ROOT, p === '/' ? 'index.html' : p));
  if (!fp.startsWith(path.resolve(ROOT))) { res.writeHead(403); return res.end('403'); }
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404); return res.end('404 Not Found'); }
    const ext = path.extname(fp).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });

}).listen(PORT, () => {
  console.log('\n  ⚡  INF.03 Studio v2');
  console.log('  ─────────────────────────────────');
  console.log('  \x1b[36mhttp://localhost:' + PORT + '\x1b[0m\n');
});
