'use strict';
// Servidor da Mesa de RPG de Belladonna. Sem dependências: só precisa do Node.js (versão 18 ou mais nova).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), os = require('os'), zlib = require('zlib');
const DIR = __dirname, PUB = path.join(DIR, 'public');
let CFG = { porta: 3000, senhaMestre: '', codigoMesa: '' };
try { Object.assign(CFG, JSON.parse(fs.readFileSync(path.join(DIR, 'config.json'), 'utf8'))); } catch (e) { console.log('config.json não encontrado; usando valores padrão.'); }
const PORT = +process.env.PORT || +CFG.porta || 3000;
const DATAF = path.join(DIR, 'dados.json');
let SEGREDO = '', DOCS = new Map();
try { const d = JSON.parse(fs.readFileSync(DATAF, 'utf8')); SEGREDO = d.segredo || ''; DOCS = new Map(Object.entries(d.docs || {})); } catch (e) {}
if (!SEGREDO) SEGREDO = crypto.randomBytes(24).toString('hex');
if (!DOCS.size) { try { DOCS = new Map(Object.entries(JSON.parse(fs.readFileSync(path.join(DIR, 'seed.json'), 'utf8')))); } catch (e) {} }
let saveT = null;
const save = () => { clearTimeout(saveT); saveT = setTimeout(() => fs.writeFile(DATAF, JSON.stringify({ segredo: SEGREDO, docs: Object.fromEntries(DOCS) }), () => {}), 400); };
save();

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = (u, o) => crypto.createHmac('sha256', SEGREDO).update(u + '|' + (o ? 1 : 0)).digest('hex').slice(0, 32);
const mkToken = (u, o) => [u, o ? 1 : 0, sign(u, o)].join('.');
function auth(tok) {
  const p = String(tok || '').split('.'); if (p.length !== 3) return null;
  const u = p[0], o = p[1] === '1'; if (!/^[\w-]{1,40}$/.test(u)) return null;
  const a = sign(u, o), b = p[2]; if (a.length !== b.length || !crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))) return null;
  return { uid: u, owner: o };
}
const PATHRE = /^[\w\-:.~@+]{1,80}(\/[\w\-:.~@+]{1,80}){0,5}$/;
const canRead = (p, u) => { const s = p.split('/'); if (s[0] === 'secret') return u.owner; if (s[0] === 'data' && s[1] === 'users') return s[2] === u.uid; return true; };
const canWrite = (p, u) => {
  const s = p.split('/');
  if (['game', 'fog', 'secret'].includes(s[0])) return u.owner;
  if (['tokens', 'sheets', 'journal'].includes(s[0])) return true;
  if (s[0] === 'players') return u.owner || s[1] === u.uid;
  if (s[0] === 'data' && s[1] === 'users') return s[2] === u.uid;
  return false;
};
const TOPICS = ['dice', 'mv', 'ping'];
const clients = new Set();
const send = (c, o) => { try { c.res.write('data: ' + JSON.stringify(o) + '\n\n'); } catch (e) {} };
const peersList = () => [...clients].filter(c => c.presence).map(c => ({ id: c.id, presence: c.presence }));
const bcPeers = () => { const l = peersList(); clients.forEach(c => send(c, { t: 'peers', peers: l })); };
const bcDoc = (p, d) => clients.forEach(c => { if (canRead(p, c.user)) send(c, { t: 'doc', p, d }); });

function body(req, limit = 1.6e6) {
  return new Promise((ok, no) => {
    let n = 0; const b = [];
    req.on('data', x => { n += x.length; if (n > limit) { no(new Error('grande')); req.destroy(); } else b.push(x); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(b).toString('utf8') || '{}')); } catch (e) { no(e); } });
    req.on('error', no);
  });
}
const json = (res, code, o) => { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(o)); };
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp' };
const cache = new Map();
function serveStatic(req, res) {
  let rel = decodeURIComponent(req.url.split('?')[0]); if (rel.endsWith('/')) rel += 'index.html';
  const f = path.normalize(path.join(PUB, rel)); if (!f.startsWith(PUB)) { res.writeHead(403); return res.end(); }
  fs.stat(f, (e, s) => {
    if (e || !s.isFile()) { res.writeHead(404); return res.end('Não encontrado'); }
    const ext = path.extname(f).toLowerCase(), key = f; let c = cache.get(key);
    const send = () => {
      const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '') && c.gz;
      const h = { 'content-type': MIME[ext] || 'application/octet-stream', 'cache-control': 'no-cache' }; if (gz) h['content-encoding'] = 'gzip';
      res.writeHead(200, h); res.end(gz ? c.gz : c.buf);
    };
    if (c && c.m === s.mtimeMs) return send();
    fs.readFile(f, (e2, buf) => { if (e2) { res.writeHead(500); return res.end(); } c = { m: s.mtimeMs, buf, gz: ['.html', '.js', '.css', '.json', '.svg'].includes(ext) ? zlib.gzipSync(buf) : null }; cache.set(key, c); send(); });
  });
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  try {
    if (req.method === 'GET' && url === '/api/ping') return json(res, 200, { app: 'belladonna', needCode: !!CFG.codigoMesa });
    if (req.method === 'POST' && url === '/api/login') {
      const b = await body(req, 5e4), name = String(b.name || '').trim().slice(0, 40);
      const fail = (m) => setTimeout(() => json(res, 401, { message: m }), 600);
      if (!name) return json(res, 400, { message: 'Digite seu nome.' });
      if (b.gm) {
        if (!CFG.senhaMestre || !same(b.pass || '', CFG.senhaMestre)) return fail('Senha do mestre incorreta.');
        return json(res, 200, { uid: 'mestre', name, owner: true, token: mkToken('mestre', true) });
      }
      if (CFG.codigoMesa && !same(String(b.code || '').trim().toLowerCase(), String(CFG.codigoMesa).trim().toLowerCase())) return fail('Código da mesa incorreto.');
      let uid = String(b.uid || ''); if (!/^u_[\w-]{6,30}$/.test(uid)) uid = 'u_' + crypto.randomBytes(8).toString('hex');
      return json(res, 200, { uid, name, owner: false, token: mkToken(uid, false) });
    }
    if (req.method === 'GET' && url === '/api/events') {
      const q = new URL(req.url, 'http://x').searchParams, user = auth(q.get('token'));
      if (!user) return json(res, 401, { message: 'Sessão inválida.' });
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no' });
      const c = { res, user, id: 'c' + crypto.randomBytes(5).toString('hex'), presence: null }; clients.add(c);
      const docs = {}; DOCS.forEach((v, k) => { if (canRead(k, user)) docs[k] = v; });
      send(c, { t: 'init', cid: c.id, docs, peers: peersList() });
      const ka = setInterval(() => { try { res.write(': ka\n\n'); } catch (e) {} }, 20000);
      req.on('close', () => { clearInterval(ka); clients.delete(c); bcPeers(); });
      return;
    }
    if (req.method === 'POST' && ['/api/write', '/api/emit', '/api/presence'].includes(url)) {
      const b = await body(req), user = auth(b.token); if (!user) return json(res, 401, { code: 'unauthenticated', message: 'Sessão inválida. Recarregue a página.' });
      if (url === '/api/write') {
        const p = b.path; if (typeof p !== 'string' || !PATHRE.test(p) || p.split('/').length % 2 !== 0) return json(res, 400, { code: 'bad_path', message: 'Caminho inválido.' });
        if (!canWrite(p, user)) return json(res, 403, { code: 'permission_denied', message: 'Sem permissão para alterar isso.' });
        if (b.op === 'delete') { DOCS.delete(p); bcDoc(p, null); save(); return json(res, 200, { ok: true }); }
        if (!b.data || typeof b.data !== 'object' || Array.isArray(b.data)) return json(res, 400, { code: 'bad_data', message: 'Dados inválidos.' });
        let nv = b.data; if (b.op === 'update') { const cur = DOCS.get(p); if (!cur) return json(res, 404, { code: 'not_found', message: 'Documento não existe.' }); nv = { ...cur, ...b.data }; }
        else if (b.op !== 'set') return json(res, 400, { code: 'bad_op', message: 'Operação inválida.' });
        if (Buffer.byteLength(JSON.stringify(nv)) > 262144) return json(res, 413, { code: 'too_large', message: 'Documento grande demais (máx. 256 KB).' });
        DOCS.set(p, nv); bcDoc(p, nv); save(); return json(res, 200, { ok: true });
      }
      const me = [...clients].find(c => c.id === b.cid && c.user.uid === user.uid);
      if (url === '/api/emit') {
        if (!TOPICS.includes(b.topic)) return json(res, 400, { code: 'bad_topic', message: 'Tópico inválido.' });
        clients.forEach(c => { if (!me || c.id !== me.id) send(c, { t: 'room', topic: b.topic, data: b.data }); }); return json(res, 200, { ok: true });
      }
      if (me) { me.presence = b.presence && typeof b.presence === 'object' ? b.presence : null; bcPeers(); }
      return json(res, 200, { ok: true });
    }
    if (req.method === 'GET') return serveStatic(req, res);
    res.writeHead(405); res.end();
  } catch (e) { try { json(res, 400, { message: 'Requisição inválida.' }); } catch (_) {} }
});
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n=== Mesa de RPG de Belladonna ===');
  console.log('Neste computador:  http://localhost:' + PORT);
  Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === 'IPv4' && !i.internal).forEach(i => console.log('Na mesma rede Wi-Fi:  http://' + i.address + ':' + PORT));
  console.log(CFG.senhaMestre ? '' : '\nATENÇÃO: defina "senhaMestre" no config.json, senão ninguém consegue entrar como mestre.');
  console.log('\nDeixe esta janela aberta durante a sessão. Para parar: Ctrl+C.\n');
});
