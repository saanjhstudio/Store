import http from 'node:http';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';

const SECRET = process.env.AUTH_SECRET;
if (!SECRET || SECRET.length < 32) {
  console.error('Set AUTH_SECRET to a random string of at least 32 characters.');
  process.exit(1);
}
const COST = 12;

const safeEqual = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const sign = msg => crypto.createHmac('sha256', SECRET).update(msg).digest('hex');
const send = (res, code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', d => { size += d.length; if (size > 4096) { reject(new Error('too large')); req.destroy(); } else chunks.push(d); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

http.createServer(async (req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) return send(res, 200, { ok: true });
  if (req.method !== 'POST') return send(res, 404, { error: 'Not found' });
  if (!safeEqual(req.headers.authorization || '', `Bearer ${SECRET}`)) return send(res, 401, { error: 'Unauthorized' });

  let b;
  try { b = await readJson(req); } catch { return send(res, 400, { error: 'Bad request' }); }
  const password = typeof b.password === 'string' ? b.password.slice(0, 64) : '';

  try {
    if (req.url === '/hash') {
      if (password.length < 10) return send(res, 400, { error: 'Password too short' });
      return send(res, 200, { hash: await bcrypt.hash(password, COST) });
    }
    if (req.url === '/verify') {
      let ok = false;
      try { ok = typeof b.hash === 'string' && await bcrypt.compare(password, b.hash); } catch { ok = false; }
      const exp = Math.floor(Date.now() / 1000) + 120;
      const nonce = String(b.nonce || '').slice(0, 100), user = String(b.username || '').slice(0, 64);
      return send(res, 200, { ok, exp, sig: sign(`${nonce}|${user}|${exp}|${ok ? 1 : 0}`) });
    }
  } catch (e) {
    console.error(e.message);
    return send(res, 500, { error: 'Server error' });
  }
  send(res, 404, { error: 'Not found' });
}).listen(process.env.PORT || 10000, () => console.log('auth server ready'));
