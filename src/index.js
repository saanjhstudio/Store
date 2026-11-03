import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { createClient } from '@libsql/client/web';
import bcrypt from 'bcryptjs';
import { ensureSchema } from './schema.js';

const SESSION_DAYS = 7;
const BCRYPT_COST = 10;
const EVENT_TYPES = new Set(['page_view', 'product_view', 'order_click', 'social_click']);
const SETTING_KEYS = ['ribbon', 'announcement', 'instagram_handle', 'whatsapp', 'wa_enabled', 'ig_enabled', 'wa_template', 'ig_template'];
const TOGGLES = ['wa_enabled', 'ig_enabled'];
const cleanSetting = (k, v) =>
  TOGGLES.includes(k) ? (v === true || v === 1 || v === '1' ? '1' : '0')
  : k === 'whatsapp' ? String(v).replace(/\D/g, '').slice(0, 15)
  : k === 'instagram_handle' ? String(v).replace(/^@/, '').trim().slice(0, 40)
  : String(v).slice(0, 600);

const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async s => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))));
const rand = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const slugify = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
const plain = r => r.rows.map(row => ({ ...row }));
const int = (v, d = 0) => (Number.isFinite(+v) ? Math.trunc(+v) : d);
const flag = v => (v ? 1 : 0);
const cacheable = c => c.header('Cache-Control', 'public, max-age=30, s-maxage=60');

const app = new Hono();

app.use('/api/*', async (c, next) => {
  const db = createClient({ url: c.env.TURSO_DATABASE_URL, authToken: c.env.TURSO_AUTH_TOKEN });
  await ensureSchema(db);
  c.set('db', db);
  await next();
});

async function getUser(c) {
  const token = getCookie(c, 'sid');
  if (!token) return null;
  const r = await c.get('db').execute({
    sql: `SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.id_hash = ? AND s.expires_at > datetime('now') AND u.active = 1`,
    args: [await sha256(token)],
  });
  return r.rows[0] ? { ...r.rows[0] } : null;
}

const originCheck = async (c, next) => {
  if (c.req.method !== 'GET') {
    const o = c.req.header('Origin');
    if (!o || new URL(o).host !== new URL(c.req.url).host) return c.json({ error: 'Bad origin' }, 403);
  }
  await next();
};

const requireManager = async (c, next) => {
  const u = await getUser(c);
  if (!u) return c.json({ error: 'Unauthorized' }, 401);
  c.set('user', u);
  await next();
};

async function listProducts(db, includeHidden) {
  const [p, im] = await db.batch([
    `SELECT * FROM products ${includeHidden ? '' : 'WHERE visible = 1'} ORDER BY sort, id DESC`,
    'SELECT product_id, url FROM product_images ORDER BY sort, id',
  ]);
  const imgs = {};
  im.rows.forEach(r => (imgs[r.product_id] ??= []).push(r.url));
  return plain(p).map(x => ({
    id: x.id, slug: x.slug, name: x.name, desc: x.description, price: x.price,
    tag: x.tag, images: imgs[x.id] || [],
    emoji: x.emoji, inStock: !!x.in_stock, featured: !!x.featured, visible: !!x.visible, sort: x.sort,
  }));
}

app.get('/api/products', async c => { cacheable(c); return c.json(await listProducts(c.get('db'), false)); });

app.get('/api/reviews', async c => {
  const r = await c.get('db').execute('SELECT id, review, name, stars, top FROM reviews WHERE visible = 1 ORDER BY id DESC');
  cacheable(c);
  return c.json(plain(r).map(x => ({ ...x, top: !!x.top })));
});

app.get('/api/gallery', async c => {
  const r = await c.get('db').execute('SELECT id, url, caption FROM gallery WHERE visible = 1 ORDER BY sort, id DESC');
  cacheable(c);
  return c.json(plain(r));
});

app.get('/api/config', async c => {
  const [tags, set] = await c.get('db').batch([
    'SELECT slug, label FROM item_tags ORDER BY sort, label',
    'SELECT key, value FROM settings',
  ]);
  cacheable(c);
  return c.json({ tags: plain(tags), settings: Object.fromEntries(set.rows.map(r => [r.key, r.value])) });
});

app.get('/img/:key', async c => {
  const o = await c.env.IMAGES.get(c.req.param('key'));
  if (!o) return c.notFound();
  return new Response(o.body, {
    headers: {
      'Content-Type': o.httpMetadata?.contentType || 'application/octet-stream',
      'Cache-Control': 'public, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
    },
  });
});

app.post('/api/track', async c => {
  const ua = c.req.header('User-Agent') || '';
  // Ignore bots, and ignore any logged-in manager automatically.
  if (/bot|crawl|spider|preview|headless/i.test(ua) || (await getUser(c))) return c.body(null, 204);
  const b = await c.req.json().catch(() => ({}));
  const evs = (Array.isArray(b.events) ? b.events : []).slice(0, 20).filter(e => EVENT_TYPES.has(e?.type));
  if (!evs.length) return c.body(null, 204);
  const device = /mobile|android|iphone/i.test(ua) ? 'mobile' : 'desktop';
  const country = c.req.raw.cf?.country || null;
  await c.get('db').batch(evs.map(e => ({
    sql: 'INSERT INTO events(type, product_id, path, referrer, sid, device, country) VALUES (?,?,?,?,?,?,?)',
    args: [e.type, Number.isInteger(e.product_id) ? e.product_id : null, String(e.path || '').slice(0, 200),
           String(e.ref || '').slice(0, 100), String(e.sid || '').slice(0, 40), device, country],
  })));
  return c.body(null, 204);
});

// One-time bootstrap (no terminal needed). Works only while the users table is empty.
app.post('/api/setup', async c => {
  const db = c.get('db');
  const { token, username, password } = await c.req.json().catch(() => ({}));
  if (!c.env.SETUP_TOKEN || token !== c.env.SETUP_TOKEN) return c.json({ error: 'Forbidden' }, 403);
  if ((await db.execute('SELECT COUNT(*) n FROM users')).rows[0].n > 0) return c.json({ error: 'Already set up' }, 409);
  if (!/^[\w.-]{3,32}$/.test(username || '') || (password || '').length < 10 || password.length > 64)
    return c.json({ error: 'Username 3-32 chars; password 10-64 chars' }, 400);
  await db.execute({ sql: "INSERT INTO users(username, password_hash, role) VALUES (?,?,'owner')", args: [username, await bcrypt.hash(password, BCRYPT_COST)] });
  return c.json({ ok: true });
});

app.post('/api/login', async c => {
  const db = c.get('db');
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const { username = '', password = '' } = await c.req.json().catch(() => ({}));

  await db.batch([
    "DELETE FROM login_attempts WHERE ts < datetime('now','-1 day')",
    "DELETE FROM sessions WHERE expires_at < datetime('now')",
  ]);
  const n = (await db.execute({ sql: "SELECT COUNT(*) n FROM login_attempts WHERE ip = ? AND ts > datetime('now','-15 minutes')", args: [ip] })).rows[0].n;
  if (n >= 5) return c.json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);

  const u = (await db.execute({ sql: 'SELECT * FROM users WHERE username = ? AND active = 1', args: [String(username)] })).rows[0];
  // Same bcrypt work whether or not the user exists, so timing doesn't reveal valid usernames.
  const ok = u ? await bcrypt.compare(String(password).slice(0, 64), u.password_hash) : (await bcrypt.hash('x', BCRYPT_COST), false);
  if (!ok) {
    await db.execute({ sql: 'INSERT INTO login_attempts(ip) VALUES (?)', args: [ip] });
    return c.json({ error: 'Invalid username or password' }, 401);
  }
  await db.execute({ sql: 'DELETE FROM login_attempts WHERE ip = ?', args: [ip] });
  const token = rand();
  await db.execute({
    sql: "INSERT INTO sessions(id_hash, user_id, expires_at) VALUES (?,?, datetime('now', ?))",
    args: [await sha256(token), u.id, `+${SESSION_DAYS} days`],
  });
  setCookie(c, 'sid', token, { httpOnly: true, secure: true, sameSite: 'Strict', path: '/', maxAge: SESSION_DAYS * 86400 });
  return c.json({ username: u.username, role: u.role });
});

app.post('/api/logout', async c => {
  const t = getCookie(c, 'sid');
  if (t) await c.get('db').execute({ sql: 'DELETE FROM sessions WHERE id_hash = ?', args: [await sha256(t)] });
  deleteCookie(c, 'sid', { path: '/' });
  return c.json({ ok: true });
});

app.get('/api/me', async c => {
  const u = await getUser(c);
  return u ? c.json(u) : c.json({ error: 'Unauthorized' }, 401);
});

app.use('/api/admin/*', originCheck, requireManager);

async function saveProduct(c, id) {
  const db = c.get('db');
  const b = await c.req.json().catch(() => ({}));
  const name = String(b.name || '').trim();
  const price = int(b.price, -1);
  if (!name || price < 0) return c.json({ error: 'Name and a valid price are required' }, 400);
  const slug = slugify(b.slug || name);
  if (!slug) return c.json({ error: 'Invalid slug' }, 400);
  const f = [name, slug, b.description || '', price, b.tag || null, flag(b.inStock ?? true), flag(b.featured), flag(b.visible ?? true), b.emoji || null, int(b.sort)];
  try {
    if (id) await db.execute({ sql: 'UPDATE products SET name=?,slug=?,description=?,price=?,tag=?,in_stock=?,featured=?,visible=?,emoji=?,sort=? WHERE id=?', args: [...f, id] });
    else id = Number((await db.execute({ sql: 'INSERT INTO products(name,slug,description,price,tag,in_stock,featured,visible,emoji,sort) VALUES (?,?,?,?,?,?,?,?,?,?)', args: f })).lastInsertRowid);
  } catch (e) {
    return c.json({ error: /UNIQUE/.test(e.message) ? 'That slug is already used' : 'Save failed' }, 409);
  }
  const images = (b.images || []).filter(u => /^\/img\/[\w.-]+$/.test(u));
  await db.batch([
    { sql: 'DELETE FROM product_images WHERE product_id = ?', args: [id] },
    ...images.map((url, i) => ({ sql: 'INSERT INTO product_images(product_id, url, sort) VALUES (?,?,?)', args: [id, url, i] })),
  ]);
  return c.json({ id, slug });
}
app.get('/api/admin/products', async c => c.json(await listProducts(c.get('db'), true)));
app.post('/api/admin/products', c => saveProduct(c, null));
app.put('/api/admin/products/:id', c => saveProduct(c, int(c.req.param('id'))));
app.delete('/api/admin/products/:id', async c => {
  const db = c.get('db'), id = int(c.req.param('id'));
  const imgs = await db.execute({ sql: 'SELECT url FROM product_images WHERE product_id = ?', args: [id] });
  await db.batch([
    { sql: 'DELETE FROM product_images WHERE product_id = ?', args: [id] },
    { sql: 'DELETE FROM products WHERE id = ?', args: [id] },
  ]);
  await Promise.all(imgs.rows.map(r => c.env.IMAGES.delete(String(r.url).replace('/img/', ''))));
  return c.json({ ok: true });
});

const reviewArgs = b => [String(b.review || '').trim(), String(b.name || '').trim(), Math.min(5, Math.max(1, int(b.stars, 5))), flag(b.top), flag(b.visible ?? true)];
app.get('/api/admin/reviews', async c => c.json(plain(await c.get('db').execute('SELECT * FROM reviews ORDER BY id DESC'))));
app.post('/api/admin/reviews', async c => {
  const a = reviewArgs(await c.req.json().catch(() => ({})));
  if (!a[0] || !a[1]) return c.json({ error: 'Review text and name are required' }, 400);
  const r = await c.get('db').execute({ sql: 'INSERT INTO reviews(review,name,stars,top,visible) VALUES (?,?,?,?,?)', args: a });
  return c.json({ id: Number(r.lastInsertRowid) });
});
app.put('/api/admin/reviews/:id', async c => {
  const a = reviewArgs(await c.req.json().catch(() => ({})));
  await c.get('db').execute({ sql: 'UPDATE reviews SET review=?,name=?,stars=?,top=?,visible=? WHERE id=?', args: [...a, int(c.req.param('id'))] });
  return c.json({ ok: true });
});
app.delete('/api/admin/reviews/:id', async c => {
  await c.get('db').execute({ sql: 'DELETE FROM reviews WHERE id = ?', args: [int(c.req.param('id'))] });
  return c.json({ ok: true });
});

app.get('/api/admin/tags', async c => c.json(plain(await c.get('db').execute('SELECT slug, label, sort FROM item_tags ORDER BY sort, label'))));
app.put('/api/admin/tags/:slug', async c => {
  const b = await c.req.json().catch(() => ({}));
  const slug = slugify(c.req.param('slug'));
  if (!slug || !String(b.label || '').trim()) return c.json({ error: 'A label is required' }, 400);
  await c.get('db').execute({
    sql: 'INSERT INTO item_tags(slug,label,sort) VALUES (?,?,?) ON CONFLICT(slug) DO UPDATE SET label=excluded.label, sort=excluded.sort',
    args: [slug, String(b.label).trim(), int(b.sort)],
  });
  return c.json({ ok: true });
});
app.delete('/api/admin/tags/:slug', async c => {
  const slug = c.req.param('slug');
  await c.get('db').batch([
    { sql: 'UPDATE products SET tag = NULL WHERE tag = ?', args: [slug] },
    { sql: 'DELETE FROM item_tags WHERE slug = ?', args: [slug] },
  ]);
  return c.json({ ok: true });
});

app.get('/api/admin/gallery', async c => c.json(plain(await c.get('db').execute('SELECT * FROM gallery ORDER BY sort, id DESC'))));
app.post('/api/admin/gallery', async c => {
  const b = await c.req.json().catch(() => ({}));
  if (!/^\/img\/[\w.-]+$/.test(b.url || '')) return c.json({ error: 'Upload a photo first' }, 400);
  const r = await c.get('db').execute({ sql: 'INSERT INTO gallery(url,caption,sort) VALUES (?,?,?)', args: [b.url, String(b.caption || '').slice(0, 120), int(b.sort)] });
  return c.json({ id: Number(r.lastInsertRowid) });
});
app.put('/api/admin/gallery/:id', async c => {
  const b = await c.req.json().catch(() => ({}));
  await c.get('db').execute({ sql: 'UPDATE gallery SET caption=?, visible=?, sort=? WHERE id=?', args: [String(b.caption || '').slice(0, 120), flag(b.visible ?? true), int(b.sort), int(c.req.param('id'))] });
  return c.json({ ok: true });
});
app.delete('/api/admin/gallery/:id', async c => {
  const db = c.get('db'), id = int(c.req.param('id'));
  const row = (await db.execute({ sql: 'SELECT url FROM gallery WHERE id = ?', args: [id] })).rows[0];
  await db.execute({ sql: 'DELETE FROM gallery WHERE id = ?', args: [id] });
  if (row) await c.env.IMAGES.delete(String(row.url).replace('/img/', ''));
  return c.json({ ok: true });
});

app.get('/api/admin/settings', async c => c.json(Object.fromEntries((await c.get('db').execute('SELECT key, value FROM settings')).rows.map(r => [r.key, r.value]))));
app.put('/api/admin/settings', async c => {
  const b = await c.req.json().catch(() => ({}));
  const keys = Object.keys(b).filter(k => SETTING_KEYS.includes(k));
  if (keys.length) await c.get('db').batch(keys.map(k => ({
    sql: 'INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
    args: [k, cleanSetting(k, b[k])],
  })));
  return c.json({ ok: true });
});

app.post('/api/admin/upload', async c => {
  const file = (await c.req.formData()).get('file');
  const ext = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' }[file?.type];
  if (!ext) return c.json({ error: 'Only JPG, PNG or WebP images' }, 400);
  if (file.size > 5 * 1024 * 1024) return c.json({ error: 'Max 5 MB per image' }, 400);
  const key = `${crypto.randomUUID()}.${ext}`;
  await c.env.IMAGES.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
  return c.json({ url: `/img/${key}` });
});

app.get('/api/admin/users', async c => c.json(plain(await c.get('db').execute('SELECT id, username, role, active, created_at FROM users ORDER BY id'))));
app.post('/api/admin/users', async c => {
  const { username, password } = await c.req.json().catch(() => ({}));
  if (!/^[\w.-]{3,32}$/.test(username || '') || (password || '').length < 10 || password.length > 64)
    return c.json({ error: 'Username 3-32 chars; password 10-64 chars' }, 400);
  try {
    await c.get('db').execute({ sql: "INSERT INTO users(username, password_hash, role) VALUES (?,?,'manager')", args: [username, await bcrypt.hash(password, BCRYPT_COST)] });
  } catch { return c.json({ error: 'Username already exists' }, 409); }
  return c.json({ ok: true });
});
app.patch('/api/admin/users/:id', async c => {
  const db = c.get('db'), id = int(c.req.param('id'));
  const b = await c.req.json().catch(() => ({}));
  if (b.active === false) {
    const others = (await db.execute({ sql: 'SELECT COUNT(*) n FROM users WHERE active = 1 AND id != ?', args: [id] })).rows[0].n;
    if (!others) return c.json({ error: "Can't deactivate the last active account" }, 400);
    await db.batch([
      { sql: 'UPDATE users SET active = 0 WHERE id = ?', args: [id] },
      { sql: 'DELETE FROM sessions WHERE user_id = ?', args: [id] },
    ]);
  }
  if (b.active === true) await db.execute({ sql: 'UPDATE users SET active = 1 WHERE id = ?', args: [id] });
  if (b.password) {
    if (b.password.length < 10 || b.password.length > 64) return c.json({ error: 'Password 10-64 chars' }, 400);
    await db.batch([
      { sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [await bcrypt.hash(b.password, BCRYPT_COST), id] },
      { sql: 'DELETE FROM sessions WHERE user_id = ?', args: [id] },
    ]);
  }
  return c.json({ ok: true });
});

app.get('/api/admin/analytics', async c => {
  const d = `-${Math.min(365, Math.max(1, int(c.req.query('days'), 30)))} days`;
  const [tot, daily, prod, pages, refs, dev, ctry] = await c.get('db').batch([
    { sql: `SELECT COALESCE(SUM(type='page_view'),0) page_views, COUNT(DISTINCT sid) visitors, COALESCE(SUM(type='product_view'),0) product_views,
            COALESCE(SUM(type='order_click'),0) order_clicks, COALESCE(SUM(type='social_click'),0) social_clicks
            FROM events WHERE ts >= datetime('now', ?)`, args: [d] },
    { sql: `SELECT date(ts) day, SUM(type='page_view') views, COUNT(DISTINCT sid) visitors FROM events WHERE ts >= datetime('now', ?) GROUP BY day ORDER BY day`, args: [d] },
    { sql: `SELECT p.id, p.name, COALESCE(SUM(e.type='product_view'),0) views, COALESCE(SUM(e.type='order_click'),0) order_clicks
            FROM products p LEFT JOIN events e ON e.product_id = p.id AND e.ts >= datetime('now', ?)
            GROUP BY p.id ORDER BY order_clicks DESC, views DESC`, args: [d] },
    { sql: `SELECT path, COUNT(*) n FROM events WHERE type='page_view' AND ts >= datetime('now', ?) GROUP BY path ORDER BY n DESC LIMIT 10`, args: [d] },
    { sql: `SELECT referrer, COUNT(*) n FROM events WHERE type='page_view' AND referrer != '' AND ts >= datetime('now', ?) GROUP BY referrer ORDER BY n DESC LIMIT 10`, args: [d] },
    { sql: `SELECT device, COUNT(DISTINCT sid) n FROM events WHERE ts >= datetime('now', ?) GROUP BY device`, args: [d] },
    { sql: `SELECT country, COUNT(DISTINCT sid) n FROM events WHERE country IS NOT NULL AND ts >= datetime('now', ?) GROUP BY country ORDER BY n DESC LIMIT 10`, args: [d] },
  ]);
  return c.json({ totals: plain(tot)[0], daily: plain(daily), products: plain(prod), pages: plain(pages), referrers: plain(refs), devices: plain(dev), countries: plain(ctry) });
});

app.notFound(c => c.json({ error: 'Not found' }, 404));
app.onError((e, c) => { console.error(e); return c.json({ error: 'Server error' }, 500); });

export default app;
