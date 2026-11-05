// Schema and auto-population: ensureSchema() runs once per Worker instance before the first API request.
// To change the schema later, append a new array to MIGRATIONS and never edit an old one.

export const STARTER_TAGS = "('art','Art',1),('necklace','Necklace',2),('keychain','Keychain',3)";

// Only inserted when a key doesn't exist yet, so edits made in the admin panel are never overwritten.
export const DEFAULT_SETTINGS = {
  instagram_handle: 'saanjhstudio._',
  whatsapp: '',
  announcement: '',
  ribbon: ['Handcrafted with Love', 'Original Art Pieces', 'Custom Orders Welcome', 'Made in India', 'New Drops Every Month'].join('\n'),
  wa_enabled: '0',
  ig_enabled: '1',
  wa_template: "Hi Saanjh Studio! I'd like to order {{Product Name}} (Product ID: {{Product ID}}). Is it still available?",
  ig_template: "Hi Saanjh Studio! I'd like to order {{Product Name}} (Product ID: {{Product ID}}). Is it still available?",
};

const MIGRATIONS = [
  // v1: initial schema
  [
    `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)`,
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'manager',
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, ts TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS item_tags (slug TEXT PRIMARY KEY, label TEXT NOT NULL, sort INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      price INTEGER NOT NULL,
      tag TEXT,
      in_stock INTEGER NOT NULL DEFAULT 1,
      featured INTEGER NOT NULL DEFAULT 0,
      visible INTEGER NOT NULL DEFAULT 1,
      emoji TEXT,
      sort INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS product_images (
      id INTEGER PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      sort INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY,
      review TEXT NOT NULL,
      name TEXT NOT NULL,
      stars INTEGER NOT NULL DEFAULT 5 CHECK (stars BETWEEN 1 AND 5),
      top INTEGER NOT NULL DEFAULT 0,
      visible INTEGER NOT NULL DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`,
    `CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY,
      ts TEXT NOT NULL DEFAULT (datetime('now')),
      type TEXT NOT NULL,
      product_id INTEGER,
      path TEXT,
      referrer TEXT,
      sid TEXT,
      device TEXT,
      country TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)`,
    `CREATE INDEX IF NOT EXISTS idx_events_product ON events(product_id, type)`,
    `CREATE INDEX IF NOT EXISTS idx_images_product ON product_images(product_id)`,
    // Starter tags are added once, here, so tags you delete later don't come back.
    `INSERT OR IGNORE INTO item_tags(slug,label,sort) VALUES ${STARTER_TAGS}`,
  ],
  // v2: gallery photos
  [
    `CREATE TABLE IF NOT EXISTS gallery (
      id INTEGER PRIMARY KEY,
      url TEXT NOT NULL,
      caption TEXT DEFAULT '',
      sort INTEGER DEFAULT 0,
      visible INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  ],
  // v3: tracked image files (bytes live in R2 or, for Turso uploads, in the data column)
  [
    `CREATE TABLE IF NOT EXISTS files (
      key TEXT PRIMARY KEY,
      store TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      data BLOB,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  ],
];

let ready;

export function ensureSchema(db) {
  return (ready ??= run(db).catch(err => { ready = undefined; throw err; }));
}

async function run(db) {
  let version = 0;
  try {
    version = Number((await db.execute("SELECT value FROM meta WHERE key = 'schema_version'")).rows[0]?.value) || 0;
  } catch { /* meta doesn't exist yet: fresh database */ }

  for (let i = version; i < MIGRATIONS.length; i++) {
    await db.batch([
      ...MIGRATIONS[i],
      { sql: "INSERT INTO meta(key,value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", args: [String(i + 1)] },
    ], 'write');
  }

  await db.batch(
    Object.entries(DEFAULT_SETTINGS).map(([key, value]) => ({ sql: 'INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)', args: [key, value] })),
    'write',
  );
}
