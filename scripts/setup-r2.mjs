import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';

const BUCKET = 'saanjh-images';
const REDIRECT = '.wrangler/deploy/config.json';

try {
  rmSync(REDIRECT, { force: true });
  const config = JSON.parse(readFileSync('wrangler.jsonc', 'utf8').replace(/^\s*\/\/.*$/gm, ''));

  const out = execFileSync('npx', ['--no-install', 'wrangler', 'r2', 'bucket', 'list'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60000,
  });

  if (out.includes(BUCKET)) {
    config.r2_buckets = [{ binding: 'IMAGES', bucket_name: BUCKET }];
    writeFileSync('wrangler.generated.json', JSON.stringify(config, null, 2));
    mkdirSync('.wrangler/deploy', { recursive: true });
    writeFileSync(REDIRECT, JSON.stringify({ configPath: '../../wrangler.generated.json' }));
    console.log(`[r2] Found bucket "${BUCKET}", binding it as IMAGES.`);
  } else {
    console.log(`[r2] Bucket "${BUCKET}" not found. Deploying without R2; photos will use Turso.`);
  }
} catch (e) {
  const why = String(e.stderr || e.message).split('\n').find(l => l.trim()) || 'unknown error';
  console.log(`[r2] Could not check for the bucket (${why.trim()}). Deploying without R2.`);
}
