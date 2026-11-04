// Writes the Worker secrets taken from the environment (GitHub secrets in CI) to a
// JSON file for `wrangler deploy|preview --secrets-file`. The file is created with
// mode 0600 and the workflow deletes it on exit. Values are never printed.
//
// Usage: node scripts/write-worker-secrets.mjs <output-file>
import { writeFileSync } from 'node:fs';

/** Every Worker secret the site uses. Missing ones are skipped. */
const NAMES = ['IPGEOLOCATION_API_KEY'];

const out = process.argv[2];
if (!out) {
  console.error('usage: node scripts/write-worker-secrets.mjs <output-file>');
  process.exit(2);
}

const secrets = {};
for (const name of NAMES) {
  const value = process.env[name];
  if (value) secrets[name] = value;
  else console.warn(`warning: ${name} is not set, the Worker keeps its previous value (if any)`);
}

writeFileSync(out, JSON.stringify(secrets), { mode: 0o600 });
console.log(`worker secrets: ${Object.keys(secrets).join(', ') || '(none)'}`);
