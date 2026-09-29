import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const secretFile = path.resolve('.wrangler-runtime-secrets.json');

const runtimeSecrets = {};

if (String(process.env.RESEND_API_KEY || '').trim()) {
  runtimeSecrets.RESEND_API_KEY = String(process.env.RESEND_API_KEY).trim();
}

if (String(process.env.RESEND_FROM_EMAIL || '').trim()) {
  runtimeSecrets.RESEND_FROM_EMAIL = String(process.env.RESEND_FROM_EMAIL).trim();
}

if (!runtimeSecrets.RESEND_API_KEY) {
  throw new Error(
    'RESEND_API_KEY غير موجود في Build Secrets. أضف Secret باسم RESEND_API_KEY في Builds ثم أعد الـDeploy.'
  );
}

try {
  fs.writeFileSync(
    secretFile,
    JSON.stringify(runtimeSecrets),
    { encoding: 'utf8', mode: 0o600 }
  );

  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';

  execFileSync(
    npx,
    [
      'wrangler',
      'deploy',
      '--config',
      './wrangler.jsonc',
      '--name',
      'mrs-mohamed-hossam',
      '--secrets-file',
      secretFile
    ],
    {
      stdio: 'inherit',
      env: process.env
    }
  );
} finally {
  try {
    fs.rmSync(secretFile, { force: true });
  } catch {}
}
