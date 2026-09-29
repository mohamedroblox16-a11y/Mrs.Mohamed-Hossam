const apiKey = String(process.env.RESEND_API_KEY || '').trim();
const fromEmail = String(process.env.RESEND_FROM_EMAIL || '').trim();

if (!apiKey) {
  throw new Error(
    'RESEND_API_KEY غير موجود في Build Secrets. أضف Secret باسم RESEND_API_KEY في Builds ثم أعد الـDeploy.'
  );
}

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';

function putSecret(name, value) {
  execFileSync(
    npx,
    [
      'wrangler',
      'secret',
      'put',
      name,
      '--name',
      'mrs-mohamed-hossam'
    ],
    {
      input: value + '\n',
      stdio: ['pipe', 'inherit', 'inherit'],
      env: process.env
    }
  );
}

putSecret('RESEND_API_KEY', apiKey);

if (fromEmail) {
  putSecret('RESEND_FROM_EMAIL', fromEmail);
}

execFileSync(
  npx,
  [
    'wrangler',
    'deploy',
    '--config',
    './wrangler.jsonc',
    '--name',
    'mrs-mohamed-hossam'
  ],
  {
    stdio: 'inherit',
    env: process.env
  }
);
