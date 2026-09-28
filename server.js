المشكلة دلوقتي في Deploy command نفسه، لكن الرسالة اللي ظهرت عندك (Failed: error occurred while running deploy command) عامة ومش بتوضح السبب.

وفيه حاجة لاحظتها في النسخة اللي جهزناها: مثال Cloudflare الرسمي لتشغيل Express على Workers بيستخدم app.listen(3000) قبل httpServerHandler({ port: 3000 })، وإحنا النسخة الحالية ناقصها السطر ده.

ضيف في server.js قبل:

export default {fetch:httpServerHandler({port:3000})};

السطر ده:

app.listen(3000);

فتبقى النهاية:

app.all("*",(req,res)=>
  env.ASSETS
    ? env.ASSETS.fetch(req)
    : res.status(404).json({message:"المسار غير موجود."})
);

await ensureAdmin();

app.listen(3000);

export default {
  fetch: httpServerHandler({ port: 3000 })
};

بعدها ارفع التعديل على GitHub واعمل Retry deployment.

ولو ظهر خطأ تاني، ابعتلي كل الكلام اللي ظاهر تحت Deploying خصوصًا أي سطر فيه ✘ أو Error، لأن سطر Failed لوحده مش كفاية لتحديد السبب.

ده كود import express from 'express';
import bcrypt from 'bcryptjs';
import { httpServerHandler } from 'cloudflare:node';
import { env } from 'cloudflare:workers';

const app = express();
const DB = () => env.DB;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const nowIso = () => new Date().toISOString();
const today = () => new Date().toISOString().slice(0, 10);
const normalizeLogin = (v) => String(v ?? '').trim().toLowerCase();
const validUrl = (v) => {
  if (!v) return true;
  try { const u = new URL(v); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
};
const safeUser = (u) => u && ({
  id: u.id, fullName: u.full_name, login: u.login, grade: u.grade,
  subject: u.subject, mode: u.mode, role: u.role, active: !!u.active,
  createdAt: u.created_at
});

async function sign(value) {
  const secret = String(env.SESSION_SECRET || 'change-me');
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function makeSession(userId) {
  return ${userId}.${await sign(userId)};
}

async function verifySession(value) {
  if (!value || !value.includes('.')) return null;
  const [id, sig] = value.split('.');
  if (sig !== await sign(id)) return null;
  return id;
}

function cookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

async function currentUser(req) {
  const sid = await verifySession(cookie(req, 'session'));
  if (!sid) return null;
  const user = await DB().prepare('SELECT * FROM users WHERE id = ? LIMIT 1').bind(sid).first();
  return user && user.active ? user : null;
}

async function requireAuth(req, res, next) {
  const user = await currentUser(req);
  if (!user) return res.status(401).json({ message: 'يجب تسجيل الدخول أولاً.' });
  req.user = user;
  next();
}

async function requireAdmin(req, res, next) {
  const user = await currentUser(req);
  if (!user) return res.status(401).json({ message: 'يجب تسجيل الدخول أولاً.' });
  if (user.role !== 'admin') return res.status(403).json({ message: 'هذه الصفحة خاصة بالمدرس.' });
  req.user = user;
  next();
}

async function ensureAdmin() {
  const login = normalizeLogin(env.ADMIN_LOGIN);
  const password = String(env.ADMIN_PASSWORD || '');
  if (!login || !password) return;
  const found = await DB().prepare('SELECT id FROM users WHERE login = ? LIMIT 1').bind(login).first();
  if (!found) {
    await DB().prepare(
      INSERT INTO users (id,full_name,login,grade,subject,mode,role,active,created_at,password_hash)
      VALUES (?,? ,?,?,?,?, 'admin',1,?,?)
    ).bind(
      crypto.randomUUID(), 'مستر محمد حسام', login, 'مدرس', 'كل المواد', 'إدارة المنصة',
      nowIso(), await bcrypt.hash(password, 12)
    ).run();
  }
}

function lectureState(settings) {
  if (!settings?.lecture_url) return { visible: false, reason: 'no-link' };
  if (!settings.scheduled_at) return { visible: true, reason: 'always' };
  const t = new Date(settings.scheduled_at).getTime();
  if (Number.isNaN(t)) return { visible: true, reason: 'invalid-schedule' };
  const showAt = t - 5 * 60 * 1000;
  return { visible: Date.now() >= showAt, reason: Date.now() >= showAt ? 'live-window' : 'not-yet', showAt: new Date(showAt).toISOString(), scheduledAt: new Date(t).toISOString() };
}

app.get('/api/health', (req, res) => res.json({ ok: true, platform: 'cloudflare-workers' }));

app.get('/api/me', requireAuth, (req, res) => res.json({ user: safeUser(req.user) }));

app.post('/api/register', async (req, res) => {
  const { fullName, login, grade, subject, mode, password } = req.body || {};
  const name = String(fullName || '').trim();
  const userLogin = normalizeLogin(login);
  if (name.split(/\s+/).filter(Boolean).length !== 3) return res.status(400).json({ message: 'اكتب اسمك ثلاثي.' });
  if (!userLogin || !grade || !subject || !mode) return res.status(400).json({ message: 'أكمل كل البيانات.' });
  if (String(password || '').length < 6) return res.status(400).json({ message: 'الباسورد يجب أن يكون 6 أحرف أو أرقام على الأقل.' });
  if (await DB().prepare('SELECT id FROM users WHERE login = ? LIMIT 1').bind(userLogin).first()) return res.status(409).json({ message: 'هذا الرقم أو اليوزر مستخدم بالفعل.' });
  await DB().prepare(
    INSERT INTO users (id,full_name,login,grade,subject,mode,role,active,created_at,password_hash)
    VALUES (?,?,?,?,?,?, 'student',1,?,?)
  ).bind(crypto.randomUUID(), name, userLogin, String(grade), String(subject), String(mode), nowIso(), await bcrypt.hash(String(password), 12)).run();
  res.status(201).json({ message: 'تم إنشاء الحساب بنجاح.' });
});

app.post('/api/login', async (req, res) => {
  const login = normalizeLogin(req.body?.login);
  const password = String(req.body?.password || '');
  const user = await DB().prepare('SELECT * FROM users WHERE login = ? LIMIT 1').bind(login).first();
  if (!user || !user.active || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ message: 'بيانات الدخول غير صحيحة.' });
  res.setHeader('Set-Cookie', session=${encodeURIComponent(await makeSession(user.id))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800);
  res.json({ message: 'تم تسجيل الدخول.', user: safeUser(user) });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  res.json({ message: 'تم تسجيل الخروج.' });
});

app.get('/api/student/dashboard', requireAuth, async (req, res) => {
  const settings = await DB().prepare('SELECT * FROM settings WHERE id = 1 LIMIT 1').first();
  const rows = await DB().prepare('SELECT id,user_id,date,status,method,created_at FROM attendance WHERE user_id = ? ORDER BY date DESC').bind(req.user.id).all();
  const state = lectureState(settings);
  res.json({
    user: safeUser(req.user),
    lecture: { title: settings?.lecture_title || 'المحاضرة القادمة', url: state.visible ? (settings?.lecture_url || '') : '', scheduledAt: settings?.scheduled_at || '', state },
    attendance: rows.results || []
  });
});

app.post('/api/student/checkin', requireAuth, async (req, res) => {
  if (req.user.role !== 'student') return res.status(400).json({ message: 'حساب المدرس لا يحتاج تسجيل حضور.' });
  const settings = await DB().prepare('SELECT * FROM settings WHERE id = 1 LIMIT 1').first();
  const state = lectureState(settings);
  if (!state.visible || !settings?.lecture_url) return res.status(400).json({ message: 'تسجيل الحضور متاح قبل المحاضرة بخمس دقائق وحتى وقتها.' });
  const d = today();
  if (await DB().prepare('SELECT id FROM attendance WHERE user_id = ? AND date = ? LIMIT 1').bind(req.user.id, d).first()) return res.json({ message: 'تم تسجيل حضورك بالفعل اليوم.' });
  await DB().prepare('INSERT INTO attendance (id,user_id,date,status,method,created_at) VALUES (?,?,? ,\'حاضر\',\'student\',?)').bind(crypto.randomUUID(), req.user.id, d, nowIso()).run();
  res.json({ message: 'تم تسجيل حضورك.' });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const result = await DB().prepare("SELECT * FROM users WHERE role != 'admin' ORDER BY full_name").all();
  res.json({ users: (result.results || []).map(safeUser) });
});

app.patch('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const user = await DB().prepare("SELECT * FROM users WHERE id = ? AND role = 'student' LIMIT 1").bind(req.params.id).first();
  if (!user) return res.status(404).json({ message: 'الطالب غير موجود.' });
  if (typeof req.body.active === 'boolean') await DB().prepare('UPDATE users SET active = ? WHERE id = ?').bind(req.body.active ? 1 : 0, req.params.id).run();
  if (typeof req.body.password === 'string' && req.body.password.length >= 6) await DB().prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(await bcrypt.hash(req.body.password, 12), req.params.id).run();
  res.json({ message: 'تم تحديث الحساب.' });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const user = await DB().prepare("SELECT id FROM users WHERE id = ? AND role = 'student' LIMIT 1").bind(req.params.id).first();
  if (!user) return res.status(404).json({ message: 'الطالب غير موجود.' });
  await DB().prepare('DELETE FROM attendance WHERE user_id = ?').bind(req.params.id).run();
  await DB().prepare('DELETE FROM users WHERE id = ?').bind(req.params.id).run();
  res.json({ message: 'تم حذف الطالب.' });
});

app.get('/api/admin/attendance', requireAdmin, async (req, res) => {
  const date = String(req.query.date || today());
  const users = await DB().prepare("SELECT id,full_name,login,grade,subject,mode FROM users WHERE role = 'student' ORDER BY full_name").all();
  const attendance = await DB().prepare('SELECT user_id,status FROM attendance WHERE date = ?').bind(date).all();
  const map = new Map((attendance.results || []).map(a => [a.user_id, a.status]));
  const rows = (users.results || []).map(u => ({ userId: u.id, fullName: u.full_name, login: u.login, grade: u.grade, subject: u.subject, mode: u.mode, status: map.get(u.id) || 'غير محدد' }));
  res.json({ date, rows });
});

app.post('/api/admin/attendance', requireAdmin, async (req, res) => {
  const { userId, date, status } = req.body || {};
  if (!userId || !date || !['حاضر','غائب','غير محدد'].includes(status)) return res.status(400).json({ message: 'بيانات الحضور غير صحيحة.' });
  if (!await DB().prepare("SELECT id FROM users WHERE id = ? AND role = 'student' LIMIT 1").bind(userId).first()) return res.status(404).json({ message: 'الطالب غير موجود.' });
  await DB().prepare('DELETE FROM attendance WHERE user_id = ? AND date = ?').bind(userId, date).run();
  if (status !== 'غير محدد') await DB().prepare('INSERT INTO attendance (id,user_id,date,status,method,created_at) VALUES (?,?,?,?,?,?)').bind(crypto.randomUUID(), userId, date, status, 'admin', nowIso()).run();
  res.json({ message: 'تم تحديث الحضور.' });
});

app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  res.json({ settings: await DB().prepare('SELECT * FROM settings WHERE id = 1 LIMIT 1').first() || { lecture_title: 'المحاضرة القادمة', lecture_url: '', scheduled_at: '' } });
});

app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  const lectureTitle = String(req.body?.lectureTitle || 'المحاضرة القادمة').trim();
  const lectureUrl = String(req.body?.lectureUrl || '').trim();
  const scheduledAt = String(req.body?.scheduledAt || '').trim();
  if (!validUrl(lectureUrl)) return res.status(400).json({ message: 'رابط المحاضرة غير صحيح.' });
  if (scheduledAt && Number.isNaN(new Date(scheduledAt).getTime())) return res.status(400).json({ message: 'موعد المحاضرة غير صحيح.' });
  await DB().prepare(
    INSERT INTO settings (id,lecture_title,lecture_url,scheduled_at,updated_at) VALUES (1,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET lecture_title=excluded.lecture_title, lecture_url=excluded.lecture_url, scheduled_at=excluded.scheduled_at, updated_at=excluded.updated_at
  ).bind(lectureTitle, lectureUrl, scheduledAt, nowIso()).run();
  res.json({ message: 'تم تحديث المحاضرة والرابط.' });
});

app.delete('/api/admin/settings', requireAdmin, async (req, res) => {
  await DB().prepare(
    INSERT INTO settings (id,lecture_title,lecture_url,scheduled_at,updated_at) VALUES (1,'المحاضرة القادمة','','',?)
    ON CONFLICT(id) DO UPDATE SET lecture_title='المحاضرة القادمة', lecture_url='', scheduled_at='', updated_at=excluded.updated_at
  ).bind(nowIso()).run();
  res.json({ message: 'تم مسح المحاضرة الحالية.' });
});

async function serveAsset(req, res) {
  if (!env.ASSETS) return res.status(404).json({ message: 'الملف غير موجود.' });
  const host = req.headers.host || 'localhost';
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const url = ${protocol}://${host}${req.originalUrl};
  const response = await env.ASSETS.fetch(new Request(url, { method: 'GET', headers: req.headers }));
  res.status(response.status);
  response.headers.forEach((value, key) => res.setHeader(key, value));
  const buf = Buffer.from(await response.arrayBuffer());
  res.send(buf);
}

app.use((req, res) => serveAsset(req, res));

app.listen(3000);
export default { fetch: httpServerHandler({ port: 3000 }) };

// Runs on Worker startup/request; safe because it only inserts the admin if absent.
try { await ensureAdmin(); } catch (e) { console.error('Admin seed failed:', e); }

أيوه، الكود اللي بعته فيه app.listen(3000) بالفعل، فمتضيفش السطر تاني. وكود Express نفسه ما يظهرش فيه خطأ واضح يفسر فشل الـDeploy.

الأغلب جدًا إن المشكلة في wrangler.jsonc وليس server.js. Cloudflare يشترط أن قيمة "name" في wrangler.jsonc تكون مطابقة لاسم الـWorker الموجود في مشروع Cloudflare؛ وإلا يفشل النشر أثناء wrangler deploy.

افتح wrangler.jsonc عندك، وهات الجزء ده:

{
  "name": "..."
}

وخليه نفس اسم الـWorker الظاهر في Cloudflare بالضبط.

مثلًا لو اسم الـWorker عندك:

Mrs.Mohamed-Hossam

يبقى:

{
  "name": "Mrs.Mohamed-Hossam",
  "main": "server.js",
  "compatibility_date": "2026-09-28",
  "compatibility_flags": ["nodejs_compat"],
  "assets": {
    "directory": "./public"
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "mr-mohamed-hossam-db",
      "database_id": "b7facb0f-73b3-4875-9079-0f98043edf28"
    }
  ]
}

وجود nodejs_compat وapp.listen(3000) متوافق مع طريقة تشغيل Express الرسمية على Workers، وD1 يجب أن يكون مربوطًا باسم DB كما في الكود عندك.

مهم: لا تغيّر server.js حاليًا.

ابعتلي محتوى ملف wrangler.jsonc عندك، وأنا أحدد لك السطر اللي محتاج يتعدل بالضبط.

عدل علي كود الي بعتو و انت ظابتو بسرعه مع حفظ باقي تعدلات

أيوه، بصيت على الكود اللي بعته. app.listen(3000) موجود بالفعل، فمش هنضيفه تاني. والتعديل الأهم عندك هو طريقة خدمة ملفات public وربط ASSETS؛ Cloudflare يوصي بتعريف binding باسم ASSETS في wrangler.jsonc ثم استخدامه عبر env.ASSETS.

استبدل server.js كله بالكود ده
import express from 'express';
import bcrypt from 'bcryptjs';
import { httpServerHandler } from 'cloudflare:node';
import { env } from 'cloudflare:workers';

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const DB = () => env.DB;

const nowIso = () => new Date().toISOString();

const today = () => {
  const now = new Date();
  return now.toISOString().slice(0, 10);
};

const normalizeLogin = (value) =>
  String(value ?? '').trim().toLowerCase();

const validUrl = (value) => {
  if (!value) return true;

  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};

const safeUser = (user) =>
  user && {
    id: user.id,
    fullName: user.full_name,
    login: user.login,
    grade: user.grade,
    subject: user.subject,
    mode: user.mode,
    role: user.role,
    active: !!user.active,
    createdAt: user.created_at
  };

/* =========================
   Session
========================= */

async function sign(value) {
  const secret = String(
    env.SESSION_SECRET || 'change-this-secret'
  );

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    {
      name: 'HMAC',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(value)
  );

  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function makeSession(userId) {
  return `${userId}.${await sign(userId)}`;
}

async function verifySession(value) {
  if (!value || !value.includes('.')) {
    return null;
  }

  const [id, signature] = value.split('.');

  if (!id || !signature) {
    return null;
  }

  const expected = await sign(id);

  if (signature !== expected) {
    return null;
  }

  return id;
}

function getCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';

  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');

    if (key === name) {
      return decodeURIComponent(rest.join('='));
    }
  }

  return '';
}

async function currentUser(req) {
  const sessionId = await verifySession(
    getCookie(req, 'session')
  );

  if (!sessionId) {
    return null;
  }

  const user = await DB()
    .prepare('SELECT * FROM users WHERE id = ? LIMIT 1')
    .bind(sessionId)
    .first();

  return user && user.active ? user : null;
}

/* =========================
   Auth middleware
========================= */

async function requireAuth(req, res, next) {
  try {
    const user = await currentUser(req);

    if (!user) {
      return res.status(401).json({
        message: 'يجب تسجيل الدخول أولاً.'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth error:', error);

    return res.status(500).json({
      message: 'حدث خطأ أثناء التحقق من الحساب.'
    });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const user = await currentUser(req);

    if (!user) {
      return res.status(401).json({
        message: 'يجب تسجيل الدخول أولاً.'
      });
    }

    if (user.role !== 'admin') {
      return res.status(403).json({
        message: 'هذه الصفحة خاصة بالمدرس.'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Admin auth error:', error);

    return res.status(500).json({
      message: 'حدث خطأ أثناء التحقق من الصلاحيات.'
    });
  }
}

/* =========================
   Create admin automatically
========================= */

async function ensureAdmin() {
  const login = normalizeLogin(env.ADMIN_LOGIN);
  const password = String(env.ADMIN_PASSWORD || '');

  if (!login || !password) {
    console.warn(
      'ADMIN_LOGIN أو ADMIN_PASSWORD غير موجودين.'
    );
    return;
  }

  const found = await DB()
    .prepare(
      'SELECT id FROM users WHERE login = ? LIMIT 1'
    )
    .bind(login)
    .first();

  if (found) {
    return;
  }

  const passwordHash = await bcrypt.hash(
    password,
    12
  );

  await DB()
    .prepare(`
      INSERT INTO users
      (
        id,
        full_name,
        login,
        grade,
        subject,
        mode,
        role,
        active,
        created_at,
        password_hash
      )
      VALUES (?, ?, ?, ?, ?, ?, 'admin', 1, ?, ?)
    `)
    .bind(
      crypto.randomUUID(),
      'مستر محمد حسام',
      login,
      'مدرس',
      'كل المواد',
      'إدارة المنصة',
      nowIso(),
      passwordHash
    )
    .run();

  console.log('Admin account created.');
}

/*
  تشغيل إنشاء الأدمن مرة واحدة لكل Worker instance.
  بدل تنفيذ العملية في global scope.
*/
let adminInitPromise = null;

async function ensureAdminOnce() {
  if (!adminInitPromise) {
    adminInitPromise = ensureAdmin().catch((error) => {
      adminInitPromise = null;
      throw error;
    });
  }

  return adminInitPromise;
}

/* =========================
   Lecture
========================= */

function lectureState(settings) {
  if (!settings?.lecture_url) {
    return {
      visible: false,
      reason: 'no-link'
    };
  }

  if (!settings.scheduled_at) {
    return {
      visible: true,
      reason: 'always'
    };
  }

  const scheduledTime = new Date(
    settings.scheduled_at
  ).getTime();

  if (Number.isNaN(scheduledTime)) {
    return {
      visible: true,
      reason: 'invalid-schedule'
    };
  }

  const showAt = scheduledTime - 5 * 60 * 1000;

  return {
    visible: Date.now() >= showAt,
    reason:
      Date.now() >= showAt
        ? 'live-window'
        : 'not-yet',
    showAt: new Date(showAt).toISOString(),
    scheduledAt: new Date(
      scheduledTime
    ).toISOString()
  };
}

/* =========================
   Health
========================= */

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    platform: 'cloudflare-workers'
  });
});

/* =========================
   Current user
========================= */

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    user: safeUser(req.user)
  });
});

/* =========================
   Register
========================= */

app.post('/api/register', async (req, res) => {
  try {
    const {
      fullName,
      login,
      grade,
      subject,
      mode,
      password
    } = req.body || {};

    const name = String(fullName || '').trim();

    const userLogin = normalizeLogin(login);

    const passwordText = String(
      password || ''
    );

    if (
      name
        .split(/\s+/)
        .filter(Boolean)
        .length !== 3
    ) {
      return res.status(400).json({
        message: 'اكتب اسمك ثلاثي.'
      });
    }

    if (
      !userLogin ||
      !grade ||
      !subject ||
      !mode
    ) {
      return res.status(400).json({
        message: 'أكمل كل البيانات.'
      });
    }

    if (passwordText.length < 6) {
      return res.status(400).json({
        message:
          'الباسورد يجب أن يكون 6 أحرف أو أرقام على الأقل.'
      });
    }

    const exists = await DB()
      .prepare(
        'SELECT id FROM users WHERE login = ? LIMIT 1'
      )
      .bind(userLogin)
      .first();

    if (exists) {
      return res.status(409).json({
        message:
          'هذا الرقم أو اليوزر مستخدم بالفعل.'
      });
    }

    const passwordHash = await bcrypt.hash(
      passwordText,
      12
    );

    await DB()
      .prepare(`
        INSERT INTO users
        (
          id,
          full_name,
          login,
          grade,
          subject,
          mode,
          role,
          active,
          created_at,
          password_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, 'student', 1, ?, ?)
      `)
      .bind(
        crypto.randomUUID(),
        name,
        userLogin,
        String(grade),
        String(subject),
        String(mode),
        nowIso(),
        passwordHash
      )
      .run();

    res.status(201).json({
      message: 'تم إنشاء الحساب بنجاح.'
    });
  } catch (error) {
    console.error('Register error:', error);

    res.status(500).json({
      message: 'حدث خطأ أثناء إنشاء الحساب.'
    });
  }
});

/* =========================
   Login
========================= */

app.post('/api/login', async (req, res) => {
  try {
    const login = normalizeLogin(
      req.body?.login
    );

    const password = String(
      req.body?.password || ''
    );

    const user = await DB()
      .prepare(
        'SELECT * FROM users WHERE login = ? LIMIT 1'
      )
      .bind(login)
      .first();

    if (
      !user ||
      !user.active ||
      !(await bcrypt.compare(
        password,
        user.password_hash
      ))
    ) {
      return res.status(401).json({
        message:
          'بيانات الدخول غير صحيحة.'
      });
    }

    const sessionValue =
      await makeSession(user.id);

    res.setHeader(
      'Set-Cookie',
      `session=${encodeURIComponent(
        sessionValue
      )}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
    );

    res.json({
      message: 'تم تسجيل الدخول.',
      user: safeUser(user)
    });
  } catch (error) {
    console.error('Login error:', error);

    res.status(500).json({
      message: 'حدث خطأ أثناء تسجيل الدخول.'
    });
  }
});

/* =========================
   Logout
========================= */

app.post('/api/logout', (req, res) => {
  res.setHeader(
    'Set-Cookie',
    'session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
  );

  res.json({
    message: 'تم تسجيل الخروج.'
  });
});

/* =========================
   Student dashboard
========================= */

app.get(
  '/api/student/dashboard',
  requireAuth,
  async (req, res) => {
    try {
      const settings = await DB()
        .prepare(
          'SELECT * FROM settings WHERE id = 1 LIMIT 1'
        )
        .first();

      const rows = await DB()
        .prepare(`
          SELECT
            id,
            user_id,
            date,
            status,
            method,
            created_at
          FROM attendance
          WHERE user_id = ?
          ORDER BY date DESC
        `)
        .bind(req.user.id)
        .all();

      const state = lectureState(settings);

      res.json({
        user: safeUser(req.user),

        lecture: {
          title:
            settings?.lecture_title ||
            'المحاضرة القادمة',

          url: state.visible
            ? settings?.lecture_url || ''
            : '',

          scheduledAt:
            settings?.scheduled_at || '',

          state
        },

        attendance: rows.results || []
      });
    } catch (error) {
      console.error(
        'Student dashboard error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل بيانات الطالب.'
      });
    }
  }
);

/* =========================
   Student check-in
========================= */

app.post(
  '/api/student/checkin',
  requireAuth,
  async (req, res) => {
    try {
      if (req.user.role !== 'student') {
        return res.status(400).json({
          message:
            'حساب المدرس لا يحتاج تسجيل حضور.'
        });
      }

      const settings = await DB()
        .prepare(
          'SELECT * FROM settings WHERE id = 1 LIMIT 1'
        )
        .first();

      const state =
        lectureState(settings);

      if (
        !state.visible ||
        !settings?.lecture_url
      ) {
        return res.status(400).json({
          message:
            'تسجيل الحضور متاح قبل المحاضرة بخمس دقائق وحتى وقتها.'
        });
      }

      const date = today();

      const already = await DB()
        .prepare(`
          SELECT id
          FROM attendance
          WHERE user_id = ?
          AND date = ?
          LIMIT 1
        `)
        .bind(req.user.id, date)
        .first();

      if (already) {
        return res.json({
          message:
            'تم تسجيل حضورك بالفعل اليوم.'
        });
      }

      await DB()
        .prepare(`
          INSERT INTO attendance
          (
            id,
            user_id,
            date,
            status,
            method,
            created_at
          )
          VALUES (?, ?, ?, ?, ?, ?)
        `)
        .bind(
          crypto.randomUUID(),
          req.user.id,
          date,
          'حاضر',
          'student',
          nowIso()
        )
        .run();

      res.json({
        message:
          'تم تسجيل حضورك.'
      });
    } catch (error) {
      console.error(
        'Check-in error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء تسجيل الحضور.'
      });
    }
  }
);

/* =========================
   Admin users
========================= */

app.get(
  '/api/admin/users',
  requireAdmin,
  async (req, res) => {
    try {
      const result = await DB()
        .prepare(`
          SELECT *
          FROM users
          WHERE role != 'admin'
          ORDER BY full_name
        `)
        .all();

      res.json({
        users:
          (result.results || [])
            .map(safeUser)
      });
    } catch (error) {
      console.error(
        'Admin users error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل الطلاب.'
      });
    }
  }
);

/* =========================
   Update user
========================= */

app.patch(
  '/api/admin/users/:id',
  requireAdmin,
  async (req, res) => {
    try {
      const user = await DB()
        .prepare(`
          SELECT id
          FROM users
          WHERE id = ?
          AND role = 'student'
          LIMIT 1
        `)
        .bind(req.params.id)
        .first();

      if (!user) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      if (
        typeof req.body.active ===
        'boolean'
      ) {
        await DB()
          .prepare(`
            UPDATE users
            SET active = ?
            WHERE id = ?
          `)
          .bind(
            req.body.active ? 1 : 0,
            req.params.id
          )
          .run();
      }

      if (
        typeof req.body.password ===
          'string' &&
        req.body.password.length >= 6
      ) {
        const hash =
          await bcrypt.hash(
            req.body.password,
            12
          );

        await DB()
          .prepare(`
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
          `)
          .bind(
            hash,
            req.params.id
          )
          .run();
      }

      res.json({
        message:
          'تم تحديث الحساب.'
      });
    } catch (error) {
      console.error(
        'Update user error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء تحديث الحساب.'
      });
    }
  }
);

/* =========================
   Delete user
========================= */

app.delete(
  '/api/admin/users/:id',
  requireAdmin,
  async (req, res) => {
    try {
      const user = await DB()
        .prepare(`
          SELECT id
          FROM users
          WHERE id = ?
          AND role = 'student'
          LIMIT 1
        `)
        .bind(req.params.id)
        .first();

      if (!user) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      await DB()
        .prepare(
          'DELETE FROM attendance WHERE user_id = ?'
        )
        .bind(req.params.id)
        .run();

      await DB()
        .prepare(
          "DELETE FROM users WHERE id = ? AND role = 'student'"
        )
        .bind(req.params.id)
        .run();

      res.json({
        message:
          'تم حذف الطالب.'
      });
    } catch (error) {
      console.error(
        'Delete user error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء حذف الطالب.'
      });
    }
  }
);

/* =========================
   Admin attendance
========================= */

app.get(
  '/api/admin/attendance',
  requireAdmin,
  async (req, res) => {
    try {
      const date =
        String(
          req.query.date || today()
        );

      const users = await DB()
        .prepare(`
          SELECT
            id,
            full_name,
            login,
            grade,
            subject,
            mode
          FROM users
          WHERE role = 'student'
          ORDER BY full_name
        `)
        .all();

      const attendance = await DB()
        .prepare(`
          SELECT user_id, status
          FROM attendance
          WHERE date = ?
        `)
        .bind(date)
        .all();

      const map =
        new Map(
          (attendance.results || [])
            .map((row) => [
              row.user_id,
              row.status
            ])
        );

      const rows =
        (users.results || [])
          .map((user) => ({
            userId: user.id,
            fullName: user.full_name,
            login: user.login,
            grade: user.grade,
            subject: user.subject,
            mode: user.mode,
            status:
              map.get(user.id) ||
              'غير محدد'
          }));

      res.json({
        date,
        rows
      });
    } catch (error) {
      console.error(
        'Attendance error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل الحضور.'
      });
    }
  }
);

/* =========================
   Set attendance
========================= */

app.post(
  '/api/admin/attendance',
  requireAdmin,
  async (req, res) => {
    try {
      const {
        userId,
        date,
        status
      } = req.body || {};

      if (
        !userId ||
        !date ||
        ![
          'حاضر',
          'غائب',
          'غير محدد'
        ].includes(status)
      ) {
        return res.status(400).json({
          message:
            'بيانات الحضور غير صحيحة.'
        });
      }

      const student =
        await DB()
          .prepare(`
            SELECT id
            FROM users
            WHERE id = ?
            AND role = 'student'
            LIMIT 1
          `)
          .bind(userId)
          .first();

      if (!student) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      await DB()
        .prepare(`
          DELETE FROM attendance
          WHERE user_id = ?
          AND date = ?
        `)
        .bind(userId, date)
        .run();

      if (status !== 'غير محدد') {
        await DB()
          .prepare(`
            INSERT INTO attendance
            (
              id,
              user_id,
              date,
              status,
              method,
              created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
          `)
          .bind(
            crypto.randomUUID(),
            userId,
            date,
            status,
            'admin',
            nowIso()
          )
          .run();
      }

      res.json({
        message:
          'تم تحديث الحضور.'
      });
    } catch (error) {
      console.error(
        'Set attendance error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء تحديث الحضور.'
      });
    }
  }
);

/* =========================
   Admin settings
========================= */

app.get(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    try {
      const settings =
        await DB()
          .prepare(
            'SELECT * FROM settings WHERE id = 1 LIMIT 1'
          )
          .first();

      res.json({
        settings:
          settings || {
            lecture_title:
              'المحاضرة القادمة',
            lecture_url: '',
            scheduled_at: ''
          }
      });
    } catch (error) {
      console.error(
        'Settings error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل إعدادات المحاضرة.'
      });
    }
  }
);

/* =========================
   Save lecture
========================= */

app.put(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    try {
      const lectureTitle =
        String(
          req.body?.lectureTitle ||
            'المحاضرة القادمة'
        ).trim();

      const lectureUrl =
        String(
          req.body?.lectureUrl || ''
        ).trim();

      const scheduledAt =
        String(
          req.body?.scheduledAt || ''
        ).trim();

      if (!validUrl(lectureUrl)) {
        return res.status(400).json({
          message:
            'رابط المحاضرة غير صحيح.'
        });
      }

      if (
        scheduledAt &&
        Number.isNaN(
          new Date(
            scheduledAt
          ).getTime()
        )
      ) {
        return res.status(400).json({
          message:
            'موعد المحاضرة غير صحيح.'
        });
      }

      await DB()
        .prepare(`
          INSERT INTO settings
          (
            id,
            lecture_title,
            lecture_url,
            scheduled_at,
            updated_at
          )
          VALUES (1, ?, ?, ?, ?)
          ON CONFLICT(id)
          DO UPDATE SET
            lecture_title =
              excluded.lecture_title,
            lecture_url =
              excluded.lecture_url,
            scheduled_at =
              excluded.scheduled_at,
            updated_at =
              excluded.updated_at
        `)
        .bind(
          lectureTitle,
          lectureUrl,
          scheduledAt,
          nowIso()
        )
        .run();

      res.json({
        message:
          'تم تحديث المحاضرة والرابط.'
      });
    } catch (error) {
      console.error(
        'Save settings error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء حفظ المحاضرة.'
      });
    }
  }
);

/* =========================
   Clear lecture
========================= */

app.delete(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    try {
      await DB()
        .prepare(`
          INSERT INTO settings
          (
            id,
            lecture_title,
            lecture_url,
            scheduled_at,
            updated_at
          )
          VALUES
          (
            1,
            'المحاضرة القادمة',
            '',
            '',
            ?
          )
          ON CONFLICT(id)
          DO UPDATE SET
            lecture_title =
              'المحاضرة القادمة',
            lecture_url = '',
            scheduled_at = '',
            updated_at =
              excluded.updated_at
        `)
        .bind(nowIso())
        .run();

      res.json({
        message:
          'تم مسح المحاضرة الحالية.'
      });
    } catch (error) {
      console.error(
        'Clear settings error:',
        error
      );

      res.status(500).json({
        message:
          'حدث خطأ أثناء مسح المحاضرة.'
      });
    }
  }
);

/* =========================
   Ensure admin for API requests
========================= */

app.use(async (req, res, next) => {
  if (!req.path.startsWith('/api/')) {
    return next();
  }

  try {
    await ensureAdminOnce();
    next();
  } catch (error) {
    console.error(
      'Admin initialization error:',
      error
    );

    res.status(500).json({
      message:
        'تعذر تجهيز حساب المدرس.'
    });
  }
});

/* =========================
   Static assets
========================= */

app.use(async (req, res) => {
  try {
    if (!env.ASSETS) {
      return res.status(404).send('Not Found');
    }

    const pathname =
      req.originalUrl || '/';

    const assetUrl =
      new URL(
        pathname,
        'https://assets.local'
      );

    const response =
      await env.ASSETS.fetch(
        assetUrl
      );

    response.headers.forEach(
      (value, key) => {
        res.setHeader(key, value);
      }
    );

    const body =
      Buffer.from(
        await response.arrayBuffer()
      );

    res.status(
      response.status
    ).send(body);
  } catch (error) {
    console.error(
      'Asset error:',
      error
    );

    res.status(500).send(
      'Asset error'
    );
  }
});

/* =========================
   Cloudflare Express
========================= */

app.listen(3000);

export default {
  fetch: httpServerHandler({
    port: 3000
  })
};
وكمان عدّل wrangler.jsonc

دي مهمة جدًا لأننا بنستخدم env.ASSETS. Cloudflare يوضح إن الـbinding لازم يتحدد باسم ASSETS علشان نقدر نستعمله من الكود.

{
  "$schema": "./node_modules/wrangler/config-schema.json",
  "name": "mr-mohamed-hossam-platform",
  "main": "server.js",
  "compatibility_date": "2026-09-28",
  "compatibility_flags": [
    "nodejs_compat"
  ],
  "assets": {
    "directory": "./public",
    "binding": "ASSETS"
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "mr-mohamed-hossam-db",
      "database_id": "b7facb0f-73b3-4875-9079-0f98043edf28"
    }
  ]
}

Cloudflare حاليًا يوضح رسميًا أن Express على Workers يستخدم app.listen(3000) مع httpServerHandler({ port: 3000 })، وأن static assets يمكن ربطها بـASSETS واستخدام env.ASSETS.fetch(...).

بعد التعديل ارفع server.js وwrangler.jsonc على GitHub، وبعدها اعمل Retry deployment. ما تغيّرش index.html أو styles.css أو app.js؛ دول واجهة المنصة القديمة اللي حافظنا عليها.
