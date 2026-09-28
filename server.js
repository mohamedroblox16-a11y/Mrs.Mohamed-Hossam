import express from 'express';
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
  return `${userId}.${await sign(userId)}`;
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
    await DB().prepare(`
      INSERT INTO users (id,full_name,login,grade,subject,mode,role,active,created_at,password_hash)
      VALUES (?,? ,?,?,?,?, 'admin',1,?,?)
    `).bind(
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
  await DB().prepare(`
    INSERT INTO users (id,full_name,login,grade,subject,mode,role,active,created_at,password_hash)
    VALUES (?,?,?,?,?,?, 'student',1,?,?)
  `).bind(crypto.randomUUID(), name, userLogin, String(grade), String(subject), String(mode), nowIso(), await bcrypt.hash(String(password), 12)).run();
  res.status(201).json({ message: 'تم إنشاء الحساب بنجاح.' });
});

app.post('/api/login', async (req, res) => {
  const login = normalizeLogin(req.body?.login);
  const password = String(req.body?.password || '');
  const user = await DB().prepare('SELECT * FROM users WHERE login = ? LIMIT 1').bind(login).first();
  if (!user || !user.active || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ message: 'بيانات الدخول غير صحيحة.' });
  res.setHeader('Set-Cookie', `session=${encodeURIComponent(await makeSession(user.id))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`);
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
  await DB().prepare(`
    INSERT INTO settings (id,lecture_title,lecture_url,scheduled_at,updated_at) VALUES (1,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET lecture_title=excluded.lecture_title, lecture_url=excluded.lecture_url, scheduled_at=excluded.scheduled_at, updated_at=excluded.updated_at
  `).bind(lectureTitle, lectureUrl, scheduledAt, nowIso()).run();
  res.json({ message: 'تم تحديث المحاضرة والرابط.' });
});

app.delete('/api/admin/settings', requireAdmin, async (req, res) => {
  await DB().prepare(`
    INSERT INTO settings (id,lecture_title,lecture_url,scheduled_at,updated_at) VALUES (1,'المحاضرة القادمة','','',?)
    ON CONFLICT(id) DO UPDATE SET lecture_title='المحاضرة القادمة', lecture_url='', scheduled_at='', updated_at=excluded.updated_at
  `).bind(nowIso()).run();
  res.json({ message: 'تم مسح المحاضرة الحالية.' });
});

async function serveAsset(req, res) {
  if (!env.ASSETS) return res.status(404).json({ message: 'الملف غير موجود.' });
  const host = req.headers.host || 'localhost';
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const url = `${protocol}://${host}${req.originalUrl}`;
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
