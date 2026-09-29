import express from 'express';
import bcrypt from 'bcryptjs';
import { httpServerHandler } from 'cloudflare:node';
import { env } from 'cloudflare:workers';

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/api', (req, res, next) => {
  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

const DB = () => env.DB;
const RUNTIME_CODE_VERSION = '2026-09-29-secret-runtime-fix-2';
const nowIso = () => new Date().toISOString();

async function ensureUserEmailColumns() {
  const columns = [
    ['email', "ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''"],
    ['email_verified', "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0"],
    ['email_verification_code_hash', "ALTER TABLE users ADD COLUMN email_verification_code_hash TEXT NOT NULL DEFAULT ''"],
    ['email_verification_expires_at', "ALTER TABLE users ADD COLUMN email_verification_expires_at TEXT NOT NULL DEFAULT ''"],
    ['email_verification_sent_at', "ALTER TABLE users ADD COLUMN email_verification_sent_at TEXT NOT NULL DEFAULT ''"]
  ];

  for (const [column, alterSql] of columns) {
    try {
      await DB()
        .prepare('SELECT ' + column + ' FROM users LIMIT 1')
        .first();
    } catch {
      await DB()
        .prepare(alterSql)
        .run();
    }
  }
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    String(value || '').trim()
  );
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function sha256Hex(value) {
  const buffer =
    await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(
        String(value)
      )
    );

  return Array.from(
    new Uint8Array(buffer)
  )
    .map(
      (b) =>
        b.toString(16).padStart(2, '0')
    )
    .join('');
}

function generateEmailCode() {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);

  return String(
    array[0] % 1000000
  ).padStart(6, '0');
}

function maskEmail(value) {
  const email = String(value || '').trim();
  const at = email.indexOf('@');

  if (at <= 0) return '';

  const local = email.slice(0, at);
  const domain = email.slice(at + 1);

  if (local.length <= 2) {
    return '*'.repeat(local.length) + '@' + domain;
  }

  return (
    local[0] +
    '*'.repeat(
      Math.max(1, local.length - 2)
    ) +
    local.slice(-1) +
    '@' +
    domain
  );
}

async function makeEmailVerificationToken(
  userId,
  expiresAt
) {
  const payload =
    String(userId) +
    '|' +
    String(expiresAt);

  return (
    payload +
    '.' +
    await sign(payload)
  );
}

async function verifyEmailVerificationToken(
  value
) {
  const raw =
    String(value || '');

  const lastDot =
    raw.lastIndexOf('.');

  if (lastDot <= 0) {
    return null;
  }

  const payload =
    raw.slice(0, lastDot);

  const signature =
    raw.slice(lastDot + 1);

  if (!payload || !signature) {
    return null;
  }

  if (
    signature !==
    await sign(payload)
  ) {
    return null;
  }

  const separator =
    payload.lastIndexOf('|');

  if (separator <= 0) {
    return null;
  }

  const userId =
    payload.slice(0, separator);

  const expiresAt =
    Number(
      payload.slice(separator + 1)
    );

  if (
    !userId ||
    !Number.isFinite(expiresAt) ||
    Date.now() > expiresAt
  ) {
    return null;
  }

  return {
    userId,
    expiresAt
  };
}

function getRuntimeSecret(name) {
  try {
    // Primary Cloudflare Workers runtime binding.
    const runtimeValue = env?.[name];

    if (String(runtimeValue || '').trim()) {
      return String(runtimeValue).trim();
    }

    // With nodejs_compat_populate_process_env, runtime bindings
    // (including secrets) are also available through process.env.
    const processValue =
      globalThis?.process?.env?.[name];

    if (String(processValue || '').trim()) {
      return String(processValue).trim();
    }

    return '';
  } catch {
    return '';
  }
}

async function sendResendBatch(recipients, subject, message) {
  const apiKey = getRuntimeSecret('RESEND_API_KEY');

  const from =
    getRuntimeSecret('RESEND_FROM_EMAIL') ||
    'mrsmohamedteam@gmail.com';

  if (!apiKey) {
    throw new Error(
      'RESEND_API_KEY غير متاح للـWorker المنشور. تأكد أنه Secret داخل Worker mrs-mohamed-hossam ثم اعمل Deploy.'
    );
  }

  const uniqueEmails = [];
  const seen = new Set();

  for (const item of recipients || []) {
    const email = String(item?.email || '').trim().toLowerCase();
    if (!validEmail(email) || seen.has(email)) continue;
    seen.add(email);
    uniqueEmails.push(email);
  }

  if (!uniqueEmails.length) {
    return { sentCount: 0, totalRecipients: 0 };
  }

  const html = `
    <div dir="rtl" style="font-family:Arial,sans-serif;line-height:1.9;color:#20253a">
      ${escapeHtml(message).replace(/\r?\n/g, '<br>')}
    </div>
  `;

  let sentCount = 0;

  for (let i = 0; i < uniqueEmails.length; i += 100) {
    const chunk = uniqueEmails.slice(i, i + 100);

    const payload = chunk.map((email) => ({
      from,
      to: [email],
      subject: String(subject || '').trim(),
      html
    }));

    const response = await fetch('https://api.resend.com/emails/batch', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    let data = {};
    try {
      data = await response.json();
    } catch {}

    if (!response.ok) {
      console.error('Resend error:', data);
      throw new Error(
        data?.message ||
        data?.error ||
        `فشل إرسال البريد من Resend (HTTP ${response.status}).`
      );
    }

    sentCount += chunk.length;
  }

  return {
    sentCount,
    totalRecipients: uniqueEmails.length
  };
}

const normalizeLogin = (v) =>
  String(v ?? '').trim().toLowerCase();

const validUrl = (v) => {
  if (!v) return true;

  try {
    const u = new URL(v);
    return (
      u.protocol === 'http:' ||
      u.protocol === 'https:'
    );
  } catch {
    return false;
  }
};

function today() {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Africa/Cairo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(new Date());

  const get = (type) =>
    parts.find(
      (part) => part.type === type
    )?.value || '';

  return (
    `${get('year')}-` +
    `${get('month')}-` +
    `${get('day')}`
  );
}

function normalizeLectureDateTime(value) {
  const raw = String(value || '').trim();

  if (!raw) return '';

  if (
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(raw)
  ) {
    const d = new Date(
      `${raw}:00+03:00`
    );

    if (Number.isNaN(d.getTime())) {
      return null;
    }

    return d.toISOString();
  }

  const parsed = new Date(raw);

  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed.toISOString();
}

function safeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    fullName: user.full_name,
    login: user.login,
    email: user.email || '',
    emailVerified:
      user.role === 'admin'
        ? true
        : !!user.email_verified,
    grade: user.grade,
    subject: user.subject,
    mode: user.mode,
    role: user.role,
    active: !!user.active,
    createdAt: user.created_at
  };
}

const DEFAULT_ADMIN_LOGIN = 'admin';
const DEFAULT_ADMIN_PASSWORD = '123456';

const adminLogin = () =>
  normalizeLogin(
    env.ADMIN_LOGIN || DEFAULT_ADMIN_LOGIN
  );

const adminPassword = () =>
  String(
    env.ADMIN_PASSWORD ||
    DEFAULT_ADMIN_PASSWORD
  );

function isAdminCredentials(
  login,
  password
) {
  return (
    (
      login === DEFAULT_ADMIN_LOGIN &&
      password === DEFAULT_ADMIN_PASSWORD
    ) ||
    (
      login === adminLogin() &&
      password === adminPassword()
    )
  );
}

/*
  إصلاح مشكلة تسجيل الدخول:
  Secure لا يتفعل على localhost HTTP
  ويتفعل تلقائيًا على HTTPS.
*/

function isHttpsRequest(req) {
  let proto = '';

  try {
    if (
      typeof req?.headers?.get ===
      'function'
    ) {
      proto =
        req.headers.get(
          'x-forwarded-proto'
        ) ||
        req.headers.get(
          'X-Forwarded-Proto'
        ) ||
        '';
    } else {
      proto =
        req?.headers?.[
          'x-forwarded-proto'
        ] || '';
    }
  } catch {
    proto = '';
  }

  return (
    proto === 'https' ||
    (
      typeof req?.protocol ===
      'string' &&
      req.protocol ===
      'https'
    )
  );
}

function appendSetCookie(
  res,
  cookie
) {
  const existing =
    res.getHeader('Set-Cookie');

  const list =
    Array.isArray(existing)
      ? existing
      : existing
        ? [existing]
        : [];

  list.push(cookie);

  res.setHeader(
    'Set-Cookie',
    list
  );
}

function makeCookieString(
  req,
  name,
  value,
  maxAge
) {
  const secure =
    isHttpsRequest(req)
      ? '; Secure'
      : '';

  return (
    name +
    '=' +
    encodeURIComponent(value) +
    '; Path=/; HttpOnly; SameSite=Lax' +
    secure +
    '; Max-Age=' +
    maxAge
  );
}

function setSessionCookie(
  req,
  res,
  value,
  maxAge = 604800
) {
  res.setHeader(
    'Set-Cookie',
    makeCookieString(
      req,
      'session',
      value,
      maxAge
    )
  );
}

function setEmailVerificationCookie(
  req,
  res,
  value,
  maxAge = 600
) {
  appendSetCookie(
    res,
    makeCookieString(
      req,
      'emailVerifyPending',
      value,
      maxAge
    )
  );
}

function clearEmailVerificationCookie(
  req,
  res
) {
  setEmailVerificationCookie(
    req,
    res,
    '',
    0
  );
}

async function sign(value) {
  const secret = String(
    env.SESSION_SECRET ||
    'mohamed-hossam-session-secret-2026'
  );

  const key =
    await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(
        secret
      ),
      {
        name: 'HMAC',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    );

  const sig =
    await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(
        value
      )
    );

  return Array.from(
    new Uint8Array(sig)
  )
    .map(
      (b) =>
        b.toString(16)
          .padStart(2, '0')
    )
    .join('');
}

async function makeSession(
  userId
) {
  return (
    `${userId}.` +
    `${await sign(userId)}`
  );
}

async function verifySession(
  value
) {
  if (
    !value ||
    !value.includes('.')
  ) {
    return null;
  }

  const [
    id,
    signature,
    extra
  ] = value.split('.');

  if (
    extra ||
    !id ||
    !signature
  ) {
    return null;
  }

  return (
    signature ===
    await sign(id)
  )
    ? id
    : null;
}

function getCookie(
  req,
  name
) {
  const headers =
    req?.headers || {};

  let raw = '';

  try {
    raw =
      typeof headers.get ===
      'function'
        ? (
            headers.get(
              'cookie'
            ) ||
            headers.get(
              'Cookie'
            ) ||
            ''
          )
        : (
            headers.cookie ||
            headers.Cookie ||
            ''
          );
  } catch {
    raw = '';
  }

  for (
    const part of
    String(raw).split(';')
  ) {
    const [
      key,
      ...rest
    ] =
      part
        .trim()
        .split('=');

    if (key === name) {
      try {
        return decodeURIComponent(
          rest.join('=')
        );
      } catch {
        return '';
      }
    }
  }

  return '';
}

async function currentUser(
  req
) {
  await ensureUserEmailColumns();

  const sessionId =
    await verifySession(
      getCookie(
        req,
        'session'
      )
    );

  if (!sessionId) {
    return null;
  }

  const user =
    await DB()
      .prepare(
        'SELECT * FROM users WHERE id = ? LIMIT 1'
      )
      .bind(sessionId)
      .first();

  return (
    user && user.active
      ? user
      : null
  );
}

async function ensureAdminAccount() {
  const login =
    adminLogin();

  const password =
    adminPassword();

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  const existing =
    await DB()
      .prepare(
        'SELECT * FROM users WHERE login = ? LIMIT 1'
      )
      .bind(login)
      .first();

  if (existing) {
    await DB()
      .prepare(`
        UPDATE users SET
          full_name = ?,
          grade = ?,
          subject = ?,
          mode = ?,
          role = 'admin',
          active = 1,
          password_hash = ?
        WHERE id = ?
      `)
      .bind(
        'مستر محمد حسام',
        'مدرس',
        'كل المواد',
        'إدارة المنصة',
        passwordHash,
        existing.id
      )
      .run();

    return DB()
      .prepare(
        'SELECT * FROM users WHERE id = ? LIMIT 1'
      )
      .bind(existing.id)
      .first();
  }

  const id =
    crypto.randomUUID();

  await DB()
    .prepare(`
      INSERT INTO users (
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
      VALUES (
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        'admin',
        1,
        ?,
        ?
      )
    `)
    .bind(
      id,
      'مستر محمد حسام',
      login,
      'مدرس',
      'كل المواد',
      'إدارة المنصة',
      nowIso(),
      passwordHash
    )
    .run();

  return DB()
    .prepare(
      'SELECT * FROM users WHERE id = ? LIMIT 1'
    )
    .bind(id)
    .first();
}

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const user =
      await currentUser(req);

    if (!user) {
      return res.status(401).json({
        message:
          'يجب تسجيل الدخول أولاً.'
      });
    }

    req.user = user;

    return next();
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message:
        'حدث خطأ أثناء التحقق من الحساب.'
    });
  }
}

async function requireAdmin(
  req,
  res,
  next
) {
  try {
    const user =
      await currentUser(req);

    if (!user) {
      return res.status(401).json({
        message:
          'يجب تسجيل الدخول أولاً.'
      });
    }

    if (
      user.role !== 'admin'
    ) {
      return res.status(403).json({
        message:
          'هذه الصفحة خاصة بالمدرس.'
      });
    }

    req.user = user;

    return next();
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message:
        'حدث خطأ أثناء التحقق من الصلاحيات.'
    });
  }
}

function lectureState(
  settings
) {
  if (
    !settings?.lecture_url
  ) {
    return {
      visible: false,
      reason: 'no-link'
    };
  }

  if (
    !settings.scheduled_at
  ) {
    return {
      visible: true,
      reason: 'always'
    };
  }

  const scheduledTime =
    new Date(
      settings.scheduled_at
    ).getTime();

  if (
    Number.isNaN(
      scheduledTime
    )
  ) {
    return {
      visible: true,
      reason:
        'invalid-schedule'
    };
  }

  const showAt =
    scheduledTime -
    5 * 60 * 1000;

  const visible =
    Date.now() >=
    showAt;

  return {
    visible,

    reason:
      visible
        ? 'live-window'
        : 'not-yet',

    showAt:
      new Date(
        showAt
      ).toISOString(),

    scheduledAt:
      new Date(
        scheduledTime
      ).toISOString()
  };
}

async function ensureGradesTable() {
  await DB()
    .prepare(`
      CREATE TABLE IF NOT EXISTS grades (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        exam_name TEXT NOT NULL,
        lesson_name TEXT NOT NULL,
        score REAL NOT NULL,
        total REAL NOT NULL,
        created_at TEXT NOT NULL
      )
    `)
    .run();
}

/* =========================
   HEALTH
========================= */

app.get(
  '/api/health',
  (req, res) => {
    return res.json({
      ok: true,
      platform:
        'cloudflare-workers',
      codeVersion:
        RUNTIME_CODE_VERSION,
      message:
        'Worker is running'
    });
  }
);

/* =========================
   AUTH
========================= */

app.get(
  '/api/me',
  requireAuth,
  (req, res) => {
    return res.json({
      user:
        safeUser(
          req.user
        )
    });
  }
);

app.post(
  '/api/register',
  async (req, res) => {
    try {
      await ensureUserEmailColumns();

      const {
        fullName,
        login,
        username,
        phoneOrDiscord,
        phone,
        identifier,
        email,
        grade,
        subject,
        mode,
        password,
        confirmPassword,
        passwordConfirm
      } = req.body || {};

      const name =
        String(
          fullName || ''
        ).trim();

      const userEmail =
        String(email || '')
          .trim()
          .toLowerCase();

      const rawLogin =
        login ??
        username ??
        phoneOrDiscord ??
        phone ??
        identifier ??
        '';

      const userLogin =
        normalizeLogin(
          rawLogin
        );

      const passwordText =
        String(
          password || ''
        );

      const confirmation =
        String(
          confirmPassword ??
          passwordConfirm ??
          passwordText
        );

      if (
        name
          .split(/\s+/)
          .filter(Boolean)
          .length !== 3
      ) {
        return res.status(400).json({
          message:
            'اكتب اسمك ثلاثي.'
        });
      }

      if (
        !userLogin ||
        !userEmail ||
        !grade ||
        !subject ||
        !mode
      ) {
        return res.status(400).json({
          message:
            'أكمل كل البيانات، بما فيها الإيميل.'
        });
      }

      if (!validEmail(userEmail)) {
        return res.status(400).json({
          message:
            'اكتب إيميل صحيح.'
        });
      }

      if (
        passwordText.length < 6
      ) {
        return res.status(400).json({
          message:
            'الباسورد يجب أن يكون 6 أحرف أو أرقام على الأقل.'
        });
      }

      if (
        passwordText !==
        confirmation
      ) {
        return res.status(400).json({
          message:
            'تأكيد الباسورد غير مطابق.'
        });
      }

      if (
        userLogin ===
          DEFAULT_ADMIN_LOGIN ||
        userLogin ===
          adminLogin()
      ) {
        return res.status(409).json({
          message:
            'اسم الدخول ده محجوز للمدرس.'
        });
      }

      const existing =
        await DB()
          .prepare(
            'SELECT id FROM users WHERE login = ? LIMIT 1'
          )
          .bind(userLogin)
          .first();

      if (existing) {
        return res.status(409).json({
          message:
            'هذا الرقم أو اليوزر مستخدم بالفعل.'
        });
      }

      const existingEmail =
        await DB()
          .prepare(
            'SELECT id FROM users WHERE email = ? LIMIT 1'
          )
          .bind(userEmail)
          .first();

      if (existingEmail) {
        return res.status(409).json({
          message:
            'الإيميل مستخدم بالفعل.'
        });
      }

      const passwordHash =
        await bcrypt.hash(
          passwordText,
          12
        );

      await DB()
        .prepare(`
          INSERT INTO users (
            id,
            full_name,
            login,
            email,
            email_verified,
            email_verification_code_hash,
            email_verification_expires_at,
            email_verification_sent_at,
            grade,
            subject,
            mode,
            role,
            active,
            created_at,
            password_hash
          )
          VALUES (
            ?,
            ?,
            ?,
            ?,
            0,
            '',
            '',
            '',
            ?,
            ?,
            ?,
            'student',
            1,
            ?,
            ?
          )
        `)
        .bind(
          crypto.randomUUID(),
          name,
          userLogin,
          userEmail,
          String(grade),
          String(subject),
          String(mode),
          nowIso(),
          passwordHash
        )
        .run();

      return res.status(201).json({
        message:
          'تم إنشاء الحساب بنجاح.'
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء إنشاء الحساب.'
      });
    }
  }
);

app.post(
  '/api/login',
  async (req, res) => {
    try {
      await ensureUserEmailColumns();

      const login =
        normalizeLogin(
          req.body?.login ??
          req.body?.username ??
          req.body?.phoneOrDiscord ??
          req.body?.phone ??
          req.body?.identifier ??
          req.body?.userLogin ??
          ''
        );

      const password =
        String(
          req.body?.password ??
          req.body?.pass ??
          ''
        );

      if (
        isAdminCredentials(
          login,
          password
        )
      ) {
        const admin =
          await ensureAdminAccount();

        if (!admin) {
          return res.status(500).json({
            message:
              'تعذر تجهيز حساب المدرس.'
          });
        }

        setSessionCookie(
          req,
          res,
          await makeSession(
            admin.id
          )
        );

        return res.json({
          message:
            'تم تسجيل دخول المدرس.',
          user:
            safeUser(
              admin
            )
        });
      }

      const user =
        await DB()
          .prepare(
            'SELECT * FROM users WHERE login = ? LIMIT 1'
          )
          .bind(login)
          .first();

      if (
        !user ||
        !user.active
      ) {
        return res.status(401).json({
          message:
            'بيانات الدخول غير صحيحة.'
        });
      }

      const ok =
        await bcrypt.compare(
          password,
          String(
            user.password_hash ||
            ''
          )
        );

      if (!ok) {
        return res.status(401).json({
          message:
            'بيانات الدخول غير صحيحة.'
        });
      }

      setSessionCookie(
        req,
        res,
        await makeSession(
          user.id
        )
      );

      return res.json({
        message:
          'تم تسجيل الدخول.',
        user:
          safeUser(
            user
          )
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تسجيل الدخول.'
      });
    }
  }
);

app.post(
  '/api/logout',
  (req, res) => {
    setSessionCookie(
      req,
      res,
      '',
      0
    );

    return res.json({
      message:
        'تم تسجيل الخروج.'
    });
  }
);

/* =========================
   STUDENT DASHBOARD
========================= */

app.get(
  '/api/student/dashboard',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role ===
        'admin'
      ) {
        return res.status(403).json({
          message:
            'حساب المدرس لا يستخدم لوحة الطالب.'
        });
      }

      const settings =
        await DB()
          .prepare(
            'SELECT * FROM settings WHERE id = 1 LIMIT 1'
          )
          .first();

      const attendance =
        await DB()
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
          .bind(
            req.user.id
          )
          .all();

      const state =
        lectureState(
          settings
        );

      return res.json({
        user:
          safeUser(
            req.user
          ),

        lecture: {
          title:
            settings?.lecture_title ||
            'المحاضرة القادمة',

          url:
            state.visible
              ? settings?.lecture_url || ''
              : '',

          scheduledAt:
            settings?.scheduled_at ||
            '',

          state
        },

        attendance:
          attendance.results ||
          []
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل بيانات الطالب.'
      });
    }
  }
);

app.post(
  '/api/student/checkin',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        'student'
      ) {
        return res.status(400).json({
          message:
            'حساب المدرس لا يحتاج تسجيل حضور.'
        });
      }

      const settings =
        await DB()
          .prepare(
            'SELECT * FROM settings WHERE id = 1 LIMIT 1'
          )
          .first();

      const state =
        lectureState(
          settings
        );

      if (
        !state.visible ||
        !settings?.lecture_url
      ) {
        return res.status(400).json({
          message:
            'تسجيل الحضور متاح قبل المحاضرة بخمس دقائق وحتى وقتها.'
        });
      }

      const date =
        today();

      const already =
        await DB()
          .prepare(`
            SELECT id
            FROM attendance
            WHERE user_id = ?
              AND date = ?
            LIMIT 1
          `)
          .bind(
            req.user.id,
            date
          )
          .first();

      if (already) {
        return res.json({
          message:
            'تم تسجيل حضورك بالفعل اليوم.'
        });
      }

      await DB()
        .prepare(`
          INSERT INTO attendance (
            id,
            user_id,
            date,
            status,
            method,
            created_at
          )
          VALUES (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
          )
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

      return res.json({
        message:
          'تم تسجيل حضورك.'
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تسجيل الحضور.'
      });
    }
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  '/api/admin/users',
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await DB()
          .prepare(`
            SELECT *
            FROM users
            WHERE role != 'admin'
            ORDER BY full_name
          `)
          .all();

      return res.json({
        users:
          (result.results || [])
            .map(
              safeUser
            )
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل الطلاب.'
      });
    }
  }
);

/* =========================
   STUDENT PROFILE
========================= */

app.get(
  '/api/admin/students/:id/profile',
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        String(
          req.params.id ||
          ''
        ).trim();

      const student =
        await DB()
          .prepare(`
            SELECT
              id,
              full_name,
              login,
              grade,
              subject,
              mode,
              role,
              active,
              created_at
            FROM users
            WHERE id = ?
              AND role = 'student'
            LIMIT 1
          `)
          .bind(id)
          .first();

      if (!student) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      await ensureGradesTable();

      const gradesResult =
        await DB()
          .prepare(`
            SELECT
              id,
              exam_name,
              lesson_name,
              score,
              total,
              created_at
            FROM grades
            WHERE user_id = ?
            ORDER BY created_at DESC
          `)
          .bind(id)
          .all();

      const attendanceResult =
        await DB()
          .prepare(`
            SELECT
              id,
              date,
              status,
              method,
              created_at
            FROM attendance
            WHERE user_id = ?
            ORDER BY date DESC
          `)
          .bind(id)
          .all();

      const grades =
        gradesResult.results ||
        [];

      const attendance =
        attendanceResult.results ||
        [];

      const present =
        attendance.filter(
          (row) =>
            row.status ===
            'حاضر'
        ).length;

      const absent =
        attendance.filter(
          (row) =>
            row.status ===
            'غائب'
        ).length;

      const unspecified =
        attendance.filter(
          (row) =>
            row.status ===
            'غير محدد'
        ).length;

      const totalScore =
        grades.reduce(
          (sum, row) =>
            sum +
            Number(
              row.score || 0
            ),
          0
        );

      const totalMax =
        grades.reduce(
          (sum, row) =>
            sum +
            Number(
              row.total || 0
            ),
          0
        );

      const percentage =
        totalMax > 0
          ? Math.round(
              (
                totalScore /
                totalMax
              ) *
              100
            )
          : 0;

      return res.json({
        profile: {
          id:
            student.id,

          fullName:
            student.full_name,

          login:
            student.login,

          grade:
            student.grade,

          subject:
            student.subject,

          mode:
            student.mode,

          role:
            student.role,

          active:
            !!student.active,

          createdAt:
            student.created_at
        },

        stats: {
          gradesCount:
            grades.length,

          attendanceCount:
            attendance.length,

          present,
          absent,
          unspecified,

          totalScore,
          totalMax,
          percentage
        },

        grades,

        attendance
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل بروفايل الطالب.'
      });
    }
  }
);

/* =========================
   EDIT STUDENT
========================= */

app.patch(
  '/api/admin/users/:id',
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        String(
          req.params.id ||
          ''
        ).trim();

      const student =
        await DB()
          .prepare(`
            SELECT *
            FROM users
            WHERE id = ?
              AND role = 'student'
            LIMIT 1
          `)
          .bind(id)
          .first();

      if (!student) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      const fullName =
        String(
          req.body?.fullName ??
          student.full_name
        ).trim();

      const login =
        normalizeLogin(
          req.body?.login ??
          student.login
        );

      const grade =
        String(
          req.body?.grade ??
          student.grade
        ).trim();

      const subject =
        String(
          req.body?.subject ??
          student.subject
        ).trim();

      const mode =
        String(
          req.body?.mode ??
          student.mode
        ).trim();

      const email =
        String(
          req.body?.email ??
          student.email ??
          ''
        ).trim().toLowerCase();

      const emailChanged =
        email !==
        String(
          student.email || ''
        ).trim().toLowerCase();

      const active =
        Number(
          req.body?.active ??
          student.active
        )
          ? 1
          : 0;

      if (
        !fullName ||
        !login ||
        !email ||
        !grade ||
        !subject ||
        !mode
      ) {
        return res.status(400).json({
          message:
            'أكمل بيانات الطالب والإيميل.'
        });
      }

      if (!validEmail(email)) {
        return res.status(400).json({
          message:
            'إيميل الطالب غير صحيح.'
        });
      }

      const duplicate =
        await DB()
          .prepare(`
            SELECT id
            FROM users
            WHERE login = ?
              AND id != ?
            LIMIT 1
          `)
          .bind(
            login,
            id
          )
          .first();

      if (duplicate) {
        return res.status(409).json({
          message:
            'رقم التلفون أو يوزر ديسكورد مستخدم بالفعل.'
        });
      }

      const duplicateEmail =
        await DB()
          .prepare('SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1')
          .bind(
            email,
            id
          )
          .first();

      if (duplicateEmail) {
        return res.status(409).json({
          message:
            'الإيميل مستخدم بالفعل مع طالب آخر.'
        });
      }

      let passwordHash =
        student.password_hash;

      if (
        req.body?.password !==
          undefined &&
        String(
          req.body.password
        ).length > 0
      ) {
        const password =
          String(
            req.body.password
          );

        if (
          password.length < 6
        ) {
          return res.status(400).json({
            message:
              'الباسورد يجب أن يكون 6 أحرف أو أرقام على الأقل.'
          });
        }

        passwordHash =
          await bcrypt.hash(
            password,
            12
          );
      }

      await DB()
        .prepare(`
          UPDATE users SET
            full_name = ?,
            login = ?,
            email = ?,
            email_verified = CASE WHEN ? THEN 0 ELSE email_verified END,
            email_verification_code_hash = CASE WHEN ? THEN '' ELSE email_verification_code_hash END,
            email_verification_expires_at = CASE WHEN ? THEN '' ELSE email_verification_expires_at END,
            email_verification_sent_at = CASE WHEN ? THEN '' ELSE email_verification_sent_at END,
            grade = ?,
            subject = ?,
            mode = ?,
            active = ?,
            password_hash = ?
          WHERE id = ?
            AND role = 'student'
        `)
        .bind(
          fullName,
          login,
          email,
          emailChanged ? 1 : 0,
          emailChanged ? 1 : 0,
          emailChanged ? 1 : 0,
          emailChanged ? 1 : 0,
          grade,
          subject,
          mode,
          active,
          passwordHash,
          id
        )
        .run();

      const updated =
        await DB()
          .prepare(
            'SELECT * FROM users WHERE id = ? LIMIT 1'
          )
          .bind(id)
          .first();

      return res.json({
        message:
          'تم تعديل بيانات الطالب بنجاح.',

        user:
          safeUser(
            updated
          )
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تعديل بيانات الطالب.'
      });
    }
  }
);

/* =========================
   EMAIL CONFIG STATUS
========================= */

app.get(
  '/api/admin/email-status',
  requireAdmin,
  async (req, res) => {
    return res.json({
      worker: 'mrs-mohamed-hossam',
      resendApiKeyConfigured:
        !!getRuntimeSecret('RESEND_API_KEY'),
      resendFromEmailConfigured:
        !!getRuntimeSecret('RESEND_FROM_EMAIL')
    });
  }
);

/* =========================
   EMAIL CENTER
========================= */

app.get(
  '/api/admin/email-students',
  requireAdmin,
  async (req, res) => {
    try {
      const result = await DB().prepare(
        'SELECT id, full_name, login, email, grade, subject, mode, active FROM users WHERE role = ? ORDER BY full_name'
      ).bind('student').all();

      return res.json({
        students: result.results || []
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: 'حدث خطأ أثناء تحميل قائمة الإيميلات.'
      });
    }
  }
);

app.post(
  '/api/admin/send-email',
  requireAdmin,
  async (req, res) => {
    try {
      const subject = String(req.body?.subject || '').trim();
      const message = String(req.body?.message || '').trim();
      const all = req.body?.all === true;
      const userIds = Array.isArray(req.body?.userIds)
        ? req.body.userIds.map((id) => String(id || '').trim()).filter(Boolean)
        : [];

      if (!subject) return res.status(400).json({ message: 'اكتب عنوان الرسالة.' });
      if (!message) return res.status(400).json({ message: 'اكتب نص الرسالة.' });
      if (!all && !userIds.length) {
        return res.status(400).json({ message: 'اختار طالبًا واحدًا على الأقل أو ALL.' });
      }

      let recipients = [];

      if (all) {
        const result = await DB().prepare(
          "SELECT id, full_name, email FROM users WHERE role = 'student' AND active = 1 AND TRIM(COALESCE(email, '')) != '' ORDER BY full_name"
        ).all();
        recipients = result.results || [];
      } else {
        const uniqueIds = [...new Set(userIds)];
        const placeholders = uniqueIds.map(() => '?').join(', ');
        const result = await DB().prepare(
          "SELECT id, full_name, email FROM users WHERE role = 'student' AND active = 1 AND id IN (" + placeholders + ") AND TRIM(COALESCE(email, '')) != '' ORDER BY full_name"
        ).bind(...uniqueIds).all();
        recipients = result.results || [];
      }

      if (!recipients.length) {
        return res.status(400).json({
          message: 'مفيش طلاب نشطين عندهم إيميلات في الاختيار.'
        });
      }

      const result = await sendResendBatch(
        recipients,
        subject,
        message
      );

      return res.json({
        message: 'تم إرسال الرسالة إلى ' + result.sentCount + ' طالب.',
        sentCount: result.sentCount,
        totalRecipients: result.totalRecipients
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: error.message || 'حدث خطأ أثناء إرسال الرسائل.'
      });
    }
  }
);
/* =========================
   DELETE STUDENT
========================= */

app.delete(
  '/api/admin/users/:id',
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        String(
          req.params.id ||
          ''
        ).trim();

      const student =
        await DB()
          .prepare(`
            SELECT id
            FROM users
            WHERE id = ?
              AND role = 'student'
            LIMIT 1
          `)
          .bind(id)
          .first();

      if (!student) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      await DB()
        .prepare(
          'DELETE FROM attendance WHERE user_id = ?'
        )
        .bind(id)
        .run();

      await ensureGradesTable();

      await DB()
        .prepare(
          'DELETE FROM grades WHERE user_id = ?'
        )
        .bind(id)
        .run();

      await DB()
        .prepare(`
          DELETE FROM users
          WHERE id = ?
            AND role = 'student'
        `)
        .bind(id)
        .run();

      return res.json({
        message:
          'تم حذف الطالب.'
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء حذف الطالب.'
      });
    }
  }
);

/* =========================
   GRADES
========================= */

app.get(
  '/api/student/grades',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        'student'
      ) {
        return res.status(403).json({
          message:
            'هذا المسار خاص بالطلاب.'
        });
      }

      await ensureGradesTable();

      const result =
        await DB()
          .prepare(`
            SELECT
              id,
              exam_name,
              lesson_name,
              score,
              total,
              created_at
            FROM grades
            WHERE user_id = ?
            ORDER BY created_at DESC
          `)
          .bind(
            req.user.id
          )
          .all();

      return res.json({
        grades:
          result.results ||
          []
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل الدرجات.'
      });
    }
  }
);

app.get(
  '/api/admin/grades',
  requireAdmin,
  async (req, res) => {
    try {
      const userId =
        String(
          req.query?.userId ||
          ''
        ).trim();

      if (!userId) {
        return res.status(400).json({
          message:
            'حدد الطالب أولاً.'
        });
      }

      await ensureGradesTable();

      const student =
        await DB()
          .prepare(`
            SELECT
              id,
              full_name
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

      const result =
        await DB()
          .prepare(`
            SELECT
              id,
              user_id,
              exam_name,
              lesson_name,
              score,
              total,
              created_at
            FROM grades
            WHERE user_id = ?
            ORDER BY created_at DESC
          `)
          .bind(userId)
          .all();

      return res.json({
        student: {
          id:
            student.id,

          fullName:
            student.full_name
        },

        grades:
          result.results ||
          []
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل درجات الطالب.'
      });
    }
  }
);

app.post(
  '/api/admin/grades',
  requireAdmin,
  async (req, res) => {
    try {
      const userId =
        String(
          req.body?.userId ||
          ''
        ).trim();

      const examName =
        String(
          req.body?.examName ||
          ''
        ).trim();

      const lessonName =
        String(
          req.body?.lessonName ||
          ''
        ).trim();

      const score =
        Number(
          req.body?.score
        );

      const total =
        Number(
          req.body?.total
        );

      if (
        !userId ||
        !examName ||
        !lessonName
      ) {
        return res.status(400).json({
          message:
            'اختر الطالب واكتب بيانات الامتحان.'
        });
      }

      if (
        !Number.isFinite(score) ||
        !Number.isFinite(total) ||
        total <= 0 ||
        score < 0 ||
        score > total
      ) {
        return res.status(400).json({
          message:
            'الدرجة المدخلة غير صحيحة.'
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

      await ensureGradesTable();

      const id =
        crypto.randomUUID();

      const createdAt =
        nowIso();

      await DB()
        .prepare(`
          INSERT INTO grades (
            id,
            user_id,
            exam_name,
            lesson_name,
            score,
            total,
            created_at
          )
          VALUES (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
          )
        `)
        .bind(
          id,
          userId,
          examName,
          lessonName,
          score,
          total,
          createdAt
        )
        .run();

      return res.status(201).json({
        message:
          'تمت إضافة الدرجة للطالب بنجاح.',

        grade: {
          id,
          userId,
          examName,
          lessonName,
          score,
          total,
          createdAt
        }
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء إضافة الدرجة.'
      });
    }
  }
);

app.delete(
  '/api/admin/grades/:id',
  requireAdmin,
  async (req, res) => {
    try {
      await ensureGradesTable();

      const id =
        String(
          req.params.id ||
          ''
        ).trim();

      const existing =
        await DB()
          .prepare(
            'SELECT id FROM grades WHERE id = ? LIMIT 1'
          )
          .bind(id)
          .first();

      if (!existing) {
        return res.status(404).json({
          message:
            'الدرجة غير موجودة.'
        });
      }

      await DB()
        .prepare(
          'DELETE FROM grades WHERE id = ?'
        )
        .bind(id)
        .run();

      return res.json({
        message:
          'تم حذف الدرجة.'
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء حذف الدرجة.'
      });
    }
  }
);

/* =========================
   ATTENDANCE
========================= */

app.get(
  '/api/admin/attendance',
  requireAdmin,
  async (req, res) => {
    try {
      const date =
        String(
          req.query?.date ||
          today()
        );

      const users =
        await DB()
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

      const attendance =
        await DB()
          .prepare(`
            SELECT
              user_id,
              status
            FROM attendance
            WHERE date = ?
          `)
          .bind(date)
          .all();

      const map =
        new Map(
          (
            attendance.results ||
            []
          ).map(
            (row) => [
              row.user_id,
              row.status
            ]
          )
        );

      const rows =
        (
          users.results ||
          []
        ).map(
          (user) => ({
            userId:
              user.id,

            fullName:
              user.full_name,

            login:
              user.login,

            grade:
              user.grade,

            subject:
              user.subject,

            mode:
              user.mode,

            status:
              map.get(
                user.id
              ) ||
              'غير محدد'
          })
        );

      return res.json({
        date,
        rows
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل الحضور.'
      });
    }
  }
);

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
        .bind(
          userId,
          date
        )
        .run();

      if (
        status !==
        'غير محدد'
      ) {
        await DB()
          .prepare(`
            INSERT INTO attendance (
              id,
              user_id,
              date,
              status,
              method,
              created_at
            )
            VALUES (
              ?,
              ?,
              ?,
              ?,
              ?,
              ?
            )
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

      return res.json({
        message:
          'تم تحديث الحضور.'
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحديث الحضور.'
      });
    }
  }
);

/* =========================
   LECTURE SETTINGS
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

      return res.json({
        settings:
          settings || {
            lecture_title:
              'المحاضرة القادمة',

            lecture_url:
              '',

            scheduled_at:
              ''
          }
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل إعدادات المحاضرة.'
      });
    }
  }
);

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
          req.body?.lectureUrl ||
          ''
        ).trim();

      const rawScheduledAt =
        String(
          req.body?.scheduledAt ||
          ''
        ).trim();

      if (
        lectureUrl &&
        !validUrl(lectureUrl)
      ) {
        return res.status(400).json({
          message:
            'رابط المحاضرة غير صحيح.'
        });
      }

      const scheduledAt =
        normalizeLectureDateTime(
          rawScheduledAt
        );

      if (
        scheduledAt === null
      ) {
        return res.status(400).json({
          message:
            'موعد المحاضرة غير صحيح.'
        });
      }

      await DB()
        .prepare(`
          INSERT INTO settings (
            id,
            lecture_title,
            lecture_url,
            scheduled_at,
            updated_at
          )
          VALUES (
            1,
            ?,
            ?,
            ?,
            ?
          )

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

      const saved =
        await DB()
          .prepare(
            'SELECT * FROM settings WHERE id = 1 LIMIT 1'
          )
          .first();

      return res.json({
        message:
          'تم حفظ موعد المحاضرة بنجاح.',

        settings:
          saved
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء حفظ موعد المحاضرة.'
      });
    }
  }
);

app.delete(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    try {
      const previousSettings =
        await DB()
          .prepare(
            'SELECT * FROM settings WHERE id = 1 LIMIT 1'
          )
          .first();

      await DB()
        .prepare(`
          INSERT INTO settings (
            id,
            lecture_title,
            lecture_url,
            scheduled_at,
            updated_at
          )
          VALUES (
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

            lecture_url =
              '',

            scheduled_at =
              '',

            updated_at =
              excluded.updated_at
        `)
        .bind(
          nowIso()
        )
        .run();

      let emailNotice = '';

      const hadLecture =
        !!(
          previousSettings?.lecture_title ||
          previousSettings?.lecture_url ||
          previousSettings?.scheduled_at
        );

      if (hadLecture) {
        try {
          const students =
            await DB()
              .prepare(
                "SELECT email FROM users WHERE role = 'student' AND active = 1 AND TRIM(COALESCE(email, '')) != ''"
              )
              .all();

          let whenText = '';

          if (previousSettings?.scheduled_at) {
            const date =
              new Date(
                previousSettings.scheduled_at
              );

            if (!Number.isNaN(date.getTime())) {
              whenText =
                date.toLocaleString(
                  'ar-EG',
                  {
                    timeZone:
                      'Africa/Cairo',
                    dateStyle:
                      'full',
                    timeStyle:
                      'short'
                  }
                );
            }
          }

          const message =
            'تم إلغاء المحاضرة من منصة مستر محمد حسام.\n\n' +
            'اسم المحاضرة: ' +
            (previousSettings?.lecture_title || 'المحاضرة القادمة') +
            (whenText
              ? '\nالموعد الذي كان محددًا: ' + whenText
              : '');

          const sent =
            await sendResendBatch(
              students.results || [],
              'تم إلغاء المحاضرة - منصة مستر محمد حسام',
              message
            );

          if (sent.sentCount) {
            emailNotice =
              ' وتم إرسال إشعار الإلغاء إلى ' +
              sent.sentCount +
              ' طالب.';
          }
        } catch (emailError) {
          console.error(
            'Cancellation email error:',
            emailError
          );

          emailNotice =
            ' لكن تعذر إرسال إشعارات الإلغاء لأن إعدادات البريد غير مكتملة أو حدث خطأ في خدمة البريد.';
        }
      }

      return res.json({
        message:
          'تم مسح المحاضرة الحالية.' +
          emailNotice
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message:
          'حدث خطأ أثناء مسح المحاضرة.'
      });
    }
  }
);

/* =========================
   API 404
========================= */

app.use(
  '/api',
  (req, res) => {
    return res.status(404).json({
      message:
        'المسار غير موجود.'
    });
  }
);

/* =========================
   ERRORS
========================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      'Unhandled Express error:',
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    return res.status(500).json({
      message:
        'حدث خطأ داخلي في السيرفر.',

      error:
        error?.message ||
        'Unknown error'
    });
  }
);

app.listen(3000);

export default httpServerHandler({
  port: 3000
});
