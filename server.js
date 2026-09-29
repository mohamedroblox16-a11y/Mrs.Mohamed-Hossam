import express from 'express';
import bcrypt from 'bcryptjs';
import { httpServerHandler } from 'cloudflare:node';
import { env } from 'cloudflare:workers';

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

/* =========================
   Helpers
========================= */

const DB = () => env.DB;

const nowIso = () =>
  new Date().toISOString();

const today = () =>
  new Date().toISOString().slice(0, 10);

const normalizeLogin = (value) =>
  String(value ?? '')
    .trim()
    .toLowerCase();

const validUrl = (value) => {
  if (!value) return true;

  try {
    const url = new URL(value);

    return (
      url.protocol === 'http:' ||
      url.protocol === 'https:'
    );
  } catch {
    return false;
  }
};

function safeUser(user) {
  if (!user) return null;

  return {
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
}

/* =========================
   Admin
========================= */

const DEFAULT_ADMIN_LOGIN = 'admin';
const DEFAULT_ADMIN_PASSWORD = '123456';

function configuredAdminLogin() {
  return normalizeLogin(
    env.ADMIN_LOGIN ||
    DEFAULT_ADMIN_LOGIN
  );
}

function configuredAdminPassword() {
  return String(
    env.ADMIN_PASSWORD ||
    DEFAULT_ADMIN_PASSWORD
  );
}

function isAdminCredentials(
  login,
  password
) {
  return (
    (
      login ===
      DEFAULT_ADMIN_LOGIN &&
      password ===
      DEFAULT_ADMIN_PASSWORD
    ) ||
    (
      login ===
      configuredAdminLogin() &&
      password ===
      configuredAdminPassword()
    )
  );
}

/* =========================
   Session
========================= */

async function sign(value) {
  const secret = String(
    env.SESSION_SECRET ||
    'mohamed-hossam-session-secret-2026'
  );

  const key =
    await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      {
        name: 'HMAC',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    );

  const signature =
    await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(value)
    );

  return Array.from(
    new Uint8Array(signature)
  )
    .map((byte) =>
      byte
        .toString(16)
        .padStart(2, '0')
    )
    .join('');
}

async function makeSession(userId) {
  return (
    userId +
    '.' +
    await sign(userId)
  );
}

async function verifySession(value) {
  if (
    !value ||
    !value.includes('.')
  ) {
    return null;
  }

  const parts =
    value.split('.');

  if (
    parts.length !== 2
  ) {
    return null;
  }

  const id = parts[0];
  const signature = parts[1];

  if (!id || !signature) {
    return null;
  }

  const expected =
    await sign(id);

  if (
    signature !== expected
  ) {
    return null;
  }

  return id;
}

function getCookie(
  req,
  name
) {
  const headers =
    req?.headers || {};

  let raw = '';

  try {
    if (
      headers &&
      typeof headers.get === 'function'
    ) {
      raw =
        headers.get('cookie') ||
        headers.get('Cookie') ||
        '';
    } else {
      raw =
        headers.cookie ||
        headers.Cookie ||
        '';
    }
  } catch {
    raw = '';
  }

  for (
    const part of String(raw).split(';')
  ) {
    const [
      key,
      ...rest
    ] = part.trim().split('=');

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

function setSessionCookie(
  res,
  value,
  maxAge = 604800
) {
  res.setHeader(
    'Set-Cookie',
    `session=${encodeURIComponent(
      value
    )}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`
  );
}

async function currentUser(req) {
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
    user &&
    user.active
  )
    ? user
    : null;
}

/* =========================
   Ensure Admin
========================= */

async function ensureAdminAccount() {
  const login =
    configuredAdminLogin();

  const password =
    configuredAdminPassword();

  const existing =
    await DB()
      .prepare(
        'SELECT * FROM users WHERE login = ? LIMIT 1'
      )
      .bind(login)
      .first();

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  if (existing) {
    await DB()
      .prepare(`
        UPDATE users
        SET
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
      VALUES (?, ?, ?, ?, ?, ?, 'admin', 1, ?, ?)
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

/* =========================
   Middleware
========================= */

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const user =
      await currentUser(req);

    if (!user) {
      return res
        .status(401)
        .json({
          message:
            'يجب تسجيل الدخول أولاً.'
        });
    }

    req.user = user;

    return next();

  } catch (error) {

    console.error(
      'Authentication error:',
      error
    );

    return res
      .status(500)
      .json({
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
      return res
        .status(401)
        .json({
          message:
            'يجب تسجيل الدخول أولاً.'
        });
    }

    if (
      user.role !== 'admin'
    ) {
      return res
        .status(403)
        .json({
          message:
            'هذه الصفحة خاصة بالمدرس.'
        });
    }

    req.user = user;

    return next();

  } catch (error) {

    console.error(
      'Admin authentication error:',
      error
    );

    return res
      .status(500)
      .json({
        message:
          'حدث خطأ أثناء التحقق من الصلاحيات.'
      });
  }
}

/* =========================
   Lecture Time
========================= */

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

  let rawDate =
    String(
      settings.scheduled_at
    ).trim();

  let scheduledTime;

  /*
    datetime-local بيبعت الوقت
    من غير timezone.
    
    المنصة بتتعامل مع مواعيد
    المحاضرات بتوقيت مصر UTC+03
    في الفترة الحالية.
  */

  if (
    !rawDate.endsWith('Z') &&
    !/[+-]\d{2}:\d{2}$/.test(
      rawDate
    )
  ) {

    if (
      rawDate.length === 16
    ) {
      rawDate += ':00';
    }

    scheduledTime =
      new Date(
        rawDate +
        '+03:00'
      ).getTime();

  } else {

    scheduledTime =
      new Date(
        rawDate
      ).getTime();
  }

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

  /*
    الرابط يظهر قبل المحاضرة
    بـ5 دقائق.
  */

  const showAt =
    scheduledTime -
    5 * 60 * 1000;

  const visible =
    Date.now() >= showAt;

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

/* =========================
   Grades Table
========================= */

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
   Health
========================= */

app.get(
  '/api/health',
  (req, res) => {
    return res
      .status(200)
      .json({
        ok: true,
        platform:
          'cloudflare-workers',
        message:
          'Worker is running'
      });
  }
);

/* =========================
   Current User
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

/* =========================
   Register
========================= */

app.post(
  '/api/register',
  async (req, res) => {

    try {

      const {
        fullName,
        login,
        username,
        phoneOrDiscord,
        phone,
        identifier,
        grade,
        subject,
        mode,
        password,
        confirmPassword,
        passwordConfirm
      } =
        req.body || {};

      const name =
        String(
          fullName || ''
        ).trim();

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

      const nameParts =
        name
          .split(/\s+/)
          .filter(Boolean);

      if (
        nameParts.length !== 3
      ) {
        return res
          .status(400)
          .json({
            message:
              'اكتب اسمك ثلاثي.'
          });
      }

      if (
        !userLogin ||
        !grade ||
        !subject ||
        !mode
      ) {
        return res
          .status(400)
          .json({
            message:
              'أكمل كل البيانات.'
          });
      }

      if (
        passwordText.length < 6
      ) {
        return res
          .status(400)
          .json({
            message:
              'الباسورد يجب أن يكون 6 أحرف أو أرقام على الأقل.'
          });
      }

      if (
        passwordText !==
        confirmation
      ) {
        return res
          .status(400)
          .json({
            message:
              'تأكيد الباسورد غير مطابق.'
          });
      }

      if (
        userLogin ===
          DEFAULT_ADMIN_LOGIN ||
        userLogin ===
          configuredAdminLogin()
      ) {
        return res
          .status(409)
          .json({
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
        return res
          .status(409)
          .json({
            message:
              'هذا الرقم أو اليوزر مستخدم بالفعل.'
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

      return res
        .status(201)
        .json({
          message:
            'تم إنشاء الحساب بنجاح.'
        });

    } catch (error) {

      console.error(
        'Register error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء إنشاء الحساب.'
        });
    }
  }
);

/* =========================
   Login
========================= */

app.post(
  '/api/login',
  async (req, res) => {

    try {

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
          return res
            .status(500)
            .json({
              message:
                'تعذر تجهيز حساب المدرس.'
            });
        }

        setSessionCookie(
          res,
          await makeSession(
            admin.id
          )
        );

        return res.json({
          message:
            'تم تسجيل دخول المدرس.',
          user:
            safeUser(admin)
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
        return res
          .status(401)
          .json({
            message:
              'بيانات الدخول غير صحيحة.'
          });
      }

      const passwordMatches =
        await bcrypt.compare(
          password,
          String(
            user.password_hash ||
            ''
          )
        );

      if (!passwordMatches) {
        return res
          .status(401)
          .json({
            message:
              'بيانات الدخول غير صحيحة.'
          });
      }

      setSessionCookie(
        res,
        await makeSession(
          user.id
        )
      );

      return res.json({
        message:
          'تم تسجيل الدخول.',
        user:
          safeUser(user)
      });

    } catch (error) {

      console.error(
        'Login error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تسجيل الدخول.'
        });
    }
  }
);

/* =========================
   Logout
========================= */

app.post(
  '/api/logout',
  (req, res) => {

    setSessionCookie(
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
   Student Dashboard
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
        return res
          .status(403)
          .json({
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
              ? settings?.lecture_url ||
                ''
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

      console.error(
        'Student dashboard error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تحميل بيانات الطالب.'
        });
    }
  }
);

/* =========================
   Student Checkin
========================= */

app.post(
  '/api/student/checkin',
  requireAuth,
  async (req, res) => {

    try {

      if (
        req.user.role !==
        'student'
      ) {
        return res
          .status(400)
          .json({
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
        return res
          .status(400)
          .json({
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

      return res.json({
        message:
          'تم تسجيل حضورك.'
      });

    } catch (error) {

      console.error(
        'Check-in error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تسجيل الحضور.'
        });
    }
  }
);

/* =========================
   Admin Users
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
          (
            result.results ||
            []
          ).map(
            safeUser
          )
      });

    } catch (error) {

      console.error(
        'Admin users error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تحميل الطلاب.'
        });
    }
  }
);

/* =========================
   Edit Student
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
        return res
          .status(404)
          .json({
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

      const active =
        Number(
          req.body?.active ??
          student.active
        ) === 1
          ? 1
          : 0;

      if (
        !fullName ||
        !login ||
        !grade ||
        !subject ||
        !mode
      ) {
        return res
          .status(400)
          .json({
            message:
              'أكمل بيانات الطالب.'
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
        return res
          .status(409)
          .json({
            message:
              'رقم التلفون أو يوزر ديسكورد مستخدم بالفعل.'
          });
      }

      let passwordHash =
        student.password_hash;

      if (
        typeof req.body?.password ===
          'string' &&
        req.body.password.trim()
          .length > 0
      ) {

        const newPassword =
          req.body.password.trim();

        if (
          newPassword.length < 6
        ) {
          return res
            .status(400)
            .json({
              message:
                'الباسورد يجب أن يكون 6 أحرف أو أرقام على الأقل.'
            });
        }

        passwordHash =
          await bcrypt.hash(
            newPassword,
            12
          );
      }

      await DB()
        .prepare(`
          UPDATE users
          SET
            full_name = ?,
            login = ?,
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
          safeUser(updated)
      });

    } catch (error) {

      console.error(
        'Update student error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تعديل بيانات الطالب.'
        });
    }
  }
);

/* =========================
   Delete Student
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
        return res
          .status(404)
          .json({
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

      console.error(
        'Delete student error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء حذف الطالب.'
        });
    }
  }
);

/* =========================
   Student Grades
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
        return res
          .status(403)
          .json({
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

      console.error(
        'Student grades error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تحميل الدرجات.'
        });
    }
  }
);

/* =========================
   Admin Grades
========================= */

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
        return res
          .status(400)
          .json({
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
        return res
          .status(404)
          .json({
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

      console.error(
        'Admin grades error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تحميل درجات الطالب.'
        });
    }
  }
);

/* =========================
   Add Grade
========================= */

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
        return res
          .status(400)
          .json({
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
        return res
          .status(400)
          .json({
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
        return res
          .status(404)
          .json({
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
          VALUES (?, ?, ?, ?, ?, ?, ?)
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

      return res
        .status(201)
        .json({
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

      console.error(
        'Add grade error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء إضافة الدرجة.'
        });
    }
  }
);

/* =========================
   Delete Grade
========================= */

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
        return res
          .status(404)
          .json({
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

      console.error(
        'Delete grade error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء حذف الدرجة.'
        });
    }
  }
);

/* =========================
   Admin Attendance
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

      const statusMap =
        new Map(
          (
            attendance.results ||
            []
          ).map(
            row => [
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
          user => ({
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
              statusMap.get(
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

      console.error(
        'Attendance error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تحميل الحضور.'
        });
    }
  }
);

/* =========================
   Set Attendance
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
      } =
        req.body || {};

      if (
        !userId ||
        !date ||
        ![
          'حاضر',
          'غائب',
          'غير محدد'
        ].includes(status)
      ) {
        return res
          .status(400)
          .json({
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
        return res
          .status(404)
          .json({
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

      return res.json({
        message:
          'تم تحديث الحضور.'
      });

    } catch (error) {

      console.error(
        'Set attendance error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تحديث الحضور.'
        });
    }
  }
);

/* =========================
   Lecture Settings
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
          settings ||
          {
            lecture_title:
              'المحاضرة القادمة',

            lecture_url:
              '',

            scheduled_at:
              ''
          }
      });

    } catch (error) {

      console.error(
        'Settings error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء تحميل إعدادات المحاضرة.'
        });
    }
  }
);

/* =========================
   Save Lecture
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
          req.body?.lectureUrl ||
          ''
        ).trim();

      const scheduledAt =
        String(
          req.body?.scheduledAt ||
          ''
        ).trim();

      if (
        !validUrl(
          lectureUrl
        )
      ) {
        return res
          .status(400)
          .json({
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
        return res
          .status(400)
          .json({
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

      return res.json({
        message:
          'تم تحديث المحاضرة والرابط.'
      });

    } catch (error) {

      console.error(
        'Save settings error:',
        error
      );

      return res
        .status(500)
        .json({
          message:
            'حدث خطأ أثناء حفظ المحاضرة.'
        });
    }
  }
);

/* =========================
   Clear Lecture
========================= */

app.delete(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {

    try {

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

      return res.json({
        message:
          'تم مسح المحاضرة الحالية.'
      });

    } catch (error) {

      console.error(
        'Clear settings error:',
        error
      );

      return res
        .status(500)
        .json({
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

    return res
      .status(404)
      .json({
        message:
          'المسار غير موجود.'
      });
  }
);

/* =========================
   Global Error
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

    return res
      .status(500)
      .json({
        message:
          'حدث خطأ داخلي في السيرفر.',
        error:
          error?.message ||
          'Unknown error'
      });
  }
);

/* =========================
   Cloudflare Worker
========================= */

app.listen(3000);

export default httpServerHandler({
  port: 3000
});
