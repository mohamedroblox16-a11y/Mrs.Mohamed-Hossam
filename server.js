import express from 'express';
import bcrypt from 'bcryptjs';
import { httpServerHandler } from 'cloudflare:node';
import { env } from 'cloudflare:workers';

const app = express();

/* =========================
   Express
========================= */

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

/* =========================
   Helpers
========================= */

const DB = () => env.DB;

const nowIso = () => new Date().toISOString();

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

const safeUser = (user) => {
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
};

/* =========================
   Admin credentials
========================= */

const DEFAULT_ADMIN_LOGIN = 'admin';
const DEFAULT_ADMIN_PASSWORD = '123456';

function getAdminLogin() {
  const configured = normalizeLogin(
    env.ADMIN_LOGIN
  );

  return configured || DEFAULT_ADMIN_LOGIN;
}

function getAdminPassword() {
  const configured = String(
    env.ADMIN_PASSWORD || ''
  );

  return configured || DEFAULT_ADMIN_PASSWORD;
}

function isAdminLogin(login, password) {
  const normalizedLogin =
    normalizeLogin(login);

  const normalizedPassword =
    String(password ?? '');

  const adminLogin = getAdminLogin();
  const adminPassword =
    getAdminPassword();

  const defaultCredentials =
    normalizedLogin ===
      DEFAULT_ADMIN_LOGIN &&
    normalizedPassword ===
      DEFAULT_ADMIN_PASSWORD;

  const configuredCredentials =
    normalizedLogin ===
      adminLogin &&
    normalizedPassword ===
      adminPassword;

  return (
    defaultCredentials ||
    configuredCredentials
  );
}

/* =========================
   Health
========================= */

app.get(
  '/api/health',
  (req, res) => {
    return res.status(200).json({
      ok: true,
      platform: 'cloudflare-workers',
      message: 'Worker is running'
    });
  }
);

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
  return `${userId}.${await sign(userId)}`;
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

  if (parts.length !== 2) {
    return null;
  }

  const [
    id,
    signature
  ] = parts;

  if (!id || !signature) {
    return null;
  }

  const expected =
    await sign(id);

  if (signature !== expected) {
    return null;
  }

  return id;
}

/* =========================
   Cookie
   يدعم Express وWeb Headers
========================= */

function getCookie(request, name) {
  const headers =
    request?.headers;

  let raw = '';

  try {
    if (
      headers &&
      typeof headers.get ===
        'function'
    ) {
      raw =
        headers.get('cookie') ||
        headers.get('Cookie') ||
        '';
    } else {
      raw =
        headers?.cookie ||
        headers?.Cookie ||
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
    ] =
      part.trim().split('=');

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

/* =========================
   Current user
========================= */

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
      .prepare(`
        SELECT *
        FROM users
        WHERE id = ?
        LIMIT 1
      `)
      .bind(sessionId)
      .first();

  if (
    user &&
    user.active
  ) {
    return user;
  }

  return null;
}

/* =========================
   Ensure Admin
========================= */

async function ensureAdmin() {
  const login =
    getAdminLogin();

  const password =
    getAdminPassword();

  if (!login || !password) {
    throw new Error(
      'بيانات حساب المدرس غير موجودة.'
    );
  }

  let admin =
    await DB()
      .prepare(`
        SELECT *
        FROM users
        WHERE login = ?
        LIMIT 1
      `)
      .bind(login)
      .first();

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  /* =========================
     الأدمن موجود
  ========================= */

  if (admin) {
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
        admin.id
      )
      .run();

    admin =
      await DB()
        .prepare(`
          SELECT *
          FROM users
          WHERE id = ?
          LIMIT 1
        `)
        .bind(admin.id)
        .first();

    return admin;
  }

  /* =========================
     الأدمن غير موجود
  ========================= */

  const adminId =
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
      adminId,
      'مستر محمد حسام',
      login,
      'مدرس',
      'كل المواد',
      'إدارة المنصة',
      nowIso(),
      passwordHash
    )
    .run();

  return (
    await DB()
      .prepare(`
        SELECT *
        FROM users
        WHERE id = ?
        LIMIT 1
      `)
      .bind(adminId)
      .first()
  );
}

let adminInitPromise =
  null;

async function ensureAdminOnce() {
  if (!adminInitPromise) {
    adminInitPromise =
      ensureAdmin().catch(
        (error) => {
          adminInitPromise = null;
          throw error;
        }
      );
  }

  return adminInitPromise;
}

/* =========================
   API Initialization
========================= */

app.use(
  async (
    req,
    res,
    next
  ) => {
    if (
      !req.path.startsWith(
        '/api/'
      )
    ) {
      return next();
    }

    if (
      req.path ===
      '/api/health'
    ) {
      return next();
    }

    try {
      await ensureAdminOnce();

      return next();
    } catch (error) {
      console.error(
        'Admin initialization error:',
        error
      );

      return res.status(500).json({
        message:
          'تعذر تجهيز حساب المدرس.',
        error:
          error?.message ||
          'Unknown error'
      });
    }
  }
);

/* =========================
   Auth Middleware
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
      return res.status(401).json({
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
      user.role !==
      'admin'
    ) {
      return res.status(403).json({
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

    return res.status(500).json({
      message:
        'حدث خطأ أثناء التحقق من الصلاحيات.'
    });
  }
}

/* =========================
   Lecture State
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
    Date.now() >= showAt;

  return {
    visible,
    reason: visible
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
   /api/me
========================= */

app.get(
  '/api/me',
  requireAuth,
  (
    req,
    res
  ) => {
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
  async (
    req,
    res
  ) => {
    try {
      const body =
        req.body || {};

      const fullName =
        body.fullName;

      const login =
        body.login ??
        body.username ??
        body.phoneOrDiscord ??
        body.phone ??
        body.identifier ??
        '';

      const grade =
        body.grade;

      const subject =
        body.subject;

      const mode =
        body.mode;

      const password =
        String(
          body.password ||
          ''
        );

      const confirmPassword =
        String(
          body.confirmPassword ??
          body.passwordConfirm ??
          password
        );

      const name =
        String(
          fullName || ''
        ).trim();

      const userLogin =
        normalizeLogin(
          login
        );

      const nameParts =
        name
          .split(/\s+/)
          .filter(Boolean);

      if (
        nameParts.length !==
        3
      ) {
        return res.status(400).json({
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
        return res.status(400).json({
          message:
            'أكمل كل البيانات.'
        });
      }

      if (
        password.length <
        6
      ) {
        return res.status(400).json({
          message:
            'الباسورد يجب أن يكون 6 أحرف أو أرقام على الأقل.'
        });
      }

      if (
        password !==
        confirmPassword
      ) {
        return res.status(400).json({
          message:
            'تأكيد الباسورد غير مطابق.'
        });
      }

      const adminLogin =
        getAdminLogin();

      if (
        userLogin ===
          DEFAULT_ADMIN_LOGIN ||
        userLogin ===
          adminLogin
      ) {
        return res.status(409).json({
          message:
            'اسم الدخول ده محجوز للمدرس.'
        });
      }

      const existing =
        await DB()
          .prepare(`
            SELECT id
            FROM users
            WHERE login = ?
            LIMIT 1
          `)
          .bind(userLogin)
          .first();

      if (existing) {
        return res.status(409).json({
          message:
            'هذا الرقم أو اليوزر مستخدم بالفعل.'
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
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
          VALUES (
            ?,
            ?,
            ?,
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
      console.error(
        'Register error:',
        error
      );

      return res.status(500).json({
        message:
          'حدث خطأ أثناء إنشاء الحساب.',
        error:
          error?.message ||
          'Unknown error'
      });
    }
  }
);

/* =========================
   Login
========================= */

app.post(
  '/api/login',
  async (
    req,
    res
  ) => {
    try {
      const body =
        req.body || {};

      const login =
        normalizeLogin(
          body.login ??
          body.username ??
          body.phoneOrDiscord ??
          body.phone ??
          body.identifier ??
          body.userLogin ??
          ''
        );

      const password =
        String(
          body.password ??
          body.pass ??
          ''
        );

      /* =========================
         Admin Login
      ========================= */

      if (
        isAdminLogin(
          login,
          password
        )
      ) {
        const admin =
          await ensureAdmin();

        if (!admin) {
          return res.status(500).json({
            message:
              'تعذر تجهيز حساب المدرس.'
          });
        }

        const sessionValue =
          await makeSession(
            admin.id
          );

        res.setHeader(
          'Set-Cookie',
          `session=${encodeURIComponent(
            sessionValue
          )}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
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

      /* =========================
         Student Login
      ========================= */

      const user =
        await DB()
          .prepare(`
            SELECT *
            FROM users
            WHERE login = ?
            LIMIT 1
          `)
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

      const passwordMatches =
        await bcrypt.compare(
          password,
          String(
            user.password_hash ||
            ''
          )
        );

      if (
        !passwordMatches
      ) {
        return res.status(401).json({
          message:
            'بيانات الدخول غير صحيحة.'
        });
      }

      const sessionValue =
        await makeSession(
          user.id
        );

      res.setHeader(
        'Set-Cookie',
        `session=${encodeURIComponent(
          sessionValue
        )}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
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
      console.error(
        'Login error:',
        error
      );

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تسجيل الدخول.',
        error:
          error?.message ||
          'Unknown error'
      });
    }
  }
);

/* =========================
   Logout
========================= */

app.post(
  '/api/logout',
  (
    req,
    res
  ) => {
    res.setHeader(
      'Set-Cookie',
      'session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
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
  async (
    req,
    res
  ) => {
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
          .prepare(`
            SELECT *
            FROM settings
            WHERE id = 1
            LIMIT 1
          `)
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
              ? (
                  settings?.lecture_url ||
                  ''
                )
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

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل بيانات الطالب.'
      });
    }
  }
);

/* =========================
   Student Check-in
========================= */

app.post(
  '/api/student/checkin',
  requireAuth,
  async (
    req,
    res
  ) => {
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
          .prepare(`
            SELECT *
            FROM settings
            WHERE id = 1
            LIMIT 1
          `)
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
      console.error(
        'Check-in error:',
        error
      );

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تسجيل الحضور.'
      });
    }
  }
);

/* =========================
   Admin - Users
========================= */

app.get(
  '/api/admin/users',
  requireAdmin,
  async (
    req,
    res
  ) => {
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

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحميل الطلاب.'
      });
    }
  }
);

/* =========================
   Update Student
========================= */

app.patch(
  '/api/admin/users/:id',
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const user =
        await DB()
          .prepare(`
            SELECT id
            FROM users
            WHERE id = ?
            AND role = 'student'
            LIMIT 1
          `)
          .bind(
            req.params.id
          )
          .first();

      if (!user) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      if (
        typeof req.body?.active ===
        'boolean'
      ) {
        await DB()
          .prepare(`
            UPDATE users
            SET active = ?
            WHERE id = ?
          `)
          .bind(
            req.body.active
              ? 1
              : 0,
            req.params.id
          )
          .run();
      }

      if (
        typeof req.body?.password ===
          'string' &&
        req.body.password.length >=
          6
      ) {
        const passwordHash =
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
            passwordHash,
            req.params.id
          )
          .run();
      }

      return res.json({
        message:
          'تم تحديث الحساب.'
      });
    } catch (error) {
      console.error(
        'Update user error:',
        error
      );

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحديث الحساب.'
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
  async (
    req,
    res
  ) => {
    try {
      const user =
        await DB()
          .prepare(`
            SELECT id
            FROM users
            WHERE id = ?
            AND role = 'student'
            LIMIT 1
          `)
          .bind(
            req.params.id
          )
          .first();

      if (!user) {
        return res.status(404).json({
          message:
            'الطالب غير موجود.'
        });
      }

      await DB()
        .prepare(`
          DELETE FROM attendance
          WHERE user_id = ?
        `)
        .bind(
          req.params.id
        )
        .run();

      await DB()
        .prepare(`
          DELETE FROM users
          WHERE id = ?
          AND role = 'student'
        `)
        .bind(
          req.params.id
        )
        .run();

      return res.json({
        message:
          'تم حذف الطالب.'
      });
    } catch (error) {
      console.error(
        'Delete user error:',
        error
      );

      return res.status(500).json({
        message:
          'حدث خطأ أثناء حذف الطالب.'
      });
    }
  }
);

/* =========================
   Admin - Attendance
========================= */

app.get(
  '/api/admin/attendance',
  requireAdmin,
  async (
    req,
    res
  ) => {
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
            userId: user.id,
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

      return res.status(500).json({
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
  async (
    req,
    res
  ) => {
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
      console.error(
        'Set attendance error:',
        error
      );

      return res.status(500).json({
        message:
          'حدث خطأ أثناء تحديث الحضور.'
      });
    }
  }
);

/* =========================
   Admin - Settings
========================= */

app.get(
  '/api/admin/settings',
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const settings =
        await DB()
          .prepare(`
            SELECT *
            FROM settings
            WHERE id = 1
            LIMIT 1
          `)
          .first();

      return res.json({
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

      return res.status(500).json({
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
  async (
    req,
    res
  ) => {
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

      return res.json({
        message:
          'تم تحديث المحاضرة والرابط.'
      });
    } catch (error) {
      console.error(
        'Save settings error:',
        error
      );

      return res.status(500).json({
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
  async (
    req,
    res
  ) => {
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
            lecture_url = '',
            scheduled_at = '',
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
  (
    req,
    res
  ) => {
    return res.status(404).json({
      message:
        'المسار غير موجود.'
    });
  }
);

/* =========================
   Global Error Handler
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

/* =========================
   Cloudflare Worker
========================= */

app.listen(3000);

export default httpServerHandler({
  port: 3000
});
