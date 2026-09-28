const $ = (id) => document.getElementById(id);

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(data.message || 'حدث خطأ غير متوقع.');
  }

  return data;
}

function showMessage(element, message, success = false) {
  if (!element) return;
  element.textContent = message || '';
  element.classList.toggle('success', success);
}

function formatDate(value) {
  if (!value) return 'غير محدد';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('ar-EG', {
    dateStyle: 'medium',
    timeStyle: 'short'
  });
}

function localDateValue(date = new Date()) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

/* =========================
   Login / Register page
========================= */

const loginForm = $('loginForm');
const registerForm = $('registerForm');
const toggleAuth = $('toggleAuth');

if (loginForm && registerForm) {
  let registerMode = false;

  function updateAuthMode() {
    registerMode = !registerMode;
    loginForm.classList.toggle('hidden', registerMode);
    registerForm.classList.toggle('hidden', !registerMode);
    $('authTitle').textContent = registerMode ? 'إنشاء حساب' : 'تسجيل الدخول';
    $('authSubtitle').textContent = registerMode
      ? 'أنشئ حسابك وابدأ استخدام المنصة.'
      : 'ادخل بياناتك للوصول إلى المنصة.';
    toggleAuth.textContent = registerMode
      ? 'العودة لتسجيل الدخول'
      : 'إنشاء حساب جديد';
  }

  toggleAuth.addEventListener('click', updateAuthMode);

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    showMessage($('loginMessage'), 'جاري تسجيل الدخول...', false);

    try {
      const data = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({
          login: $('login').value.trim(),
          password: $('password').value
        })
      });

      showMessage($('loginMessage'), data.message || 'تم تسجيل الدخول.', true);
      setTimeout(() => {
        window.location.href = '/dashboard.html';
      }, 250);
    } catch (error) {
      showMessage($('loginMessage'), error.message);
    }
  });

  registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    showMessage($('registerMessage'), 'جاري إنشاء الحساب...', false);

    try {
      const data = await api('/api/register', {
        method: 'POST',
        body: JSON.stringify({
          fullName: $('fullName').value.trim(),
          login: $('registerLogin').value.trim(),
          grade: $('grade').value,
          subject: $('subject').value,
          mode: $('mode').value,
          password: $('registerPassword').value,
          confirmPassword: $('confirmPassword').value
        })
      });

      showMessage($('registerMessage'), data.message || 'تم إنشاء الحساب.', true);
      registerForm.reset();
      setTimeout(() => updateAuthMode(), 700);
    } catch (error) {
      showMessage($('registerMessage'), error.message);
    }
  });
}

/* =========================
   Dashboard
========================= */

const studentView = $('studentView');
const adminView = $('adminView');

if (studentView || adminView) {
  let currentUser = null;
  let usersCache = [];

  async function loadMe() {
    try {
      const data = await api('/api/me');
      currentUser = data.user;

      $('userName').textContent = currentUser.fullName;
      $('dashboardRole').textContent = currentUser.role === 'admin'
        ? 'لوحة المدرس'
        : 'لوحة الطالب';

      if (currentUser.role === 'admin') {
        adminView.classList.remove('hidden');
        await loadAdmin();
      } else {
        studentView.classList.remove('hidden');
        await loadStudent();
      }
    } catch (error) {
      window.location.href = '/';
    }
  }

  async function loadStudent() {
    const data = await api('/api/student/dashboard');
    const user = data.user;
    const lecture = data.lecture;

    $('studentName').textContent = user.fullName;
    $('studentGrade').textContent = user.grade;
    $('studentSubject').textContent = user.subject;
    $('studentMode').textContent = user.mode;

    $('profileName').textContent = user.fullName;
    $('profileLogin').textContent = user.login;
    $('profileGrade').textContent = user.grade;
    $('profileSubject').textContent = user.subject;

    $('lectureTitle').textContent = lecture.title || 'المحاضرة القادمة';
    $('lectureTime').textContent = lecture.scheduledAt
      ? formatDate(lecture.scheduledAt)
      : 'لم يتم تحديد موعد بعد.';

    const available = Boolean(lecture.url && lecture.state?.visible);
    const badge = $('lectureBadge');
    const link = $('lectureLink');
    const checkin = $('checkinBtn');

    if (available) {
      badge.textContent = 'متاحة الآن';
      badge.className = 'status-badge live';
      link.href = lecture.url;
      link.classList.remove('disabled-link');
      $('lectureNote').textContent = 'المحاضرة متاحة، اضغط للدخول وتابع تسجيل حضورك.';
      checkin.disabled = false;
    } else {
      badge.textContent = 'غير متاحة';
      badge.className = 'status-badge neutral';
      link.href = '#';
      link.classList.add('disabled-link');
      $('lectureNote').textContent = lecture.scheduledAt
        ? 'رابط المحاضرة سيظهر قبل الموعد بخمس دقائق.'
        : 'انتظر تحديث موعد ورابط المحاضرة من المدرس.';
      checkin.disabled = true;
    }

    const body = $('studentAttendanceBody');
    const rows = data.attendance || [];

    body.innerHTML = rows.length
      ? rows.map((row) => `
          <tr>
            <td>${escapeHtml(row.date)}</td>
            <td><span class="status-badge ${row.status === 'حاضر' ? 'live' : 'neutral'}">${escapeHtml(row.status)}</span></td>
            <td>${escapeHtml(row.method)}</td>
          </tr>
        `).join('')
      : '<tr><td colspan="3">لا يوجد سجل حضور حتى الآن.</td></tr>';
  }

  async function loadAdmin() {
    await Promise.all([
      loadAdminUsers(),
      loadAdminSettings(),
      loadAdminAttendance()
    ]);
  }

  async function loadAdminUsers() {
    const data = await api('/api/admin/users');
    usersCache = data.users || [];
    $('totalStudents').textContent = usersCache.length;
    renderUsers();
  }

  function renderUsers() {
    const body = $('usersBody');

    body.innerHTML = usersCache.length
      ? usersCache.map((user) => `
          <tr>
            <td>${escapeHtml(user.fullName)}</td>
            <td>${escapeHtml(user.login)}</td>
            <td>${escapeHtml(user.grade)}</td>
            <td>${escapeHtml(user.subject)}</td>
            <td>${escapeHtml(user.mode)}</td>
            <td><span class="status-badge ${user.active ? 'live' : 'neutral'}">${user.active ? 'نشط' : 'موقوف'}</span></td>
            <td>
              <button class="table-action" data-toggle-user="${escapeHtml(user.id)}">${user.active ? 'إيقاف' : 'تفعيل'}</button>
              <button class="table-action danger" data-delete-user="${escapeHtml(user.id)}">حذف</button>
            </td>
          </tr>
        `).join('')
      : '<tr><td colspan="7">لا يوجد طلاب حتى الآن.</td></tr>';
  }

  async function toggleUser(id) {
    const user = usersCache.find((item) => item.id === id);
    if (!user) return;

    await api(`/api/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ active: !user.active })
    });

    await loadAdminUsers();
  }

  async function deleteUser(id) {
    const user = usersCache.find((item) => item.id === id);
    if (!user) return;

    const yes = window.confirm(`هل تريد حذف الطالب ${user.fullName}؟`);
    if (!yes) return;

    await api(`/api/admin/users/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });

    await loadAdminUsers();
    await loadAdminAttendance();
  }

  $('usersBody')?.addEventListener('click', async (event) => {
    const toggle = event.target.closest('[data-toggle-user]');
    const remove = event.target.closest('[data-delete-user]');

    try {
      if (toggle) await toggleUser(toggle.dataset.toggleUser);
      if (remove) await deleteUser(remove.dataset.deleteUser);
    } catch (error) {
      showMessage($('pageMessage'), error.message);
    }
  });

  async function loadAdminSettings() {
    const data = await api('/api/admin/settings');
    const settings = data.settings || {};

    $('lectureTitleInput').value = settings.lecture_title || '';
    $('lectureUrlInput').value = settings.lecture_url || '';
    $('scheduledAtInput').value = settings.scheduled_at || '';
  }

  $('settingsForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    showMessage($('settingsMessage'), 'جاري الحفظ...');

    try {
      const data = await api('/api/admin/settings', {
        method: 'PUT',
        body: JSON.stringify({
          lectureTitle: $('lectureTitleInput').value.trim(),
          lectureUrl: $('lectureUrlInput').value.trim(),
          scheduledAt: $('scheduledAtInput').value
        })
      });

      showMessage($('settingsMessage'), data.message, true);
      await loadAdminSettings();
    } catch (error) {
      showMessage($('settingsMessage'), error.message);
    }
  });

  $('clearLectureBtn')?.addEventListener('click', async () => {
    try {
      await api('/api/admin/settings', { method: 'DELETE' });
      showMessage($('settingsMessage'), 'تم مسح المحاضرة الحالية.', true);
      await loadAdminSettings();
    } catch (error) {
      showMessage($('settingsMessage'), error.message);
    }
  });

  const attendanceDate = $('attendanceDate');
  if (attendanceDate) {
    attendanceDate.value = localDateValue();
    attendanceDate.addEventListener('change', loadAdminAttendance);
  }

  $('refreshUsersBtn')?.addEventListener('click', async () => {
    try {
      await loadAdminUsers();
      await loadAdminAttendance();
      showMessage($('pageMessage'), 'تم تحديث البيانات.', true);
    } catch (error) {
      showMessage($('pageMessage'), error.message);
    }
  });

  async function loadAdminAttendance() {
    const date = attendanceDate?.value || localDateValue();
    const data = await api(`/api/admin/attendance?date=${encodeURIComponent(date)}`);
    const rows = data.rows || [];

    const present = rows.filter((row) => row.status === 'حاضر').length;
    const absent = rows.filter((row) => row.status === 'غائب').length;

    $('presentToday').textContent = present;
    $('absentToday').textContent = absent;

    const total = usersCache.length;
    const percent = total ? Math.round((present / total) * 100) : 0;
    $('todayAttendancePercent').textContent = `${percent}%`;
    $('todayProgress').style.width = `${percent}%`;
    $('attendanceDateLabel').textContent = date;

    const body = $('adminAttendanceBody');
    body.innerHTML = rows.length
      ? rows.map((row) => `
          <tr>
            <td>${escapeHtml(row.fullName)}</td>
            <td>${escapeHtml(row.login)}</td>
            <td>
              <select class="table-select" data-status-user="${escapeHtml(row.userId)}">
                <option value="غير محدد" ${row.status === 'غير محدد' ? 'selected' : ''}>غير محدد</option>
                <option value="حاضر" ${row.status === 'حاضر' ? 'selected' : ''}>حاضر</option>
                <option value="غائب" ${row.status === 'غائب' ? 'selected' : ''}>غائب</option>
              </select>
            </td>
            <td><button class="table-action" data-save-attendance="${escapeHtml(row.userId)}">حفظ</button></td>
          </tr>
        `).join('')
      : '<tr><td colspan="4">لا يوجد طلاب.</td></tr>';
  }

  $('adminAttendanceBody')?.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-save-attendance]');
    if (!button) return;

    const userId = button.dataset.saveAttendance;
    const select = document.querySelector(`[data-status-user="${CSS.escape(userId)}"]`);
    if (!select) return;

    try {
      const data = await api('/api/admin/attendance', {
        method: 'POST',
        body: JSON.stringify({
          userId,
          date: attendanceDate.value,
          status: select.value
        })
      });

      showMessage($('pageMessage'), data.message, true);
      await loadAdminAttendance();
    } catch (error) {
      showMessage($('pageMessage'), error.message);
    }
  });

  $('checkinBtn')?.addEventListener('click', async () => {
    showMessage($('studentActionMessage'), 'جاري تسجيل الحضور...');

    try {
      const data = await api('/api/student/checkin', {
        method: 'POST'
      });
      showMessage($('studentActionMessage'), data.message, true);
      await loadStudent();
    } catch (error) {
      showMessage($('studentActionMessage'), error.message);
    }
  });

  $('logoutBtn')?.addEventListener('click', async () => {
    try {
      await api('/api/logout', { method: 'POST' });
    } finally {
      window.location.href = '/';
    }
  });

  loadMe();
}
