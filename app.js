const $ = (id) => document.getElementById(id);
let currentUser = null;
let students = [];

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || "حدث خطأ غير متوقع.");
  return data;
}

function showView(viewId) {
  ["authView", "studentView", "adminView"].forEach(id => {
    $(id).hidden = id !== viewId;
  });
}

function showMessage(id, text, type = "") {
  const el = $(id);
  el.textContent = text || "";
  el.hidden = !text;
  el.className = `message ${type}`;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[c]));
}

function formatDate(value) {
  if (!value) return "";
  try { return new Date(value).toLocaleString("ar-EG", { dateStyle: "medium", timeStyle: "short" }); }
  catch { return value; }
}

function setToday() {
  const d = new Date();
  const off = d.getTimezoneOffset();
  return new Date(d.getTime() - off * 60000).toISOString().slice(0, 10);
}

function renderProfile(user) {
  $("profileBox").innerHTML = `
    <div class="profile-item"><small>الاسم</small><strong>${esc(user.fullName)}</strong></div>
    <div class="profile-item"><small>التواصل</small><strong>${esc(user.login)}</strong></div>
    <div class="profile-item"><small>السنة</small><strong>${esc(user.grade)}</strong></div>
    <div class="profile-item"><small>الدرس</small><strong>${esc(user.subject)}</strong></div>
    <div class="profile-item"><small>نوع الحصة</small><strong>${esc(user.mode)}</strong></div>
    <div class="profile-item"><small>نوع الحساب</small><strong>${user.role === "admin" ? "مدرس" : "طالب"}</strong></div>`;
}

async function loadStudent() {
  const data = await api("/api/student/dashboard");
  currentUser = data.user;
  $("studentWelcome").textContent = `أهلاً ${data.user.fullName}`;
  $("studentMeta").textContent = `${data.user.grade} • ${data.user.subject} • ${data.user.mode}`;
  renderProfile(data.user);

  const lecture = data.lecture || {};
  const state = lecture.state || {};
  $("lectureTitle").textContent = lecture.title || "المحاضرة القادمة";
  $("lectureTime").textContent = lecture.scheduledAt ? `الموعد: ${formatDate(lecture.scheduledAt)}` : "لم يتم تحديد موعد بعد.";
  $("lectureBadge").textContent = lecture.url ? "متاح" : (state.reason === "not-yet" ? "قريباً" : "غير متاح");
  $("lectureBadge").classList.toggle("live", !!lecture.url);
  $("lectureWaiting").hidden = !!lecture.url;
  $("lectureLink").hidden = !lecture.url;
  if (lecture.url) $("lectureLink").href = lecture.url;
  $("checkinButton").hidden = !(state.visible && lecture.url);

  const rows = data.attendance || [];
  $("studentAttendance").innerHTML = rows.length
    ? rows.map(r => `<tr><td>${esc(r.date)}</td><td>${esc(r.status)}</td><td>${r.method === "admin" ? "المدرس" : "الطالب"}</td></tr>`).join("")
    : `<tr><td colspan="3">لا يوجد سجل حضور حتى الآن.</td></tr>`;
}

async function loadAdmin() {
  const users = await api("/api/admin/users");
  students = users.users || [];
  $("statStudents").textContent = students.length;
  renderStudents();

  const setting = await api("/api/admin/settings");
  const s = setting.settings || {};
  $("adminLectureTitle").value = s.lecture_title || "المحاضرة القادمة";
  $("adminLectureUrl").value = s.lecture_url || "";
  $("adminScheduledAt").value = s.scheduled_at ? new Date(s.scheduled_at).toISOString().slice(0,16) : "";

  if (!$("attendanceDate").value) $("attendanceDate").value = setToday();
  await loadAttendance();
}

function renderStudents() {
  $("studentsTable").innerHTML = students.length ? students.map(u => `
    <tr>
      <td>${esc(u.fullName)}</td>
      <td>${esc(u.login)}</td>
      <td>${esc(u.grade)}</td>
      <td>${esc(u.subject)}</td>
      <td>${esc(u.mode)}</td>
      <td class="${u.active ? "status-active" : "status-inactive"}">${u.active ? "مفعل" : "متوقف"}</td>
      <td>
        <button class="action-btn ${u.active ? "danger" : "success"}" data-toggle="${esc(u.id)}">${u.active ? "إيقاف" : "تفعيل"}</button>
        <button class="action-btn danger" data-delete="${esc(u.id)}">حذف</button>
      </td>
    </tr>`).join("") : `<tr><td colspan="7">لا يوجد طلاب حتى الآن.</td></tr>`;

  $("studentsTable").querySelectorAll("[data-toggle]").forEach(btn => btn.onclick = async () => {
    const user = students.find(u => u.id === btn.dataset.toggle);
    if (!user) return;
    try {
      await api(`/api/admin/users/${user.id}`, { method:"PATCH", body: JSON.stringify({active: !user.active}) });
      await loadAdmin();
    } catch (e) { alert(e.message); }
  });

  $("studentsTable").querySelectorAll("[data-delete]").forEach(btn => btn.onclick = async () => {
    const user = students.find(u => u.id === btn.dataset.delete);
    if (!user || !confirm(`حذف حساب ${user.fullName}؟`)) return;
    try {
      await api(`/api/admin/users/${user.id}`, { method:"DELETE" });
      await loadAdmin();
    } catch (e) { alert(e.message); }
  });
}

async function loadAttendance() {
  const date = $("attendanceDate").value || setToday();
  const data = await api(`/api/admin/attendance?date=${encodeURIComponent(date)}`);
  const rows = data.rows || [];
  $("statPresent").textContent = rows.filter(r => r.status === "حاضر").length;
  $("statAbsent").textContent = rows.filter(r => r.status === "غائب").length;

  $("attendanceTable").innerHTML = rows.length ? rows.map(r => `
    <tr>
      <td>${esc(r.fullName)}</td>
      <td>${esc(r.grade)}</td>
      <td>${esc(r.subject)}</td>
      <td class="${r.status === "حاضر" ? "status-present" : r.status === "غائب" ? "status-absent" : ""}">${esc(r.status)}</td>
      <td>
        <select class="attendance-select" data-user="${esc(r.userId)}">
          <option ${r.status === "غير محدد" ? "selected" : ""}>غير محدد</option>
          <option ${r.status === "حاضر" ? "selected" : ""}>حاضر</option>
          <option ${r.status === "غائب" ? "selected" : ""}>غائب</option>
        </select>
      </td>
    </tr>`).join("") : `<tr><td colspan="5">لا يوجد طلاب.</td></tr>`;

  $("attendanceTable").querySelectorAll("[data-user]").forEach(sel => sel.onchange = async () => {
    try {
      await api("/api/admin/attendance", {
        method:"POST",
        body:JSON.stringify({userId:sel.dataset.user,date,status:sel.value})
      });
      await loadAttendance();
    } catch(e) { alert(e.message); }
  });
}

async function logout() {
  try { await api("/api/logout", {method:"POST"}); }
  finally { currentUser = null; showView("authView"); }
}

$("showRegister").onclick = () => {
  $("loginPanel").hidden = true;
  $("registerPanel").hidden = false;
  showMessage("authMessage", "");
};
$("showLogin").onclick = () => {
  $("registerPanel").hidden = true;
  $("loginPanel").hidden = false;
  showMessage("authMessage", "");
};

$("loginForm").onsubmit = async e => {
  e.preventDefault();
  try {
    const data = await api("/api/login", {method:"POST", body:JSON.stringify({login:$("loginInput").value.trim(),password:$("loginPassword").value})});
    currentUser = data.user;
    if (currentUser.role === "admin") { showView("adminView"); await loadAdmin(); }
    else { showView("studentView"); await loadStudent(); }
  } catch(e) { showMessage("authMessage", e.message, "error"); }
};

$("registerForm").onsubmit = async e => {
  e.preventDefault();
  if ($("registerPassword").value !== $("confirmPassword").value) {
    showMessage("authMessage", "الباسورد وتأكيد الباسورد مش متطابقين.", "error");
    return;
  }
  try {
    await api("/api/register", {method:"POST", body:JSON.stringify({
      fullName:$("fullName").value.trim(),
      login:$("registerLogin").value.trim(),
      grade:$("grade").value,
      subject:$("subject").value,
      mode:$("mode").value,
      password:$("registerPassword").value
    })});
    $("registerForm").reset();
    $("registerPanel").hidden = true;
    $("loginPanel").hidden = false;
    showMessage("authMessage", "تم إنشاء الحساب بنجاح. سجّل الدخول الآن.", "success");
  } catch(e) { showMessage("authMessage", e.message, "error"); }
};

$("studentLogout").onclick = logout;
$("adminLogout").onclick = logout;
$("checkinButton").onclick = async () => {
  try {
    const d = await api("/api/student/checkin", {method:"POST"});
    showMessage("studentMessage", d.message, "success");
    await loadStudent();
  } catch(e) { showMessage("studentMessage", e.message, "error"); }
};

$("lectureForm").onsubmit = async e => {
  e.preventDefault();
  try {
    await api("/api/admin/settings", {method:"PUT", body:JSON.stringify({
      lectureTitle:$("adminLectureTitle").value.trim(),
      lectureUrl:$("adminLectureUrl").value.trim(),
      scheduledAt:$("adminScheduledAt").value
    })});
    showMessage("adminLectureMessage", "تم حفظ المحاضرة والموعد.", "success");
  } catch(e) { showMessage("adminLectureMessage", e.message, "error"); }
};

$("clearLecture").onclick = async () => {
  try {
    const d = await api("/api/admin/settings", {method:"DELETE"});
    showMessage("adminLectureMessage", d.message, "success");
    await loadAdmin();
  } catch(e) { showMessage("adminLectureMessage", e.message, "error"); }
};

$("refreshStudents").onclick = () => loadAdmin().catch(e => alert(e.message));
$("attendanceDate").onchange = () => loadAttendance().catch(e => alert(e.message));

(async function boot(){
  try {
    const data = await api("/api/me");
    currentUser = data.user;
    if (currentUser.role === "admin") { showView("adminView"); await loadAdmin(); }
    else { showView("studentView"); await loadStudent(); }
  } catch { showView("authView"); }
})();
