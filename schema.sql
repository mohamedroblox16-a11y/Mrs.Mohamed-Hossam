CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  login TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL DEFAULT '',
  grade TEXT NOT NULL,
  subject TEXT NOT NULL,
  mode TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attendance (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  date TEXT NOT NULL,
  status TEXT NOT NULL,
  method TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(user_id, date)
);

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  lecture_title TEXT NOT NULL DEFAULT 'المحاضرة القادمة',
  lecture_url TEXT NOT NULL DEFAULT '',
  scheduled_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
