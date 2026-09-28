CREATE TABLE IF NOT EXISTS grades (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  exam_name TEXT NOT NULL,
  lesson_name TEXT NOT NULL,
  score REAL NOT NULL,
  total REAL NOT NULL,
  created_at TEXT NOT NULL
);