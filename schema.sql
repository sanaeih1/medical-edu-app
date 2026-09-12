-- ============================================================================
-- schema.sql — «آموزش پزشکی در یک نگاه»
-- این فایل را در Cloudflare Dashboard → Workers & Pages → D1 →
-- (دیتابیس شما) → Console کپی و اجرا کنید (یک بار، در ابتدای راه‌اندازی).
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  name          TEXT NOT NULL,
  gender        TEXT DEFAULT 'نامشخص',
  field         TEXT DEFAULT 'عمومی',
  role          TEXT NOT NULL DEFAULT 'user',
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash  TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id);

CREATE TABLE IF NOT EXISTS sessions_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  TEXT NOT NULL,
  ts       INTEGER NOT NULL,
  action   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions_log(user_id);

CREATE TABLE IF NOT EXISTS progress (
  user_id        TEXT NOT NULL,
  chapter_id     TEXT NOT NULL,
  viewed         INTEGER DEFAULT 0,
  read           INTEGER DEFAULT 0,
  viewed_at      INTEGER,
  read_at        INTEGER,
  last_score_json TEXT,
  answers_json   TEXT,
  quiz_at        INTEGER,
  PRIMARY KEY (user_id, chapter_id)
);

CREATE TABLE IF NOT EXISTS results (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      TEXT NOT NULL,
  type         TEXT NOT NULL,      -- 'chapter' | 'pretest' | 'posttest'
  chapter_id   TEXT,
  score        INTEGER NOT NULL,
  total        INTEGER NOT NULL,
  pct          INTEGER NOT NULL,
  answers_json TEXT,
  ts           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_user ON results(user_id);
CREATE INDEX IF NOT EXISTS idx_results_type ON results(type);

CREATE TABLE IF NOT EXISTS sus_responses (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      TEXT NOT NULL,
  answers_json TEXT NOT NULL,
  score        REAL NOT NULL,
  ts           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sus_user ON sus_responses(user_id);

CREATE TABLE IF NOT EXISTS bookmarks (
  user_id     TEXT NOT NULL,
  chapter_id  TEXT NOT NULL,
  PRIMARY KEY (user_id, chapter_id)
);

CREATE TABLE IF NOT EXISTS settings (
  key    TEXT PRIMARY KEY,
  value  TEXT
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('pretestCount', '10');
INSERT OR IGNORE INTO settings (key, value) VALUES ('posttestCount', '10');

-- حساب مدیر پیش‌فرض: نام کاربری admin / رمز عبور admin
-- (رمز به‌صورت هش‌شده با PBKDF2-SHA256 ذخیره شده، نه متن ساده)
-- ⚠️ حتماً پس از اولین ورود، از پنل تنظیمات رمز را عوض کنید.
INSERT OR IGNORE INTO users (id, username, password_hash, salt, name, gender, field, role, created_at)
VALUES (
  'admin-seed-1',
  'admin',
  'URKTdeI1JtB+pdkLdKlGW5qQBQ6aEhJ4bTIDr2gQMcs=',
  'aYcl5dN3JSwIvCOUlk0O7w==',
  'مدیر سیستم',
  'نامشخص',
  'مدیریت',
  'admin',
  0
);
