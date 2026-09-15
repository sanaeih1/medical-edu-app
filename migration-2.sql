-- ============================================================================
-- migration-2.sql — برای دیتابیسی که از قبل روی Cloudflare ساخته و پر شده
-- این فایل را در Cloudflare Dashboard → D1 → (دیتابیس شما) → Console
-- کپی و اجرا کنید. کاربران و نتایج فعلی شما پاک نمی‌شوند.
-- (اگر تازه دارید از صفر شروع می‌کنید، این فایل لازم نیست — همه‌چیز از
-- قبل در schema.sql هست.)
-- ============================================================================

ALTER TABLE users ADD COLUMN national_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_national_id ON users(national_id) WHERE national_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS activity_log (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  ts             INTEGER NOT NULL,
  level          TEXT NOT NULL,
  actor_user_id  TEXT,
  action         TEXT NOT NULL,
  details_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity_log(ts);
