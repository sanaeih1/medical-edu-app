/* =====================================================================
   بک‌اند کامل «آموزش پزشکی در یک نگاه» در یک فایل واحد.
   دلیل یک‌فایلی بودن: آپلود این پروژه از گوشی (بدون کامپیوتر) با فایل‌های
   پراکنده در پوشه‌های تودرتو خیلی سخت است؛ اسم این فایل ([[path]].js) به
   Cloudflare Pages می‌گوید همه‌ی درخواست‌های زیر /api/ را همین یک فایل
   جواب بدهد. برای دیدن مسیر هر درخواست، آرایه‌ی context.params.path را
   می‌خوانیم (مثلاً برای /api/auth/login برابر است با ['auth','login']).
   ===================================================================== */

const PBKDF2_ITERATIONS = 100000;
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 روز

/* ---------- ابزارهای رمزنگاری و پاسخ ---------- */
function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function randomHex(nBytes = 32) {
  const arr = new Uint8Array(nBytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hashPassword(password, saltB64) {
  const enc = new TextEncoder();
  const saltBuf = saltB64 ? base64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBuf, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return { hash: bufToBase64(bits), salt: bufToBase64(saltBuf) };
}
async function verifyPassword(password, saltB64, expectedHashB64) {
  const { hash } = await hashPassword(password, saltB64);
  return hash === expectedHashB64;
}
async function sha256Hex(text) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders }
  });
}
function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}
class AuthError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}
async function createToken(env, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  await env.DB.prepare(
    'INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(tokenHash, userId, now, now + TOKEN_TTL_MS).run();
  return token;
}
async function getUserFromRequest(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1].trim();
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT u.* FROM auth_tokens t JOIN users u ON u.id = t.user_id
     WHERE t.token_hash = ? AND t.expires_at > ?`
  ).bind(tokenHash, Date.now()).first();
  return row || null;
}
async function requireAuth(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) throw new AuthError('نیاز به ورود به حساب کاربری دارید', 401);
  return user;
}
async function requireAdmin(request, env) {
  const user = await requireAuth(request, env);
  if (user.role !== 'admin') throw new AuthError('این بخش فقط برای مدیر سیستم در دسترس است', 403);
  return user;
}
function publicUser(u) {
  return { id: u.id, username: u.username, name: u.name, gender: u.gender, field: u.field, role: u.role, created: u.created_at };
}

/* ---------- ثبت‌نام / ورود / رمز عبور ---------- */
async function handleRegister(request, env) {
  const body = await request.json().catch(() => ({}));
  const username = (body.username || '').trim();
  const password = body.password || '';
  const name = (body.name || '').trim();
  const gender = body.gender || 'نامشخص';
  const field = body.field || 'عمومی';

  if (!username || !password || !name) return errorResponse('همه فیلدها الزامی است', 400);
  if (username.length < 3) return errorResponse('نام کاربری باید حداقل ۳ کاراکتر باشد', 400);
  if (password.length < 4) return errorResponse('رمز عبور باید حداقل ۴ کاراکتر باشد', 400);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) return errorResponse('این نام کاربری قبلاً ثبت شده است', 409);

  const id = 'u' + Date.now() + Math.floor(Math.random() * 100000);
  const { hash, salt } = await hashPassword(password);
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO users (id, username, password_hash, salt, name, gender, field, role, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'user', ?)`
  ).bind(id, username, hash, salt, name, gender, field, now).run();

  await env.DB.prepare('INSERT INTO sessions_log (user_id, ts, action) VALUES (?, ?, ?)').bind(id, now, 'register').run();

  const token = await createToken(env, id);
  return jsonResponse({ token, user: publicUser({ id, username, name, gender, field, role: 'user', created_at: now }) });
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const username = (body.username || '').trim();
  const password = body.password || '';
  if (!username || !password) return errorResponse('نام کاربری و رمز عبور الزامی است', 400);

  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user) return errorResponse('نام کاربری یا رمز عبور نادرست است', 401);

  const ok = await verifyPassword(password, user.salt, user.password_hash);
  if (!ok) return errorResponse('نام کاربری یا رمز عبور نادرست است', 401);

  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions_log (user_id, ts, action) VALUES (?, ?, ?)').bind(user.id, now, 'login').run();

  const token = await createToken(env, user.id);
  return jsonResponse({ token, user: publicUser(user) });
}

async function handleChangePassword(request, env) {
  const user = await requireAuth(request, env);
  const body = await request.json().catch(() => ({}));
  const { oldPassword, newPassword } = body;
  if (!oldPassword || !newPassword) return errorResponse('همه فیلدها الزامی است', 400);
  if (String(newPassword).length < 4) return errorResponse('رمز عبور جدید باید حداقل ۴ کاراکتر باشد', 400);

  const ok = await verifyPassword(oldPassword, user.salt, user.password_hash);
  if (!ok) return errorResponse('رمز عبور فعلی نادرست است', 401);

  const { hash, salt } = await hashPassword(newPassword);
  await env.DB.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').bind(hash, salt, user.id).run();
  return jsonResponse({ ok: true });
}

/* ---------- داده‌ی شخصی کاربر ---------- */
async function handleMeGet(request, env) {
  const user = await requireAuth(request, env);
  const [progressRows, resultRows, susRows, bookmarkRows, sessionRows] = await Promise.all([
    env.DB.prepare('SELECT * FROM progress WHERE user_id = ?').bind(user.id).all(),
    env.DB.prepare('SELECT * FROM results WHERE user_id = ? ORDER BY ts ASC').bind(user.id).all(),
    env.DB.prepare('SELECT * FROM sus_responses WHERE user_id = ? ORDER BY ts DESC').bind(user.id).all(),
    env.DB.prepare('SELECT chapter_id FROM bookmarks WHERE user_id = ?').bind(user.id).all(),
    env.DB.prepare('SELECT ts, action FROM sessions_log WHERE user_id = ? ORDER BY ts ASC').bind(user.id).all()
  ]);
  const progress = {};
  for (const r of progressRows.results) {
    progress[r.chapter_id] = {
      viewed: !!r.viewed, read: !!r.read, viewedAt: r.viewed_at, readAt: r.read_at,
      lastScore: r.last_score_json ? JSON.parse(r.last_score_json) : null,
      answers: r.answers_json ? JSON.parse(r.answers_json) : null, quizAt: r.quiz_at
    };
  }
  const results = resultRows.results.map(r => ({
    type: r.type, chapter: r.chapter_id, score: r.score, total: r.total, pct: r.pct,
    details: r.answers_json ? JSON.parse(r.answers_json) : null, ts: r.ts
  }));
  const sus = susRows.results.map(s => ({ answers: JSON.parse(s.answers_json), score: s.score, ts: s.ts }));
  const bookmarks = {};
  bookmarkRows.results.forEach(b => { bookmarks[b.chapter_id] = true; });
  return jsonResponse({ user: publicUser(user), progress, results, sus, bookmarks, sessions: sessionRows.results });
}
async function handleMeDelete(request, env) {
  const user = await requireAuth(request, env);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM progress WHERE user_id = ?').bind(user.id),
    env.DB.prepare('DELETE FROM results WHERE user_id = ?').bind(user.id),
    env.DB.prepare('DELETE FROM sus_responses WHERE user_id = ?').bind(user.id),
    env.DB.prepare('DELETE FROM bookmarks WHERE user_id = ?').bind(user.id)
  ]);
  return jsonResponse({ ok: true });
}

/* ---------- پیشرفت / نمرات / SUS / بوکمارک ---------- */
async function handleProgress(request, env) {
  const user = await requireAuth(request, env);
  const body = await request.json().catch(() => ({}));
  const { chapterId, action } = body;
  if (!chapterId || !['viewed', 'read'].includes(action)) return errorResponse('درخواست نامعتبر', 400);
  const now = Date.now();
  const existing = await env.DB.prepare('SELECT * FROM progress WHERE user_id = ? AND chapter_id = ?').bind(user.id, chapterId).first();
  if (!existing) {
    await env.DB.prepare(
      `INSERT INTO progress (user_id, chapter_id, viewed, read, viewed_at, read_at) VALUES (?, ?, 1, ?, ?, ?)`
    ).bind(user.id, chapterId, action === 'read' ? 1 : 0, now, action === 'read' ? now : null).run();
  } else if (action === 'read' && !existing.read) {
    await env.DB.prepare(
      `UPDATE progress SET read = 1, read_at = ?, viewed = 1, viewed_at = COALESCE(viewed_at, ?) WHERE user_id = ? AND chapter_id = ?`
    ).bind(now, now, user.id, chapterId).run();
  } else if (action === 'viewed' && !existing.viewed) {
    await env.DB.prepare('UPDATE progress SET viewed = 1, viewed_at = ? WHERE user_id = ? AND chapter_id = ?').bind(now, user.id, chapterId).run();
  }
  return jsonResponse({ ok: true });
}
async function handleQuizResult(request, env) {
  const user = await requireAuth(request, env);
  const body = await request.json().catch(() => ({}));
  const { type, chapterId, score, total, answers } = body;
  if (!['chapter', 'pretest', 'posttest'].includes(type)) return errorResponse('نوع آزمون نامعتبر است', 400);
  if (typeof score !== 'number' || typeof total !== 'number' || total <= 0) return errorResponse('نمره نامعتبر است', 400);
  const pct = Math.round((score / total) * 100);
  const now = Date.now();
  const answersJson = JSON.stringify(answers || []);
  await env.DB.prepare(
    `INSERT INTO results (user_id, type, chapter_id, score, total, pct, answers_json, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(user.id, type, chapterId || null, score, total, pct, answersJson, now).run();
  if (type === 'chapter' && chapterId) {
    const lastScoreJson = JSON.stringify({ score, total, pct });
    const existing = await env.DB.prepare('SELECT chapter_id FROM progress WHERE user_id = ? AND chapter_id = ?').bind(user.id, chapterId).first();
    if (existing) {
      await env.DB.prepare(
        `UPDATE progress SET last_score_json = ?, answers_json = ?, quiz_at = ?, read = 1, viewed = 1 WHERE user_id = ? AND chapter_id = ?`
      ).bind(lastScoreJson, answersJson, now, user.id, chapterId).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO progress (user_id, chapter_id, viewed, read, viewed_at, read_at, last_score_json, answers_json, quiz_at)
         VALUES (?, ?, 1, 1, ?, ?, ?, ?, ?)`
      ).bind(user.id, chapterId, now, now, lastScoreJson, answersJson, now).run();
    }
  }
  return jsonResponse({ ok: true, pct });
}
async function handleSus(request, env) {
  const user = await requireAuth(request, env);
  const body = await request.json().catch(() => ({}));
  const answers = body.answers;
  if (!Array.isArray(answers) || answers.length !== 10 || answers.some(v => !(v >= 1 && v <= 5))) {
    return errorResponse('پاسخ‌های پرسشنامه نامعتبر است', 400);
  }
  let sum = 0;
  for (let i = 0; i < answers.length; i++) sum += (i % 2 === 0) ? (answers[i] - 1) : (5 - answers[i]);
  const score = sum * 2.5;
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sus_responses (user_id, answers_json, score, ts) VALUES (?, ?, ?, ?)').bind(user.id, JSON.stringify(answers), score, now).run();
  return jsonResponse({ ok: true, score });
}
async function handleBookmark(request, env) {
  const user = await requireAuth(request, env);
  const body = await request.json().catch(() => ({}));
  const { chapterId, bookmarked } = body;
  if (!chapterId) return errorResponse('شناسه فصل الزامی است', 400);
  if (bookmarked) {
    await env.DB.prepare('INSERT OR IGNORE INTO bookmarks (user_id, chapter_id) VALUES (?, ?)').bind(user.id, chapterId).run();
  } else {
    await env.DB.prepare('DELETE FROM bookmarks WHERE user_id = ? AND chapter_id = ?').bind(user.id, chapterId).run();
  }
  return jsonResponse({ ok: true });
}

/* ---------- مقایسه‌ی بی‌نام و تنظیمات عمومی ---------- */
async function handleCompare(request, env) {
  await requireAuth(request, env);
  const rows = await env.DB.prepare(`
    SELECT u.field AS field, u.gender AS gender, r.type AS type, r.pct AS pct, r.user_id AS user_id, r.ts AS ts
    FROM results r JOIN users u ON u.id = r.user_id
    WHERE r.type IN ('pretest','posttest') AND u.role = 'user'
  `).all();
  const perUser = {};
  for (const row of rows.results) {
    if (!perUser[row.user_id]) perUser[row.user_id] = { field: row.field, gender: row.gender };
    const u = perUser[row.user_id];
    if (row.type === 'pretest') {
      if (u.preTs === undefined || row.ts < u.preTs) { u.pre = row.pct; u.preTs = row.ts; }
    } else {
      if (u.postTs === undefined || row.ts > u.postTs) { u.post = row.pct; u.postTs = row.ts; }
    }
  }
  const groupBy = (key) => {
    const groups = {};
    Object.values(perUser).forEach(u => {
      if (u.pre === undefined) return;
      const k = u[key] || 'نامشخص';
      (groups[k] = groups[k] || []).push({ pre: u.pre, post: u.post ?? null });
    });
    return groups;
  };
  const avg = arr => arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
  const summarize = (groups) => Object.fromEntries(Object.entries(groups).map(([k, arr]) => [k, {
    count: arr.length, avgPre: avg(arr.map(x => x.pre)), avgPost: avg(arr.filter(x => x.post !== null).map(x => x.post))
  }]));
  return jsonResponse({ byField: summarize(groupBy('field')), byGender: summarize(groupBy('gender')) });
}
async function handleSettingsGet(env) {
  const rows = await env.DB.prepare('SELECT key, value FROM settings').all();
  const s = {};
  rows.results.forEach(r => { s[r.key] = r.value; });
  return jsonResponse({ pretestCount: parseInt(s.pretestCount || '10', 10), posttestCount: parseInt(s.posttestCount || '10', 10) });
}

/* ---------- بخش ادمین ---------- */
async function handleAdminSettingsPost(request, env) {
  await requireAdmin(request, env);
  const body = await request.json().catch(() => ({}));
  const { pretestCount, posttestCount } = body;
  if (pretestCount > 0) {
    await env.DB.prepare(`INSERT INTO settings (key, value) VALUES ('pretestCount', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(String(pretestCount)).run();
  }
  if (posttestCount > 0) {
    await env.DB.prepare(`INSERT INTO settings (key, value) VALUES ('posttestCount', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(String(posttestCount)).run();
  }
  return jsonResponse({ ok: true });
}
async function handleAdminUsersGet(request, env) {
  await requireAdmin(request, env);
  const users = await env.DB.prepare(`SELECT * FROM users WHERE role != 'admin' ORDER BY created_at DESC`).all();
  const loginCounts = await env.DB.prepare(`SELECT user_id, COUNT(*) as cnt FROM sessions_log WHERE action = 'login' GROUP BY user_id`).all();
  const cntMap = {};
  loginCounts.results.forEach(r => { cntMap[r.user_id] = r.cnt; });
  const list = users.results.map(u => ({ id: u.id, username: u.username, name: u.name, gender: u.gender, field: u.field, created: u.created_at, logins: cntMap[u.id] || 0 }));
  const [resultsCount, susCount] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) as c FROM results').first(),
    env.DB.prepare('SELECT COUNT(*) as c FROM sus_responses').first()
  ]);
  return jsonResponse({ users: list, stats: { resultsCount: resultsCount.c, susCount: susCount.c } });
}
async function handleAdminUserGet(request, env, id) {
  await requireAdmin(request, env);
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
  if (!user) return errorResponse('کاربر یافت نشد', 404);
  const results = await env.DB.prepare('SELECT * FROM results WHERE user_id = ?').bind(id).all();
  const sus = await env.DB.prepare('SELECT * FROM sus_responses WHERE user_id = ? ORDER BY ts DESC LIMIT 1').bind(id).first();
  const logins = await env.DB.prepare(`SELECT COUNT(*) as cnt FROM sessions_log WHERE user_id = ? AND action='login'`).bind(id).first();
  const pre = results.results.find(r => r.type === 'pretest');
  const post = [...results.results].reverse().find(r => r.type === 'posttest');
  const chapterCount = results.results.filter(r => r.type === 'chapter').length;
  return jsonResponse({
    user: { id: user.id, username: user.username, name: user.name, gender: user.gender, field: user.field, created: user.created_at },
    logins: logins ? logins.cnt : 0, pre: pre ? pre.pct : null, post: post ? post.pct : null,
    sus: sus ? sus.score : null, chapterQuizzes: chapterCount
  });
}
async function handleAdminUserDelete(request, env, id) {
  await requireAdmin(request, env);
  const user = await env.DB.prepare(`SELECT id FROM users WHERE id = ? AND role != 'admin'`).bind(id).first();
  if (!user) return errorResponse('کاربر یافت نشد', 404);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM progress WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM results WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM sus_responses WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM bookmarks WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM sessions_log WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM auth_tokens WHERE user_id = ?').bind(id),
    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id)
  ]);
  return jsonResponse({ ok: true });
}
async function handleAdminResults(request, env) {
  await requireAdmin(request, env);
  const rows = await env.DB.prepare(`
    SELECT r.id, r.type, r.chapter_id, r.score, r.total, r.pct, r.ts, u.name AS user_name, u.username AS username
    FROM results r JOIN users u ON u.id = r.user_id ORDER BY r.ts DESC LIMIT 300
  `).all();
  return jsonResponse({ results: rows.results });
}
async function handleAdminSus(request, env) {
  await requireAdmin(request, env);
  const rows = await env.DB.prepare(`
    SELECT s.id, s.score, s.ts, u.name AS user_name, u.username AS username
    FROM sus_responses s JOIN users u ON u.id = s.user_id ORDER BY s.ts DESC
  `).all();
  return jsonResponse({ sus: rows.results });
}
function csvEscape(v) { return `"${String(v == null ? '' : v).replace(/"/g, '""')}"`; }
function toCSV(rows) { return rows.map(r => r.map(csvEscape).join(',')).join('\n'); }
function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} - ${p(d.getHours())}:${p(d.getMinutes())}`;
}
async function handleAdminExport(request, env) {
  await requireAdmin(request, env);
  const url = new URL(request.url);
  const type = url.searchParams.get('type') || 'all';
  const rows = [];
  if (type === 'users' || type === 'all') {
    const users = await env.DB.prepare(`SELECT * FROM users WHERE role != 'admin'`).all();
    const logins = await env.DB.prepare(`SELECT user_id, COUNT(*) c FROM sessions_log WHERE action='login' GROUP BY user_id`).all();
    const loginMap = {}; logins.results.forEach(l => { loginMap[l.user_id] = l.c; });
    rows.push(['--- کاربران ---']);
    rows.push(['نام', 'نام کاربری', 'جنسیت', 'رشته', 'تاریخ عضویت', 'تعداد ورود']);
    users.results.forEach(u => rows.push([u.name, u.username, u.gender, u.field, fmtDate(u.created_at), loginMap[u.id] || 0]));
    rows.push([]);
  }
  if (type === 'results' || type === 'all') {
    const results = await env.DB.prepare(`SELECT r.*, u.username AS uname FROM results r JOIN users u ON u.id=r.user_id ORDER BY r.ts`).all();
    rows.push(['--- نتایج آزمون‌ها ---']);
    rows.push(['کاربر', 'نوع', 'فصل', 'نمره', 'از', 'درصد', 'تاریخ']);
    results.results.forEach(r => rows.push([r.uname, r.type, r.chapter_id || '', r.score, r.total, r.pct, fmtDate(r.ts)]));
    rows.push([]);
  }
  if (type === 'sus' || type === 'all') {
    const sus = await env.DB.prepare(`SELECT s.*, u.username AS uname FROM sus_responses s JOIN users u ON u.id=s.user_id ORDER BY s.ts`).all();
    rows.push(['--- نتایج SUS ---']);
    rows.push(['کاربر', 'امتیاز', 'تاریخ', 'پاسخ‌ها (JSON)']);
    sus.results.forEach(s => rows.push([s.uname, Number(s.score).toFixed(1), fmtDate(s.ts), s.answers_json]));
    rows.push([]);
  }
  if (type === 'progress' || type === 'all') {
    const progress = await env.DB.prepare(`SELECT p.*, u.username AS uname FROM progress p JOIN users u ON u.id=p.user_id`).all();
    rows.push(['--- پیشرفت کاربران ---']);
    rows.push(['کاربر', 'فصل', 'مشاهده', 'مطالعه', 'آخرین نمره']);
    progress.results.forEach(p => {
      let lastPct = '';
      try { lastPct = p.last_score_json ? JSON.parse(p.last_score_json).pct + '%' : ''; } catch (e) { /* ignore */ }
      rows.push([p.uname, p.chapter_id, p.viewed ? '✓' : '', p.read ? '✓' : '', lastPct]);
    });
    rows.push([]);
  }
  if (type === 'sessions' || type === 'all') {
    const sessions = await env.DB.prepare(`SELECT s.*, u.username AS uname FROM sessions_log s JOIN users u ON u.id=s.user_id ORDER BY s.ts`).all();
    rows.push(['--- تاریخچه ورود ---']);
    rows.push(['کاربر', 'زمان', 'عملیات']);
    sessions.results.forEach(s => rows.push([s.uname, fmtDate(s.ts), s.action]));
  }
  const csv = '\ufeff' + toCSV(rows);
  return new Response(csv, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="medical-edu-${type}-${Date.now()}.csv"` } });
}
async function handleAdminReset(request, env) {
  await requireAdmin(request, env);
  const body = await request.json().catch(() => ({}));
  const { scope, userId } = body;
  if (scope === 'user') {
    if (!userId) return errorResponse('شناسه کاربر الزامی است', 400);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM progress WHERE user_id = ?').bind(userId),
      env.DB.prepare('DELETE FROM results WHERE user_id = ?').bind(userId),
      env.DB.prepare('DELETE FROM sus_responses WHERE user_id = ?').bind(userId),
      env.DB.prepare('DELETE FROM bookmarks WHERE user_id = ?').bind(userId)
    ]);
    return jsonResponse({ ok: true });
  }
  if (scope === 'all') {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM progress WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM results WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM sus_responses WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM bookmarks WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`)
    ]);
    return jsonResponse({ ok: true });
  }
  if (scope === 'all-users') {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM progress WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM results WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM sus_responses WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM bookmarks WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM sessions_log WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM auth_tokens WHERE user_id IN (SELECT id FROM users WHERE role != 'admin')`),
      env.DB.prepare(`DELETE FROM users WHERE role != 'admin'`)
    ]);
    return jsonResponse({ ok: true });
  }
  return errorResponse('scope نامعتبر است', 400);
}

/* ---------- مسیریاب اصلی ---------- */
export async function onRequest(context) {
  const { request, env, params } = context;
  const segs = Array.isArray(params.path) ? params.path : (params.path ? [params.path] : []);
  const p = segs.join('/');
  const method = request.method;
  try {
    if (method === 'POST' && p === 'auth/register') return await handleRegister(request, env);
    if (method === 'POST' && p === 'auth/login') return await handleLogin(request, env);
    if (method === 'POST' && p === 'change-password') return await handleChangePassword(request, env);
    if (method === 'GET' && p === 'me') return await handleMeGet(request, env);
    if (method === 'DELETE' && p === 'me') return await handleMeDelete(request, env);
    if (method === 'POST' && p === 'progress') return await handleProgress(request, env);
    if (method === 'POST' && p === 'quiz-result') return await handleQuizResult(request, env);
    if (method === 'POST' && p === 'sus') return await handleSus(request, env);
    if (method === 'POST' && p === 'bookmark') return await handleBookmark(request, env);
    if (method === 'GET' && p === 'compare') return await handleCompare(request, env);
    if (method === 'GET' && p === 'settings') return await handleSettingsGet(env);
    if (method === 'POST' && p === 'admin/settings') return await handleAdminSettingsPost(request, env);
    if (method === 'GET' && p === 'admin/users') return await handleAdminUsersGet(request, env);
    if (method === 'GET' && segs[0] === 'admin' && segs[1] === 'users' && segs[2]) return await handleAdminUserGet(request, env, segs[2]);
    if (method === 'DELETE' && segs[0] === 'admin' && segs[1] === 'users' && segs[2]) return await handleAdminUserDelete(request, env, segs[2]);
    if (method === 'GET' && p === 'admin/results') return await handleAdminResults(request, env);
    if (method === 'GET' && p === 'admin/sus') return await handleAdminSus(request, env);
    if (method === 'GET' && segs[0] === 'admin' && segs[1] === 'export') return await handleAdminExport(request, env);
    if (method === 'POST' && p === 'admin/reset') return await handleAdminReset(request, env);
    return errorResponse('مسیر یافت نشد', 404);
  } catch (err) {
    const status = err && err.status ? err.status : 500;
    const message = (err && err.message) ? err.message : 'خطای داخلی سرور';
    return jsonResponse({ error: message }, status);
  }
}
