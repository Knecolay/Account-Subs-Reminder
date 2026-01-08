const RECORDS_KEY = "v1:records";
const CONFIG_KEY = "v1:config";
const SESSION_PREFIX = "v1:session:";
const FORGOT_COOLDOWN_KEY = "v1:forgot:cooldown";

function json(data, init = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { ...init, headers });
}

function text(body, init = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "text/plain; charset=utf-8");
  headers.set("cache-control", "no-store");
  return new Response(body, { ...init, headers });
}

function html(body, init = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "text/html; charset=utf-8");
  headers.set("cache-control", "no-store");
  return new Response(body, { ...init, headers });
}

function redirect(location, status = 302, init = {}) {
  const headers = new Headers(init.headers);
  headers.set("location", location);
  return new Response(null, { ...init, status, headers });
}

function badRequest(message) {
  return json({ ok: false, error: message }, { status: 400 });
}

function unauthorized(init = {}) {
  return json({ ok: false, error: "Unauthorized" }, { status: 401, ...init });
}

function serverError(message) {
  return json({ ok: false, error: message }, { status: 500 });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function parseYmdToUtcDate(ymd) {
  if (typeof ymd !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(ymd)) return null;
  const date = new Date(`${ymd}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function diffDaysUtc(dateA, dateB) {
  const ms = dateA.getTime() - dateB.getTime();
  return Math.floor(ms / 86400000);
}

function newId(bytesLen = 16) {
  const bytes = new Uint8Array(bytesLen);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function generatePassword(length = 12) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function getCookieValue(cookieString, key) {
  if (!cookieString) return null;
  const match = cookieString.match(new RegExp(`(^|;\\s*)${key}=([^;]+)`));
  return match ? match[2] : null;
}

function setCookieHeader(name, value, opts) {
  const parts = [`${name}=${value}`];
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) parts.push("Secure");
  return parts.join("; ");
}

function clearSessionCookieHeader(request) {
  const secure = new URL(request.url).protocol === "https:";
  return setCookieHeader("session", "", { maxAge: 0, httpOnly: true, sameSite: "Lax", secure, path: "/" });
}

async function loadRecords(env) {
  const data = await env.SUBS_KV.get(RECORDS_KEY, { type: "json" });
  return Array.isArray(data) ? data : [];
}

async function saveRecords(env, records) {
  await env.SUBS_KV.put(RECORDS_KEY, JSON.stringify(records));
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, salt) {
  return sha256Hex(`${salt}:${password}`);
}

async function ensureConfig(env) {
  const existing = await env.SUBS_KV.get(CONFIG_KEY, { type: "json" });
  if (existing && typeof existing === "object") {
    if (typeof existing.authVersion !== "number") {
      existing.authVersion = 1;
      await saveConfig(env, existing);
    }
    return existing;
  }
  const salt = newId(8);
  const adminPasswordHash = await hashPassword("password", salt);
  const config = {
    adminUsername: "admin",
    adminPasswordSalt: salt,
    adminPasswordHash,
    authVersion: 1,
    remindDays: 7,
    expiredDays: 30,
    emailSubjectPrefix: "[SubsTracker]",
    resendApiKey: "",
    emailFrom: "",
    emailTo: "",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await env.SUBS_KV.put(CONFIG_KEY, JSON.stringify(config));
  return config;
}

async function saveConfig(env, config) {
  config.updatedAt = new Date().toISOString();
  await env.SUBS_KV.put(CONFIG_KEY, JSON.stringify(config));
}

async function requireUser(request, env) {
  const token = getCookieValue(request.headers.get("cookie"), "session");
  if (!token) return { ok: false };
  const session = await env.SUBS_KV.get(`${SESSION_PREFIX}${token}`, { type: "json" });
  if (!session || typeof session !== "object" || !session.username) return { ok: false };
  const config = await ensureConfig(env);
  if (typeof config.authVersion === "number") {
    if (typeof session.authVersion !== "number" || session.authVersion !== config.authVersion) {
      await destroySession(env, token);
      return { ok: false, clearCookie: true };
    }
  }
  return { ok: true, user: session.username };
}

async function createSession(env, username, authVersion) {
  const token = newId(24);
  const ttlSeconds = 60 * 60 * 24 * 7;
  await env.SUBS_KV.put(`${SESSION_PREFIX}${token}`, JSON.stringify({ username, authVersion }), { expirationTtl: ttlSeconds });
  return { token, ttlSeconds };
}

async function destroySession(env, token) {
  if (!token) return;
  await env.SUBS_KV.delete(`${SESSION_PREFIX}${token}`);
}

function normalizeProvider(provider) {
  const p = String(provider || "").trim().toLowerCase();
  if (p === "chatgpt" || p === "gpt" || p === "openai") return "chatgpt";
  if (p === "gemini" || p === "google" || p === "googlegemini") return "gemini";
  return p || "other";
}

function validateRecordInput(input) {
  if (!input || typeof input !== "object") return { ok: false, error: "Invalid JSON body." };
  const provider = normalizeProvider(input.provider);
  const account = String(input.account || "").trim();
  const startedAt = String(input.startedAt || "").trim();
  const expiresAt = String(input.expiresAt || "").trim();
  const note = typeof input.note === "string" ? input.note.trim() : "";
  if (!account) return { ok: false, error: "Missing `account`." };
  const start = parseYmdToUtcDate(startedAt);
  const end = parseYmdToUtcDate(expiresAt);
  if (!start) return { ok: false, error: "Invalid `startedAt` (YYYY-MM-DD)." };
  if (!end) return { ok: false, error: "Invalid `expiresAt` (YYYY-MM-DD)." };
  if (end.getTime() < start.getTime()) return { ok: false, error: "`expiresAt` must be >= `startedAt`." };
  return { ok: true, value: { provider, account, startedAt, expiresAt, note } };
}

function toCsv(records) {
  const header = ["id", "provider", "account", "startedAt", "expiresAt", "note"];
  const escape = (v) => {
    const s = String(v ?? "");
    if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const lines = [header.join(",")];
  for (const r of records) {
    lines.push([r.id, r.provider, r.account, r.startedAt, r.expiresAt, r.note || ""].map(escape).join(","));
  }
  return lines.join("\n");
}

function parseCsv(textBody) {
  const rows = [];
  let row = [];
  let cell = "";
  let inQuotes = false;
  const pushCell = () => {
    row.push(cell);
    cell = "";
  };
  const pushRow = () => {
    rows.push(row);
    row = [];
  };
  for (let i = 0; i < textBody.length; i++) {
    const ch = textBody[i];
    if (inQuotes) {
      if (ch === '"') {
        const next = textBody[i + 1];
        if (next === '"') {
          cell += '"';
          i++;
        } else inQuotes = false;
      } else cell += ch;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      continue;
    }
    if (ch === ",") {
      pushCell();
      continue;
    }
    if (ch === "\n") {
      pushCell();
      pushRow();
      continue;
    }
    if (ch === "\r") continue;
    cell += ch;
  }
  pushCell();
  pushRow();
  const nonEmpty = rows.filter((r) => r.some((c) => String(c).trim() !== ""));
  if (nonEmpty.length === 0) return [];
  const first = nonEmpty[0].map((c) => String(c).trim().toLowerCase());
  const hasHeader =
    first.includes("provider") && first.includes("account") && first.includes("startedat") && first.includes("expiresat");
  const startIndex = hasHeader ? 1 : 0;
  return nonEmpty.slice(startIndex).map((r) => {
    const [provider, account, startedAt, expiresAt, note] = r;
    return { provider: provider ?? "", account: account ?? "", startedAt: startedAt ?? "", expiresAt: expiresAt ?? "", note: note ?? "" };
  });
}

async function handleListRecords(env) {
  const records = await loadRecords(env);
  records.sort((a, b) => (a.expiresAt || "").localeCompare(b.expiresAt || ""));
  return json({ ok: true, records });
}

async function handleCreateRecord(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest("Invalid JSON.");
  }
  const validated = validateRecordInput(body);
  if (!validated.ok) return badRequest(validated.error);
  const nowIso = new Date().toISOString();
  const record = { id: newId(), ...validated.value, createdAt: nowIso, updatedAt: nowIso };
  const records = await loadRecords(env);
  records.push(record);
  await saveRecords(env, records);
  return json({ ok: true, record }, { status: 201 });
}

async function handleUpdateRecord(id, request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest("Invalid JSON.");
  }
  const validated = validateRecordInput(body);
  if (!validated.ok) return badRequest(validated.error);
  const records = await loadRecords(env);
  const idx = records.findIndex((r) => r.id === id);
  if (idx < 0) return badRequest("Record not found.");
  const nowIso = new Date().toISOString();
  records[idx] = { ...records[idx], ...validated.value, updatedAt: nowIso };
  await saveRecords(env, records);
  return json({ ok: true, record: records[idx] });
}

async function handleDeleteRecord(id, env) {
  const records = await loadRecords(env);
  const next = records.filter((r) => r.id !== id);
  if (next.length === records.length) return badRequest("Record not found.");
  await saveRecords(env, next);
  return json({ ok: true });
}

async function handleExport(request, env) {
  const url = new URL(request.url);
  const format = (url.searchParams.get("format") || "json").toLowerCase();
  const records = await loadRecords(env);
  records.sort((a, b) => (a.expiresAt || "").localeCompare(b.expiresAt || ""));
  if (format === "csv") {
    return new Response(toCsv(records), { headers: { "content-type": "text/csv; charset=utf-8", "cache-control": "no-store" } });
  }
  return json({ ok: true, records });
}

async function handleImport(request, env) {
  const url = new URL(request.url);
  const format = (url.searchParams.get("format") || "json").toLowerCase();
  const mode = (url.searchParams.get("mode") || "merge").toLowerCase();
  const raw = await request.text();
  let items;
  if (format === "csv") items = parseCsv(raw);
  else {
    try {
      items = JSON.parse(raw);
    } catch {
      return badRequest("Invalid JSON.");
    }
  }
  if (!Array.isArray(items)) return badRequest("Import body must be an array (or CSV rows).");
  const existing = mode === "replace" ? [] : await loadRecords(env);
  const byKey = new Map(existing.map((r) => [`${r.provider}::${r.account}`, r]));
  let added = 0;
  let updated = 0;
  let skipped = 0;
  const nowIso = new Date().toISOString();
  for (const item of items) {
    const validated = validateRecordInput(item);
    if (!validated.ok) {
      skipped++;
      continue;
    }
    const k = `${validated.value.provider}::${validated.value.account}`;
    const found = byKey.get(k);
    if (found && mode !== "replace") {
      found.provider = validated.value.provider;
      found.account = validated.value.account;
      found.startedAt = validated.value.startedAt;
      found.expiresAt = validated.value.expiresAt;
      found.note = validated.value.note;
      found.updatedAt = nowIso;
      updated++;
      continue;
    }
    const record = { id: newId(), ...validated.value, createdAt: nowIso, updatedAt: nowIso };
    existing.push(record);
    byKey.set(k, record);
    added++;
  }
  await saveRecords(env, existing);
  return json({ ok: true, added, updated, skipped, total: existing.length });
}

function buildReminderList(records, remindDays, expiredDays) {
  const now = new Date();
  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const soon = [];
  const expired = [];
  for (const r of records) {
    const end = parseYmdToUtcDate(r.expiresAt);
    if (!end) continue;
    const left = diffDaysUtc(end, today);
    if (left < 0) {
      if (expiredDays > 0 && left >= -expiredDays) expired.push({ ...r, daysLeft: left });
      continue;
    }
    if (left <= remindDays) soon.push({ ...r, daysLeft: left });
  }
  soon.sort((a, b) => a.daysLeft - b.daysLeft);
  expired.sort((a, b) => a.daysLeft - b.daysLeft);
  return { today: today.toISOString().slice(0, 10), soon, expired };
}

function reminderEmailHtml(summary, remindDays) {
  const rows = (arr) =>
    arr
      .map(
        (r) =>
          `<tr><td>${escapeHtml(r.provider)}</td><td>${escapeHtml(r.account)}</td><td>${escapeHtml(r.startedAt)}</td><td>${escapeHtml(
            r.expiresAt,
          )}</td><td>${r.daysLeft}</td><td>${escapeHtml(r.note || "")}</td></tr>`,
      )
      .join("");
  const table = (title, arr) =>
    `<h3>${escapeHtml(title)}（${arr.length}）</h3><table border="1" cellspacing="0" cellpadding="6"><tr><th>Provider</th><th>Account</th><th>Started</th><th>Expires</th><th>Days</th><th>Note</th></tr>${rows(
      arr,
    )}</table>`;
  return `<div><h2>订阅到期提醒</h2><p>日期：${escapeHtml(summary.today)}（UTC），提醒窗口：未来 ${remindDays} 天</p>${
    summary.soon.length ? table("即将到期", summary.soon) : `<p>未来 ${remindDays} 天内没有即将到期的记录。</p>`
  }${summary.expired.length ? table("已过期（窗口内）", summary.expired) : ""}<p style="color:#666">由 Cloudflare Workers 定时任务发送。</p></div>`;
}

function credentialEmailHtml({ title, username, password, note }) {
  return `
  <div style="font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;max-width:720px;margin:0 auto">
    <h2 style="margin:0 0 8px">${escapeHtml(title)}</h2>
    <p style="margin:0 0 14px;color:#555">${escapeHtml(note || "")}</p>
    <div style="border:1px solid #e6e6e6;border-radius:12px;padding:12px 14px;background:#fafafa">
      <div style="margin:6px 0"><b>用户名：</b><code>${escapeHtml(username)}</code></div>
      <div style="margin:6px 0"><b>密码：</b><code>${escapeHtml(password)}</code></div>
    </div>
    <p style="margin:14px 0 0;color:#888;font-size:12px">如非本人操作，建议尽快登录修改密码并检查收件邮箱配置。</p>
  </div>`;
}

async function sendResendEmail(config, subject, htmlBody) {
  return sendEmailViaResend(config.resendApiKey, config.emailFrom, config.emailTo, subject, htmlBody);
}

async function sendEmailViaResend(resendApiKey, emailFrom, emailTo, subject, htmlBody) {
  const to = String(emailTo || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!resendApiKey) throw new Error("Resend not configured (missing API key).");
  if (!emailFrom) throw new Error("Missing emailFrom.");
  if (!to.length) throw new Error("emailTo is empty.");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${resendApiKey}` },
    body: JSON.stringify({ from: emailFrom, to, subject, html: htmlBody }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.message || `Resend error: HTTP ${res.status}`);
  return data;
}

async function runReminder(env, { forceSend = false } = {}) {
  const config = await ensureConfig(env);
  const remindDays = Math.max(0, Number.parseInt(String(config.remindDays ?? 7), 10) || 7);
  const expiredDays = Math.max(0, Number.parseInt(String(config.expiredDays ?? 30), 10) || 30);
  const records = await loadRecords(env);
  const summary = buildReminderList(records, remindDays, expiredDays);
  const hasContent = summary.soon.length || summary.expired.length;
  if (!hasContent && !forceSend) return { ok: true, skipped: true, reason: "No expiring/expired records." };
  if (!config.resendApiKey || !config.emailFrom || !config.emailTo) return { ok: false, skipped: true, reason: "Email not configured." };
  const prefix = config.emailSubjectPrefix ? String(config.emailSubjectPrefix).trim() : "[SubsTracker]";
  const subject = `${prefix} 到期提醒 ${summary.today}`;
  const htmlBody = reminderEmailHtml(summary, remindDays);
  const data = await sendResendEmail(config, subject, htmlBody);
  return { ok: true, skipped: false, resend: data, summary };
}

function loginPageHtml() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>SubsTracker 登录</title>
  <style>
    :root{
      --bg0:#070a14; --bg1:#0b1020; --card:rgba(18,26,51,.88); --line:#223059;
      --text:#e7e9f2; --muted:#aab2d5; --accent:#6aa9ff; --danger:#ff6a7a;
      --accentBg: rgba(106,169,255,.14);
      --accentBgHover: rgba(106,169,255,.18);
      --accentLine: rgba(106,169,255,.45);
      --glowA: rgba(106,169,255,.18);
      --glowB: rgba(255,106,122,.12);
      --panel: rgba(11,18,40,.55);
      --panelSoft: rgba(11,18,40,.35);
      --inputBg: #0b1228;
      --shadow: 0 18px 60px rgba(0,0,0,.35);
      --radius:16px;
      --scheme: dark;
      --codeBg: rgba(255,255,255,.06);
      --codeBorder: var(--line);
    }
    *{box-sizing:border-box}
    body{
      margin:0; min-height:100vh; display:grid; place-items:center;
      background:radial-gradient(900px 420px at 20% 10%, var(--glowA), transparent 50%),
                 radial-gradient(700px 420px at 90% 30%, var(--glowB), transparent 55%),
                 linear-gradient(180deg,var(--bg0),var(--bg1));
      color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      padding:20px 12px;
    }
    .shell{width:min(460px, 94vw)}
    .brand{margin-bottom:14px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
    .logo{font-size:26px;font-weight:800;letter-spacing:.2px}
    .sub{color:var(--muted);font-size:13px;margin-top:6px;line-height:1.5}
    .card{
      background:var(--card);
      border:1px solid var(--line);
      border-radius:var(--radius);
      box-shadow:var(--shadow);
      backdrop-filter: blur(10px);
      padding:16px;
    }
    label{display:flex;flex-direction:column;gap:8px;font-size:13px;color:var(--muted);margin-top:12px}
    input{
      border:1px solid var(--line);
      background:var(--inputBg);
      color:var(--text);
      border-radius:12px;
      padding:12px 12px;
      outline:none;
    }
    input:focus{border-color:var(--accentLine); box-shadow: 0 0 0 3px var(--accentBg)}
    .row{display:flex;gap:10px;align-items:center}
    .btn{
      cursor:pointer;
      border:1px solid var(--accentLine);
      background:var(--accentBg);
      color:var(--text);
      border-radius:12px;
      padding:12px 14px;
      width:100%;
      margin-top:14px;
      font-weight:650;
    }
    .btn:hover{background:var(--accentBgHover)}
    .themeBtn{
      cursor:pointer;
      border:1px solid var(--line);
      background:var(--panel);
      color:var(--text);
      border-radius:999px;
      padding:8px 10px;
      font-size:12px;
      white-space:nowrap;
    }
    .themeBtn:hover{border-color:var(--accentLine)}
    .pwWrap{position:relative}
    .pwWrap input{padding-right:46px}
    .pwToggle{
      position:absolute;
      right:8px; top:50%; transform:translateY(-50%);
      border:1px solid var(--line);
      background:var(--panel);
      color:var(--muted);
      border-radius:10px;
      padding:6px 8px;
      cursor:pointer;
      font-size:12px;
    }
    .pwToggle:hover{border-color:var(--accentLine); color:var(--text)}
    .linkRow{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-top:10px}
    .link{
      cursor:pointer;
      border:0;
      background:transparent;
      padding:0;
      color:var(--accent);
      font-size:12px;
      text-decoration:underline;
    }
    .link:hover{opacity:.9}
    .hint{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.5}
    .msg{margin-top:10px;font-size:12px}
    .msg.danger{color:var(--danger)}
    code{background:var(--codeBg);border:1px solid var(--codeBorder);padding:1px 6px;border-radius:10px}
  </style>
</head>
<body>
  <div class="shell">
    <div class="brand">
      <div>
        <div class="logo">SubsTracker</div>
        <div class="sub">记录 ChatGPT / Google Gemini 订阅账号与到期时间，并通过 Resend 邮件提醒。</div>
      </div>
      <button class="themeBtn" id="btnTheme" type="button" title="切换主题">主题</button>
    </div>
    <div class="card">
      <form id="f">
        <div class="hint">首次使用默认账号：<code>admin</code> / <code>password</code>（登录后请到“设置”修改）。</div>
        <label>
          <span>用户名</span>
          <input id="u" autocomplete="username" placeholder="例如：admin" required />
        </label>
        <label>
          <span>密码</span>
          <div class="pwWrap">
            <input id="p" type="password" autocomplete="current-password" placeholder="请输入密码" required />
            <button class="pwToggle" id="toggleP" type="button">显示</button>
          </div>
        </label>
        <button class="btn" type="submit">登录</button>
        <div class="linkRow">
          <button class="link" id="btnForgot" type="button">忘记密码</button>
          <span class="hint">需要先在“设置”里配置收件邮箱</span>
        </div>
        <div id="m" class="msg"></div>
      </form>
    </div>
  </div>
  <script>
    const u = document.getElementById('u');
    const p = document.getElementById('p');
    const m = document.getElementById('m');
    const btnTheme = document.getElementById('btnTheme');
    u.value = localStorage.getItem('subs_username') || 'admin';
    u.addEventListener('change', () => localStorage.setItem('subs_username', u.value.trim()));

    const themes = [
      { key:'night', name:'夜', scheme:'dark', bg0:'#050711', bg1:'#070a14', card:'rgba(18,26,51,.88)', line:'#223059', text:'#e7e9f2', muted:'#aab2d5', panel:'rgba(11,18,40,.55)', inputBg:'#0b1228', accent:'#6aa9ff', accentBg:'rgba(106,169,255,.14)', accentBgHover:'rgba(106,169,255,.18)', accentLine:'rgba(106,169,255,.45)', glowA:'rgba(106,169,255,.18)', glowB:'rgba(255,106,122,.12)' },
      { key:'blue', name:'蓝', scheme:'dark', bg0:'#070a14', bg1:'#0b1020', card:'rgba(18,26,51,.88)', line:'#223059', text:'#e7e9f2', muted:'#aab2d5', panel:'rgba(11,18,40,.55)', inputBg:'#0b1228', accent:'#6aa9ff', accentBg:'rgba(106,169,255,.14)', accentBgHover:'rgba(106,169,255,.18)', accentLine:'rgba(106,169,255,.45)', glowA:'rgba(106,169,255,.18)', glowB:'rgba(255,106,122,.12)' },
      { key:'green', name:'绿', scheme:'dark', bg0:'#06110c', bg1:'#071a14', card:'rgba(16,38,30,.88)', line:'#1b4a35', text:'#e8fff2', muted:'#a8d9bf', panel:'rgba(8,28,20,.55)', inputBg:'#0a1e16', accent:'#72f3b0', accentBg:'rgba(114,243,176,.14)', accentBgHover:'rgba(114,243,176,.18)', accentLine:'rgba(114,243,176,.45)', glowA:'rgba(114,243,176,.16)', glowB:'rgba(106,169,255,.10)' },
      { key:'orange', name:'橙', scheme:'dark', bg0:'#120a06', bg1:'#201008', card:'rgba(42,25,16,.88)', line:'#5a341f', text:'#fff2e8', muted:'#e0c3aa', panel:'rgba(32,18,10,.55)', inputBg:'#1c110a', accent:'#ffb86a', accentBg:'rgba(255,184,106,.14)', accentBgHover:'rgba(255,184,106,.18)', accentLine:'rgba(255,184,106,.45)', glowA:'rgba(255,184,106,.16)', glowB:'rgba(255,106,122,.10)' },
      { key:'purple', name:'紫', scheme:'dark', bg0:'#0a0614', bg1:'#130a22', card:'rgba(24,16,44,.88)', line:'#3a2a66', text:'#f2ecff', muted:'#c9b9ff', panel:'rgba(18,10,40,.55)', inputBg:'#120a28', accent:'#b08cff', accentBg:'rgba(176,140,255,.14)', accentBgHover:'rgba(176,140,255,.18)', accentLine:'rgba(176,140,255,.45)', glowA:'rgba(176,140,255,.18)', glowB:'rgba(255,106,255,.10)' },
      { key:'day', name:'日', scheme:'light', bg0:'#f6f7fb', bg1:'#eef1fb', card:'rgba(255,255,255,.88)', line:'rgba(20,30,55,.14)', text:'#101429', muted:'rgba(20,30,55,.65)', panel:'rgba(255,255,255,.72)', inputBg:'rgba(255,255,255,.90)', accent:'#2f6bff', accentBg:'rgba(47,107,255,.12)', accentBgHover:'rgba(47,107,255,.16)', accentLine:'rgba(47,107,255,.35)', glowA:'rgba(47,107,255,.12)', glowB:'rgba(255,106,122,.10)' },
    ];

    function applyTheme(key) {
      const t = themes.find(x => x.key === key) || themes[0];
      localStorage.setItem('subs_theme', t.key);
      const scheme = t.scheme || 'dark';
      document.documentElement.style.colorScheme = scheme;
      document.documentElement.style.setProperty('--scheme', scheme);
      document.documentElement.style.setProperty('--bg0', t.bg0);
      document.documentElement.style.setProperty('--bg1', t.bg1);
      document.documentElement.style.setProperty('--card', t.card);
      document.documentElement.style.setProperty('--line', t.line);
      document.documentElement.style.setProperty('--text', t.text);
      document.documentElement.style.setProperty('--muted', t.muted);
      document.documentElement.style.setProperty('--panel', t.panel);
      document.documentElement.style.setProperty('--panelSoft', t.panelSoft || t.panel);
      document.documentElement.style.setProperty('--inputBg', t.inputBg);
      document.documentElement.style.setProperty('--codeBg', t.codeBg || (scheme === 'light' ? 'rgba(16,20,41,.06)' : 'rgba(255,255,255,.06)'));
      document.documentElement.style.setProperty('--codeBorder', t.codeBorder || (scheme === 'light' ? 'rgba(16,20,41,.14)' : t.line));
      document.documentElement.style.setProperty('--accent', t.accent);
      document.documentElement.style.setProperty('--accentBg', t.accentBg);
      document.documentElement.style.setProperty('--accentBgHover', t.accentBgHover);
      document.documentElement.style.setProperty('--accentLine', t.accentLine);
      document.documentElement.style.setProperty('--glowA', t.glowA);
      document.documentElement.style.setProperty('--glowB', t.glowB);
      btnTheme.textContent = '主题：' + t.name;
    }

    applyTheme(localStorage.getItem('subs_theme') || 'blue');
    btnTheme.addEventListener('click', () => {
      const cur = localStorage.getItem('subs_theme') || 'blue';
      const idx = Math.max(0, themes.findIndex(x => x.key === cur));
      const next = themes[(idx + 1) % themes.length].key;
      applyTheme(next);
    });

    document.getElementById('toggleP').addEventListener('click', () => {
      const isPw = p.type === 'password';
      p.type = isPw ? 'text' : 'password';
      document.getElementById('toggleP').textContent = isPw ? '隐藏' : '显示';
      p.focus();
    });

    document.getElementById('btnForgot').addEventListener('click', async () => {
      const username = u.value.trim() || 'admin';
      if (!confirm('将会发送一封邮件到已配置的收件邮箱，并重置管理员密码。继续？')) return;
      m.textContent = '';
      m.className = 'msg';
      const res = await fetch('/api/forgot', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        m.textContent = data.error || ('HTTP ' + res.status);
        m.className = 'msg danger';
        return;
      }
      m.textContent = '已发送重置邮件，请查收（id: ' + (data.id || 'ok') + '）';
    });

    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      m.textContent = '';
      m.className = 'msg';
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: u.value.trim(), password: p.value })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        m.textContent = data.error || ('HTTP ' + res.status);
        m.className = 'msg danger';
        return;
      }
      window.location.href = '/admin';
    });
  </script>
</body>
</html>`;
}

function adminPageHtml() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>SubsTracker</title>
  <style>
    :root{
      --bg0:#070a14; --bg1:#0b1020; --card:rgba(18,26,51,.86); --line:#223059;
      --text:#e7e9f2; --muted:#aab2d5; --accent:#6aa9ff; --danger:#ff6a7a; --warn:#ffd36a; --ok:#72f3b0;
      --accentBg: rgba(106,169,255,.14);
      --accentBgHover: rgba(106,169,255,.18);
      --accentLine: rgba(106,169,255,.45);
      --glowA: rgba(106,169,255,.18);
      --glowB: rgba(255,106,122,.12);
      --rowHover: rgba(106,169,255,.06);
      --panel: rgba(11,18,40,.55);
      --panelSoft: rgba(11,18,40,.35);
      --inputBg: #0b1228;
      --tableBg: rgba(11,18,40,.18);
      --tableLine: rgba(34,48,89,.65);
      --dateIconFilter: invert(1) brightness(1.25) contrast(1.05) opacity(.98);
      --dateIconBg: rgba(255,255,255,.14);
      --dateIconBorder: rgba(255,255,255,.22);
      --dateIconShadow: 0 6px 18px rgba(0,0,0,.35);
      --shadow: 0 18px 60px rgba(0,0,0,.35);
      --radius:14px;
      --scheme: dark;
      --pillBg: rgba(11,18,40,.35);
      --codeBg: rgba(255,255,255,.06);
      --codeBorder: var(--line);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      background:radial-gradient(900px 420px at 20% 10%, var(--glowA), transparent 50%),
                 radial-gradient(700px 420px at 90% 30%, var(--glowB), transparent 55%),
                 linear-gradient(180deg,var(--bg0),var(--bg1));
      color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    }
    .wrap{max-width:1180px;margin:0 auto;padding:18px 14px 60px}
    .top{
      display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
      position:sticky;top:0;z-index:3;padding:14px 0;
      backdrop-filter: blur(10px);
    }
    .brand{display:flex;flex-direction:column;gap:6px}
    .logo{font-size:20px;font-weight:800;letter-spacing:.2px}
    .sub{color:var(--muted);font-size:12px}
    .nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .tabs{display:flex;gap:8px;align-items:center}
    .tab{
      cursor:pointer;
      padding:9px 12px;
      border-radius:999px;
      border:1px solid var(--line);
      color:var(--muted);
      background:var(--panel);
      user-select:none;
    }
    .tab.active{
      color:var(--text);
      border-color:var(--accentLine);
      background:var(--accentBg);
    }
    .btn{
      cursor:pointer;
      border:1px solid var(--line);
      background:var(--panel);
      color:var(--text);
      border-radius:12px;
      padding:10px 12px;
    }
    .btn.sm{padding:7px 10px;border-radius:999px;font-size:12px}
    .btn:hover{border-color:var(--accentLine)}
    .btn.primary{border-color:var(--accentLine);background:var(--accentBg)}
    .btn.primary:hover{background:var(--accentBgHover)}
    .btn.danger{border-color:rgba(255,106,122,.45);background:rgba(255,106,122,.10)}
    .btn.ghost{background:transparent}
    .card{
      background:var(--card);
      border:1px solid var(--line);
      border-radius:var(--radius);
      box-shadow:var(--shadow);
      backdrop-filter: blur(10px);
      padding:14px;
      margin-top:14px;
    }
    .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
    .col-12{grid-column:span 12}
    .col-6{grid-column:span 6}
    .col-4{grid-column:span 4}
    .col-3{grid-column:span 3}
    .col-2{grid-column:span 2}
    @media (max-width: 860px){
      .col-6,.col-4,.col-3,.col-2{grid-column:span 12}
    }
    .field{display:flex;flex-direction:column;gap:8px}
    .label{font-size:12px;color:var(--muted)}
    input,select{
      border:1px solid var(--line);
      background:var(--inputBg);
      color:var(--text);
      border-radius:12px;
      padding:11px 12px;
      outline:none;
      width:100%;
    }
    input[type="date"]{color-scheme: var(--scheme)}
    input[type="date"]::-webkit-calendar-picker-indicator{
      cursor:pointer;
      filter: var(--dateIconFilter);
      background: var(--dateIconBg);
      border: 1px solid var(--dateIconBorder);
      border-radius: 10px;
      padding: 6px;
      opacity: 1;
      box-shadow: var(--dateIconShadow);
    }
    input[type="date"]::-webkit-calendar-picker-indicator:hover{opacity:1; border-color: var(--accentLine)}
    .pwWrap{position:relative}
    .pwWrap input{padding-right:46px}
    .pwToggle{
      position:absolute;
      right:8px; top:50%; transform:translateY(-50%);
      border:1px solid var(--line);
      background:var(--panel);
      color:var(--muted);
      border-radius:10px;
      padding:6px 8px;
      cursor:pointer;
      font-size:12px;
    }
    .pwToggle:hover{border-color:var(--accentLine); color:var(--text)}
    input:focus,select:focus{border-color:var(--accentLine); box-shadow: 0 0 0 3px var(--accentBg)}
    .hint{font-size:12px;color:var(--muted);line-height:1.5}
    .status{font-size:12px;line-height:1.5}
    .status.ok{color:var(--ok)}
    .status.bad{color:var(--danger)}
    .status.warn{color:var(--warn)}
    .toolbar{display:flex;gap:10px;align-items:end;flex-wrap:wrap}
    .pill{
      display:inline-flex;align-items:center;gap:6px;
      padding:4px 10px;border-radius:999px;border:1px solid var(--line);
      color:var(--muted);font-size:12px;background:var(--pillBg)
    }
    .tableWrap{overflow:auto;border:1px solid var(--line);border-radius:14px}
    table{width:100%;border-collapse:separate;border-spacing:0;min-width:860px;background:var(--tableBg)}
    th,td{padding:12px 10px;border-bottom:1px solid var(--tableLine);text-align:left;font-size:13px;vertical-align:top}
    th{color:var(--muted);font-weight:650;background:var(--panel);position:sticky;top:0}
    tr:hover td{background:var(--rowHover)}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    .kpi{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .right{margin-left:auto}
    code{background:var(--codeBg);border:1px solid var(--codeBorder);padding:1px 6px;border-radius:10px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="brand">
        <div class="logo">SubsTracker</div>
        <div class="sub">更安全的做法：建议把 Worker 放在私有域名或 Cloudflare Access 保护下。</div>
      </div>
      <div class="nav">
        <div class="tabs">
          <div class="tab active" id="tabRecords">订阅</div>
          <div class="tab" id="tabSettings">设置</div>
        </div>
        <button class="btn" id="btnTheme" type="button" title="切换主题">主题</button>
        <button class="btn ghost" id="btnLogout">退出登录</button>
      </div>
    </div>

    <div class="card">
      <div id="status" class="status"></div>
    </div>

    <div id="viewRecords">
      <div class="card">
        <div class="kpi">
          <span class="pill">列表数：<span id="count" class="mono">0</span></span>
          <span class="pill">提醒阈值：<span id="remindBadge" class="mono">7</span> 天</span>
          <div class="right field" style="min-width:280px">
            <span class="label">搜索（平台/账号/备注）</span>
            <input id="q" placeholder="例如：chatgpt / gmail / Plus" />
          </div>
        </div>
        <div class="hint" style="margin-top:10px">日期支持点选日历或手动输入，格式：<code>YYYY-MM-DD</code></div>
      </div>

      <div class="card">
        <div class="toolbar">
          <div class="grid col-12" style="width:100%">
            <label class="field col-3">
              <span class="label">平台</span>
              <select id="provider">
                <option value="chatgpt">ChatGPT</option>
                <option value="gemini">Google Gemini</option>
                <option value="other">Other</option>
              </select>
            </label>
            <label class="field col-3">
              <span class="label">账号/邮箱</span>
              <input id="account" placeholder="例如：a@example.com" required />
            </label>
            <label class="field col-2">
              <span class="label">开通日期</span>
              <input id="startedAt" type="date" required />
            </label>
            <label class="field col-2">
              <span class="label">到期日期</span>
              <input id="expiresAt" type="date" required />
            </label>
            <label class="field col-2">
              <span class="label">备注</span>
              <input id="note" placeholder="例如：Plus / Pro / 年付" />
            </label>
          </div>
          <div class="toolbar" style="align-items:center">
            <span class="label">快速设置到期（基于开通日期）</span>
            <button class="btn sm" type="button" data-exp="7d">+1周</button>
            <button class="btn sm" type="button" data-exp="1m">+1月</button>
            <button class="btn sm" type="button" data-exp="3m">+3月</button>
            <button class="btn sm" type="button" data-exp="1y">+1年</button>
            <span class="hint">未填写开通日期时默认用今天</span>
          </div>
          <div class="toolbar">
            <button class="btn primary" id="btnSave">保存（新增/修改）</button>
            <button class="btn" id="btnCancel" style="display:none">取消编辑</button>
            <button class="btn" id="btnRefresh">刷新列表</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="grid">
          <div class="col-12">
            <div class="hint">导入/导出：CSV 支持带表头或不带表头，列顺序：<code>provider,account,startedAt,expiresAt,note</code></div>
          </div>
          <div class="col-12 toolbar">
            <button class="btn" id="btnExportJson">导出 JSON</button>
            <button class="btn" id="btnExportCsv">导出 CSV</button>
            <label class="field" style="min-width:260px">
              <span class="label">选择导入文件（.json/.csv）</span>
              <input id="file" type="file" accept=".json,.csv,application/json,text/csv" />
            </label>
            <label class="field" style="min-width:170px">
              <span class="label">导入模式</span>
              <select id="importMode">
                <option value="merge">merge（合并/更新）</option>
                <option value="replace">replace（覆盖）</option>
              </select>
            </label>
            <button class="btn primary" id="btnImport">导入</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="tableWrap">
          <table>
            <thead>
              <tr>
                <th style="width:120px">平台</th>
                <th>账号</th>
                <th style="width:140px">开通</th>
                <th style="width:140px">到期</th>
                <th style="width:110px">剩余</th>
                <th>备注</th>
                <th style="width:140px">操作</th>
              </tr>
            </thead>
            <tbody id="tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="viewSettings" style="display:none">
      <div class="card">
        <div class="grid">
          <div class="col-12">
            <div class="hint">自动提醒需要 Cloudflare Cron（UTC）：<code>0 0 * * *</code>（北京 08:00）和 <code>0 12 * * *</code>（北京 20:00）</div>
          </div>
          <label class="field col-4">
            <span class="label">管理员用户名</span>
            <input id="cfgUser" placeholder="例如：admin" />
          </label>
          <label class="field col-4">
            <span class="label">新密码（不改留空）</span>
            <div class="pwWrap">
              <input id="cfgPass1" type="password" placeholder="留空则不修改" />
              <button class="pwToggle" id="toggleCfgPass" type="button">显示</button>
            </div>
          </label>
          <label class="field col-4">
            <span class="label">确认新密码</span>
            <div class="pwWrap">
              <input id="cfgPass2" type="password" placeholder="再输入一次以确认" />
            </div>
          </label>
        </div>
      </div>

      <div class="card">
        <div class="grid">
          <div class="col-12">
            <div class="hint">Resend：发件人必须是你在 Resend 验证过的域名/邮箱；API Key 不会回显，想更新就重新填写。</div>
          </div>
          <label class="field col-4">
            <span class="label">Resend API Key（不回显，填写才会更新）</span>
            <input id="cfgResendKey" type="password" placeholder="re_..." />
          </label>
          <label class="field col-4">
            <span class="label">发件人（EMAIL_FROM）</span>
            <input id="cfgFrom" placeholder="SubsTracker <no-reply@yourdomain.com>" />
          </label>
          <label class="field col-4">
            <span class="label">收件人（EMAIL_TO，逗号分隔）</span>
            <input id="cfgTo" placeholder="a@xx.com,b@yy.com" />
          </label>
        </div>
      </div>

      <div class="card">
        <div class="grid">
          <label class="field col-3">
            <span class="label">提前提醒天数（REMIND_DAYS）</span>
            <input id="cfgRemind" type="number" min="0" step="1" placeholder="7" />
          </label>
          <label class="field col-3">
            <span class="label">过期提醒窗口天数（EXPIRED_DAYS，0=不提醒过期）</span>
            <input id="cfgExpired" type="number" min="0" step="1" placeholder="30" />
          </label>
          <label class="field col-3">
            <span class="label">邮件标题前缀</span>
            <input id="cfgPrefix" placeholder="[SubsTracker]" />
          </label>
          <div class="col-12 toolbar">
            <button class="btn primary" id="btnSaveCfg">保存设置</button>
            <button class="btn" id="btnTestEmail">测试邮件（强制发送）</button>
            <button class="btn" id="btnRunEmail">立即检查（有到期才发）</button>
          </div>
          <div class="col-12 hint" id="cfgHint"></div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const $ = (id) => document.getElementById(id);
    const btnTheme = $('btnTheme');
    let editingId = null;
    let recordsCache = [];
    let configCache = { remindDays: 7 };

    const themes = [
      {
        key: 'night',
        name: '夜',
        scheme: 'dark',
        bg0: '#050711',
        bg1: '#070a14',
        card: 'rgba(18,26,51,.86)',
        line: '#223059',
        text: '#e7e9f2',
        muted: '#aab2d5',
        panel: 'rgba(11,18,40,.55)',
        panelSoft: 'rgba(11,18,40,.35)',
        inputBg: '#0b1228',
        tableBg: 'rgba(11,18,40,.18)',
        dateIconFilter: 'invert(1) brightness(1.25) contrast(1.05) opacity(.98)',
        dateIconBg: 'rgba(255,255,255,.14)',
        dateIconBorder: 'rgba(255,255,255,.22)',
        accent: '#6aa9ff',
        accentBg: 'rgba(106,169,255,.14)',
        accentBgHover: 'rgba(106,169,255,.18)',
        accentLine: 'rgba(106,169,255,.45)',
        glowA: 'rgba(106,169,255,.18)',
        glowB: 'rgba(255,106,122,.12)',
        rowHover: 'rgba(106,169,255,.06)',
      },
      {
        key: 'blue',
        name: '蓝',
        scheme: 'dark',
        bg0: '#070a14',
        bg1: '#0b1020',
        card: 'rgba(18,26,51,.86)',
        line: '#223059',
        text: '#e7e9f2',
        muted: '#aab2d5',
        panel: 'rgba(11,18,40,.55)',
        panelSoft: 'rgba(11,18,40,.35)',
        inputBg: '#0b1228',
        tableBg: 'rgba(11,18,40,.18)',
        dateIconFilter: 'invert(1) brightness(1.25) contrast(1.05) opacity(.98)',
        dateIconBg: 'rgba(255,255,255,.14)',
        dateIconBorder: 'rgba(255,255,255,.22)',
        accent: '#6aa9ff',
        accentBg: 'rgba(106,169,255,.14)',
        accentBgHover: 'rgba(106,169,255,.18)',
        accentLine: 'rgba(106,169,255,.45)',
        glowA: 'rgba(106,169,255,.18)',
        glowB: 'rgba(255,106,122,.12)',
        rowHover: 'rgba(106,169,255,.06)',
      },
      {
        key: 'green',
        name: '绿',
        scheme: 'dark',
        bg0: '#06110c',
        bg1: '#071a14',
        card: 'rgba(16,38,30,.86)',
        line: '#1b4a35',
        text: '#e8fff2',
        muted: '#a8d9bf',
        panel: 'rgba(8,28,20,.55)',
        panelSoft: 'rgba(8,28,20,.35)',
        inputBg: '#0a1e16',
        tableBg: 'rgba(8,28,20,.22)',
        dateIconFilter: 'invert(1) brightness(1.25) contrast(1.05) opacity(.98)',
        dateIconBg: 'rgba(255,255,255,.14)',
        dateIconBorder: 'rgba(255,255,255,.22)',
        accent: '#72f3b0',
        accentBg: 'rgba(114,243,176,.14)',
        accentBgHover: 'rgba(114,243,176,.18)',
        accentLine: 'rgba(114,243,176,.45)',
        glowA: 'rgba(114,243,176,.16)',
        glowB: 'rgba(106,169,255,.10)',
        rowHover: 'rgba(114,243,176,.06)',
      },
      {
        key: 'orange',
        name: '橙',
        scheme: 'dark',
        bg0: '#120a06',
        bg1: '#201008',
        card: 'rgba(42,25,16,.86)',
        line: '#5a341f',
        text: '#fff2e8',
        muted: '#e0c3aa',
        panel: 'rgba(32,18,10,.55)',
        panelSoft: 'rgba(32,18,10,.35)',
        inputBg: '#1c110a',
        tableBg: 'rgba(32,18,10,.22)',
        dateIconFilter: 'invert(1) brightness(1.25) contrast(1.05) opacity(.98)',
        dateIconBg: 'rgba(255,255,255,.16)',
        dateIconBorder: 'rgba(255,255,255,.24)',
        accent: '#ffb86a',
        accentBg: 'rgba(255,184,106,.14)',
        accentBgHover: 'rgba(255,184,106,.18)',
        accentLine: 'rgba(255,184,106,.45)',
        glowA: 'rgba(255,184,106,.16)',
        glowB: 'rgba(255,106,122,.10)',
        rowHover: 'rgba(255,184,106,.06)',
      },
      {
        key: 'purple',
        name: '紫',
        scheme: 'dark',
        bg0: '#0a0614',
        bg1: '#130a22',
        card: 'rgba(24,16,44,.86)',
        line: '#3a2a66',
        text: '#f2ecff',
        muted: '#c9b9ff',
        panel: 'rgba(18,10,40,.55)',
        panelSoft: 'rgba(18,10,40,.35)',
        inputBg: '#120a28',
        tableBg: 'rgba(18,10,40,.20)',
        dateIconFilter: 'invert(1) brightness(1.25) contrast(1.05) opacity(.98)',
        dateIconBg: 'rgba(255,255,255,.16)',
        dateIconBorder: 'rgba(255,255,255,.24)',
        accent: '#b08cff',
        accentBg: 'rgba(176,140,255,.14)',
        accentBgHover: 'rgba(176,140,255,.18)',
        accentLine: 'rgba(176,140,255,.45)',
        glowA: 'rgba(176,140,255,.18)',
        glowB: 'rgba(255,106,255,.10)',
        rowHover: 'rgba(176,140,255,.06)',
      },
      {
        key: 'day',
        name: '日',
        scheme: 'light',
        bg0: '#f6f7fb',
        bg1: '#eef1fb',
        card: 'rgba(255,255,255,.88)',
        line: 'rgba(20,30,55,.14)',
        text: '#101429',
        muted: 'rgba(20,30,55,.65)',
        panel: 'rgba(255,255,255,.72)',
        panelSoft: 'rgba(255,255,255,.55)',
        inputBg: 'rgba(255,255,255,.90)',
        tableBg: 'rgba(255,255,255,.62)',
        dateIconFilter: 'invert(0) opacity(.85)',
        dateIconBg: 'rgba(16,20,41,.06)',
        dateIconBorder: 'rgba(16,20,41,.14)',
        accent: '#2f6bff',
        accentBg: 'rgba(47,107,255,.12)',
        accentBgHover: 'rgba(47,107,255,.16)',
        accentLine: 'rgba(47,107,255,.35)',
        glowA: 'rgba(47,107,255,.12)',
        glowB: 'rgba(255,106,122,.10)',
        rowHover: 'rgba(47,107,255,.05)',
      },
    ];

    function applyTheme(key) {
      const t = themes.find(x => x.key === key) || themes[0];
      localStorage.setItem('subs_theme', t.key);
      const scheme = t.scheme || 'dark';
      document.documentElement.style.colorScheme = scheme;
      document.documentElement.style.setProperty('--scheme', scheme);
      document.documentElement.style.setProperty('--bg0', t.bg0);
      document.documentElement.style.setProperty('--bg1', t.bg1);
      document.documentElement.style.setProperty('--card', t.card);
      document.documentElement.style.setProperty('--line', t.line);
      document.documentElement.style.setProperty('--text', t.text);
      document.documentElement.style.setProperty('--muted', t.muted);
      document.documentElement.style.setProperty('--panel', t.panel);
      document.documentElement.style.setProperty('--panelSoft', t.panelSoft || t.panel);
      document.documentElement.style.setProperty('--inputBg', t.inputBg);
      document.documentElement.style.setProperty('--tableBg', t.tableBg);
      document.documentElement.style.setProperty('--tableLine', t.tableLine || (scheme === 'light' ? 'rgba(16,20,41,.10)' : 'rgba(34,48,89,.65)'));
      document.documentElement.style.setProperty('--dateIconFilter', t.dateIconFilter);
      document.documentElement.style.setProperty('--dateIconBg', t.dateIconBg);
      document.documentElement.style.setProperty('--dateIconBorder', t.dateIconBorder);
      document.documentElement.style.setProperty('--dateIconShadow', t.dateIconShadow || (scheme === 'light' ? '0 6px 18px rgba(16,20,41,.12)' : '0 6px 18px rgba(0,0,0,.35)'));
      document.documentElement.style.setProperty('--accent', t.accent);
      document.documentElement.style.setProperty('--accentBg', t.accentBg);
      document.documentElement.style.setProperty('--accentBgHover', t.accentBgHover);
      document.documentElement.style.setProperty('--accentLine', t.accentLine);
      document.documentElement.style.setProperty('--glowA', t.glowA);
      document.documentElement.style.setProperty('--glowB', t.glowB);
      document.documentElement.style.setProperty('--rowHover', t.rowHover);
      document.documentElement.style.setProperty('--pillBg', t.pillBg || t.panelSoft || t.panel);
      document.documentElement.style.setProperty('--codeBg', t.codeBg || (scheme === 'light' ? 'rgba(16,20,41,.06)' : 'rgba(255,255,255,.06)'));
      document.documentElement.style.setProperty('--codeBorder', t.codeBorder || (scheme === 'light' ? 'rgba(16,20,41,.14)' : t.line));
      if (btnTheme) btnTheme.textContent = '主题：' + t.name;
    }

    applyTheme(localStorage.getItem('subs_theme') || 'blue');
    if (btnTheme) {
      btnTheme.addEventListener('click', () => {
        const cur = localStorage.getItem('subs_theme') || 'blue';
        const idx = Math.max(0, themes.findIndex(x => x.key === cur));
        applyTheme(themes[(idx + 1) % themes.length].key);
      });
    }

    function setStatus(msg, level) {
      const el = $('status');
      el.textContent = msg || '';
      el.className = 'status ' + (level || '');
    }

    async function api(path, opts = {}) {
      const r = await fetch(path, opts);
      const ct = r.headers.get('content-type') || '';
      const b = ct.includes('application/json') ? await r.json() : await r.text();
      if (r.status === 401) {
        setStatus('登录已失效，请重新登录', 'warn');
        setTimeout(() => (window.location.href = '/login'), 150);
        throw new Error(b?.error || b || 'Unauthorized');
      }
      if (!r.ok) throw new Error(b?.error || b || ('HTTP ' + r.status));
      return b;
    }

    function esc(s) {
      return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
    }

    function ymdToUtc(ymd) {
      if (!ymd) return null;
      const d = new Date(ymd + 'T00:00:00.000Z');
      return isNaN(d.getTime()) ? null : d;
    }

    function daysLeft(expiresAt) {
      const end = ymdToUtc(expiresAt);
      if (!end) return null;
      const now = new Date();
      const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      return Math.floor((end.getTime() - today.getTime()) / 86400000);
    }

    function todayYmdUtc() {
      const now = new Date();
      const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      return today.toISOString().slice(0, 10);
    }

    function addToYmd(baseYmd, { days = 0, months = 0, years = 0 } = {}) {
      const base = ymdToUtc(baseYmd) || ymdToUtc(todayYmdUtc());
      const d = new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth(), base.getUTCDate()));
      if (years) d.setUTCFullYear(d.getUTCFullYear() + years);
      if (months) d.setUTCMonth(d.getUTCMonth() + months);
      if (days) d.setUTCDate(d.getUTCDate() + days);
      return d.toISOString().slice(0, 10);
    }

    function applyExpiryPreset(preset) {
      if (!$('startedAt').value) $('startedAt').value = todayYmdUtc();
      const base = $('startedAt').value;
      let next;
      if (preset === '7d') next = addToYmd(base, { days: 7 });
      else if (preset === '1m') next = addToYmd(base, { months: 1 });
      else if (preset === '3m') next = addToYmd(base, { months: 3 });
      else if (preset === '1y') next = addToYmd(base, { years: 1 });
      else return;
      $('expiresAt').value = next;
      setStatus('已快速设置到期日期：' + next, 'ok');
    }

    function applyFilter() {
      const q = ($('q').value || '').trim().toLowerCase();
      if (!q) return recordsCache;
      return recordsCache.filter((r) => {
        const s = [r.provider, r.account, r.note].join(' ').toLowerCase();
        return s.includes(q);
      });
    }

    function renderTable() {
      const rows = applyFilter();
      $('count').textContent = String(rows.length);
      const remind = Number(configCache.remindDays || 7);
      const body = rows.map((r) => {
        const left = daysLeft(r.expiresAt);
        const leftText = left == null ? '-' : (left + ' 天');
        const leftClass = left == null ? '' : (left < 0 ? 'dangerText' : (left <= remind ? 'warnText' : ''));
        const note = esc(r.note || '');
        return '<tr>' +
          '<td><span class="pill mono">' + esc(r.provider) + '</span></td>' +
          '<td class="mono">' + esc(r.account) + '</td>' +
          '<td class="mono">' + esc(r.startedAt) + '</td>' +
          '<td class="mono">' + esc(r.expiresAt) + '</td>' +
          '<td class="' + leftClass + ' mono">' + esc(leftText) + '</td>' +
          '<td>' + note + '</td>' +
          '<td>' +
            '<button class="btn" data-e="' + r.id + '">编辑</button> ' +
            '<button class="btn danger" data-d="' + r.id + '">删除</button>' +
          '</td>' +
        '</tr>';
      }).join('');
      $('tbody').innerHTML = body || '<tr><td colspan="7" class="hint">暂无记录</td></tr>';

      $('tbody').querySelectorAll('button[data-d]').forEach((b) => b.onclick = async () => {
        if (!confirm('确认删除？')) return;
        await api('/api/records/' + b.dataset.d, { method: 'DELETE' });
        await load();
        setStatus('已删除', 'ok');
      });
      $('tbody').querySelectorAll('button[data-e]').forEach((b) => b.onclick = () => {
        const r = recordsCache.find((x) => x.id === b.dataset.e);
        if (!r) return;
        editingId = r.id;
        $('provider').value = r.provider || 'chatgpt';
        $('account').value = r.account || '';
        $('startedAt').value = r.startedAt || '';
        $('expiresAt').value = r.expiresAt || '';
        $('note').value = r.note || '';
        $('btnCancel').style.display = '';
        setStatus('编辑中：修改后点“保存（新增/修改）”', 'warn');
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
    }

    async function load() {
      const d = await api('/api/records');
      recordsCache = d.records || [];
      renderTable();
    }

    async function loadConfig() {
      const c = await api('/api/config');
      configCache = c;
      $('cfgUser').value = c.adminUsername || 'admin';
      $('cfgFrom').value = c.emailFrom || '';
      $('cfgTo').value = c.emailTo || '';
      $('cfgRemind').value = String(c.remindDays ?? 7);
      $('cfgExpired').value = String(c.expiredDays ?? 30);
      $('cfgPrefix').value = c.emailSubjectPrefix || '[SubsTracker]';
      $('cfgHint').textContent = c.resendConfigured ? 'Resend 已配置（API Key 不回显）' : 'Resend 未配置（需要填写 API Key 才能发邮件）';
      $('remindBadge').textContent = String(c.remindDays ?? 7);
    }

    function download(name, content, type) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    }

    $('q').addEventListener('input', () => renderTable());

    document.querySelectorAll('button[data-exp]').forEach((b) => {
      b.addEventListener('click', () => applyExpiryPreset(b.dataset.exp));
    });

    const toggleCfgPass = $('toggleCfgPass');
    if (toggleCfgPass) {
      toggleCfgPass.addEventListener('click', () => {
        const p1 = $('cfgPass1');
        const p2 = $('cfgPass2');
        const show = p1.type === 'password';
        p1.type = show ? 'text' : 'password';
        p2.type = show ? 'text' : 'password';
        toggleCfgPass.textContent = show ? '隐藏' : '显示';
        p1.focus();
      });
    }

    $('btnRefresh').onclick = async () => {
      try { await load(); setStatus('已刷新', 'ok'); } catch (e) { setStatus(e.message, 'bad'); }
    };

    $('btnSave').onclick = async () => {
      try {
        const payload = {
          provider: $('provider').value,
          account: $('account').value,
          startedAt: $('startedAt').value,
          expiresAt: $('expiresAt').value,
          note: $('note').value
        };
        if (editingId) {
          await api('/api/records/' + editingId, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
        } else {
          await api('/api/records', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
        }
        editingId = null;
        $('btnCancel').style.display = 'none';
        $('account').value = ''; $('note').value = '';
        await load();
        setStatus('已保存', 'ok');
      } catch (e) {
        setStatus(e.message, 'bad');
      }
    };

    $('btnCancel').onclick = () => {
      editingId = null;
      $('btnCancel').style.display = 'none';
      $('account').value = ''; $('note').value = '';
      setStatus('已取消编辑', '');
    };

    $('btnExportJson').onclick = async () => {
      const d = await api('/api/export?format=json');
      download('subs-export.json', JSON.stringify(d.records, null, 2), 'application/json');
    };
    $('btnExportCsv').onclick = async () => {
      const csv = await api('/api/export?format=csv');
      download('subs-export.csv', csv, 'text/csv');
    };
    $('btnImport').onclick = async () => {
      const f = $('file').files[0];
      if (!f) return setStatus('请选择文件', 'warn');
      const mode = $('importMode').value;
      const t = await f.text();
      const format = f.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json';
      try {
        const r = await api('/api/import?format=' + format + '&mode=' + mode, { method: 'POST', headers: { 'content-type': 'text/plain; charset=utf-8' }, body: t });
        await load();
        setStatus('导入完成：新增 ' + r.added + '，更新 ' + (r.updated || 0) + '，忽略 ' + r.skipped, 'ok');
      } catch (e) {
        setStatus(e.message, 'bad');
      }
    };

    $('btnSaveCfg').onclick = async () => {
      try {
        const pass1 = $('cfgPass1').value;
        const pass2 = $('cfgPass2').value;
        if (pass1 || pass2) {
          if (pass1 !== pass2) {
            setStatus('两次输入的新密码不一致，请检查。', 'bad');
            return;
          }
        }
        const payload = {
          adminUsername: $('cfgUser').value.trim(),
          adminPasswordNew: pass1,
          adminPasswordNewConfirm: pass2,
          resendApiKey: $('cfgResendKey').value,
          emailFrom: $('cfgFrom').value.trim(),
          emailTo: $('cfgTo').value.trim(),
          remindDays: $('cfgRemind').value,
          expiredDays: $('cfgExpired').value,
          emailSubjectPrefix: $('cfgPrefix').value.trim()
        };
        const resp = await api('/api/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
        $('cfgPass1').value = '';
        $('cfgPass2').value = '';
        $('cfgResendKey').value = '';
        if (resp?.reloginRequired) {
          setStatus('账号/密码已更新：已强制退出，请重新登录', 'warn');
          setTimeout(() => (window.location.href = '/login'), 600);
          return;
        }
        await loadConfig();
        if (resp?.mail && resp.mail.sent === false) setStatus('设置已保存，但邮件通知发送失败：' + (resp.mail.error || ''), 'warn');
        else if (resp?.mail && resp.mail.sent === true) setStatus('设置已保存，邮件通知已发送（id: ' + (resp.mail.id || 'ok') + '）', 'ok');
        else setStatus('设置已保存', 'ok');
      } catch (e) {
        setStatus(e.message, 'bad');
      }
    };
    $('btnTestEmail').onclick = async () => {
      try {
        const r = await api('/api/remind/test', { method: 'POST' });
        setStatus('测试邮件：' + (r.id || r.reason || 'ok'), 'ok');
      } catch (e) {
        setStatus(e.message, 'bad');
      }
    };
    $('btnRunEmail').onclick = async () => {
      try {
        const r = await api('/api/remind/run', { method: 'POST' });
        if (r.skipped) setStatus('未发送：' + (r.reason || '无到期/过期记录'), 'warn');
        else setStatus('已发送：' + (r.resend?.id || 'ok'), 'ok');
      } catch (e) {
        setStatus(e.message, 'bad');
      }
    };
    $('btnLogout').onclick = async () => {
      await api('/api/logout', { method: 'POST' }).catch(() => {});
      window.location.href = '/login';
    };

    function show(tab) {
      const isRecords = tab === 'records';
      $('viewRecords').style.display = isRecords ? '' : 'none';
      $('viewSettings').style.display = isRecords ? 'none' : '';
      $('tabRecords').classList.toggle('active', isRecords);
      $('tabSettings').classList.toggle('active', !isRecords);
    }

    $('tabRecords').onclick = () => show('records');
    $('tabSettings').onclick = async () => { show('settings'); await loadConfig(); };

    (async () => {
      try {
        await loadConfig();
        await load();
        setStatus('已加载', 'ok');
      } catch (e) {
        setStatus(e.message, 'bad');
      }
    })();

    async function heartbeat() {
      try {
        const r = await fetch('/api/config', { cache: 'no-store' });
        if (r.status === 401) window.location.href = '/login';
      } catch {}
    }
    setInterval(heartbeat, 60 * 1000);
  </script>
  <style>
    .dangerText{color:var(--danger)}
    .warnText{color:var(--warn)}
  </style>
</body>
</html>`;
}

function debugMissingKvHtml() {
  return `<!doctype html><html><head><meta charset="utf-8"/></head><body style="font-family:system-ui;padding:16px">
  <h2>KV 未绑定</h2>
  <p>请在 Worker 设置里绑定 KV：Variable name 填 <code>SUBS_KV</code>。</p>
</body></html>`;
}

async function handleLogin(request, env) {
  const config = await ensureConfig(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest("Invalid JSON.");
  }
  const username = String(body?.username || "").trim();
  const password = String(body?.password || "");
  if (!username || !password) return badRequest("Missing username/password.");
  const gotHash = await hashPassword(password, String(config.adminPasswordSalt || ""));
  if (username !== String(config.adminUsername || "admin") || gotHash !== String(config.adminPasswordHash || "")) return unauthorized();
  const { token, ttlSeconds } = await createSession(env, username, Number(config.authVersion || 1));
  const secure = new URL(request.url).protocol === "https:";
  const cookie = setCookieHeader("session", token, { maxAge: ttlSeconds, httpOnly: true, sameSite: "Lax", secure, path: "/" });
  return json({ ok: true }, { headers: { "set-cookie": cookie } });
}

async function handleLogout(request, env) {
  const token = getCookieValue(request.headers.get("cookie"), "session");
  await destroySession(env, token);
  const cookie = clearSessionCookieHeader(request);
  return json({ ok: true }, { headers: { "set-cookie": cookie } });
}

async function handleGetConfig(env) {
  const config = await ensureConfig(env);
  return json({
    ok: true,
    adminUsername: config.adminUsername || "admin",
    remindDays: config.remindDays ?? 7,
    expiredDays: config.expiredDays ?? 30,
    emailSubjectPrefix: config.emailSubjectPrefix || "[SubsTracker]",
    emailFrom: config.emailFrom || "",
    emailTo: config.emailTo || "",
    resendConfigured: !!config.resendApiKey,
  });
}

async function handleUpdateConfig(request, env) {
  const config = await ensureConfig(env);
  const previousUsername = String(config.adminUsername || "admin");
  const previousAuthVersion = Number(config.authVersion || 1);
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest("Invalid JSON.");
  }
  const adminUsername = String(body?.adminUsername || "").trim() || "admin";
  const adminPasswordNew = String(body?.adminPasswordNew || "");
  const adminPasswordNewConfirm = String(body?.adminPasswordNewConfirm || "");
  const resendApiKey = String(body?.resendApiKey || "").trim();
  const emailFrom = String(body?.emailFrom || "").trim();
  const emailTo = String(body?.emailTo || "").trim();
  const remindDaysRaw = String(body?.remindDays ?? "").trim();
  const expiredDaysRaw = String(body?.expiredDays ?? "").trim();
  const prefixRaw = String(body?.emailSubjectPrefix ?? "").trim();
  const remindDays = remindDaysRaw ? Number.parseInt(remindDaysRaw, 10) : Number(config.remindDays ?? 7);
  const expiredDays = expiredDaysRaw ? Number.parseInt(expiredDaysRaw, 10) : Number(config.expiredDays ?? 30);
  const emailSubjectPrefix = prefixRaw || String(config.emailSubjectPrefix ?? "[SubsTracker]").trim();
  if (!Number.isFinite(remindDays) || remindDays < 0) return badRequest("Invalid remindDays.");
  if (!Number.isFinite(expiredDays) || expiredDays < 0) return badRequest("Invalid expiredDays.");
  if (!emailSubjectPrefix) return badRequest("Invalid emailSubjectPrefix.");
  if (adminPasswordNew && adminPasswordNew !== adminPasswordNewConfirm) return badRequest("Passwords do not match.");

  const usernameChanged = previousUsername !== adminUsername;
  const passwordChanged = !!adminPasswordNew;

  config.adminUsername = adminUsername;
  config.remindDays = remindDays;
  config.expiredDays = expiredDays;
  config.emailSubjectPrefix = emailSubjectPrefix;
  config.emailFrom = emailFrom;
  config.emailTo = emailTo;
  if (resendApiKey) config.resendApiKey = resendApiKey;
  if (adminPasswordNew) {
    const salt = newId(8);
    config.adminPasswordSalt = salt;
    config.adminPasswordHash = await hashPassword(adminPasswordNew, salt);
  }
  if (usernameChanged || passwordChanged) {
    config.authVersion = previousAuthVersion + 1;
  }
  await saveConfig(env, config);

  let mail = null;
  if (adminPasswordNew && config.resendApiKey && config.emailFrom && config.emailTo) {
    try {
      const subject = `${config.emailSubjectPrefix || "[SubsTracker]"} 管理员密码已修改`;
      const note =
        previousUsername === adminUsername
          ? "你在 SubsTracker 设置中修改了管理员密码。"
          : "你在 SubsTracker 设置中修改了管理员用户名和密码。";
      const htmlBody = credentialEmailHtml({
        title: "管理员凭据已更新",
        username: adminUsername,
        password: adminPasswordNew,
        note,
      });
      const sent = await sendEmailViaResend(config.resendApiKey, config.emailFrom, config.emailTo, subject, htmlBody);
      mail = { sent: true, id: sent?.id || null };
    } catch (err) {
      mail = { sent: false, error: err?.message || String(err) };
    }
  }

  const reloginRequired = usernameChanged || passwordChanged;
  if (reloginRequired) {
    const token = getCookieValue(request.headers.get("cookie"), "session");
    await destroySession(env, token);
    const cookie = clearSessionCookieHeader(request);
    return json({ ok: true, mail, reloginRequired }, { headers: { "set-cookie": cookie } });
  }
  return json({ ok: true, mail, reloginRequired: false });
}

async function handleForgotPassword(request, env) {
  const config = await ensureConfig(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest("Invalid JSON.");
  }

  const username = String(body?.username || "").trim();
  if (!username) return badRequest("Missing username.");
  if (username !== String(config.adminUsername || "admin")) return unauthorized();

  if (!config.resendApiKey || !config.emailFrom || !config.emailTo) {
    return badRequest("Email not configured. Please login and configure Resend/email first.");
  }

  const cooldown = await env.SUBS_KV.get(FORGOT_COOLDOWN_KEY);
  if (cooldown) return badRequest("Please wait 60 seconds and try again.");
  await env.SUBS_KV.put(FORGOT_COOLDOWN_KEY, "1", { expirationTtl: 60 });

  const newPassword = generatePassword(12);
  const salt = newId(8);
  const newHash = await hashPassword(newPassword, salt);

  const subject = `${config.emailSubjectPrefix || "[SubsTracker]"} 忘记密码/重置`;
  const htmlBody = credentialEmailHtml({
    title: "忘记密码：已重置",
    username: config.adminUsername || "admin",
    password: newPassword,
    note: "你触发了“忘记密码”。系统已为你生成一个新的临时密码，请尽快登录后在“设置”中修改。",
  });
  const data = await sendEmailViaResend(config.resendApiKey, config.emailFrom, config.emailTo, subject, htmlBody);

  config.adminPasswordSalt = salt;
  config.adminPasswordHash = newHash;
  config.authVersion = Number(config.authVersion || 1) + 1;
  await saveConfig(env, config);

  return json({ ok: true, id: data?.id || null });
}

async function route(request, env) {
  if (!env.SUBS_KV) return html(debugMissingKvHtml(), { status: 500 });
  const url = new URL(request.url);
  const { pathname } = url;

  if (pathname === "/") {
    const auth = await requireUser(request, env);
    if (auth.ok) return redirect("/admin");
    if (auth.clearCookie) return redirect("/login", 302, { headers: { "set-cookie": clearSessionCookieHeader(request) } });
    return redirect("/login");
  }
  if (request.method === "GET" && pathname === "/login") return html(loginPageHtml());
  if (request.method === "GET" && pathname === "/admin") {
    const auth = await requireUser(request, env);
    if (!auth.ok) {
      if (auth.clearCookie) return redirect("/login", 302, { headers: { "set-cookie": clearSessionCookieHeader(request) } });
      return redirect("/login");
    }
    return html(adminPageHtml());
  }

  if (pathname.startsWith("/api/")) {
    if (request.method === "POST" && pathname === "/api/login") return handleLogin(request, env);
    if (request.method === "POST" && pathname === "/api/logout") return handleLogout(request, env);
    if (request.method === "POST" && pathname === "/api/forgot") return handleForgotPassword(request, env);

    const auth = await requireUser(request, env);
    if (!auth.ok) {
      if (auth.clearCookie) return unauthorized({ headers: { "set-cookie": clearSessionCookieHeader(request) } });
      return unauthorized();
    }

    if (request.method === "GET" && pathname === "/api/records") return handleListRecords(env);
    if (request.method === "POST" && pathname === "/api/records") return handleCreateRecord(request, env);
    if (request.method === "PUT" && pathname.startsWith("/api/records/")) {
      const id = pathname.slice("/api/records/".length);
      if (!id) return badRequest("Missing id.");
      return handleUpdateRecord(id, request, env);
    }
    if (request.method === "DELETE" && pathname.startsWith("/api/records/")) {
      const id = pathname.slice("/api/records/".length);
      if (!id) return badRequest("Missing id.");
      return handleDeleteRecord(id, env);
    }
    if (request.method === "GET" && pathname === "/api/export") return handleExport(request, env);
    if (request.method === "POST" && pathname === "/api/import") return handleImport(request, env);
    if (request.method === "GET" && pathname === "/api/config") return handleGetConfig(env);
    if (request.method === "POST" && pathname === "/api/config") return handleUpdateConfig(request, env);
    if (request.method === "POST" && pathname === "/api/remind/test") {
      const res = await runReminder(env, { forceSend: true });
      return json({ ok: true, id: res?.resend?.id || null, skipped: !!res.skipped, reason: res.reason || null });
    }
    if (request.method === "POST" && pathname === "/api/remind/run") {
      const res = await runReminder(env, { forceSend: false });
      return json(res);
    }
    return json({ ok: false, error: "Not found" }, { status: 404 });
  }

  return text("Not found", { status: 404 });
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (err) {
      return serverError(err?.message || String(err));
    }
  },
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(runReminder(env).catch(() => {}));
  },
};
