# SubsTracker (Cloudflare Workers + KV)

用于记录 **ChatGPT / Google Gemini** 等订阅账号的开通与到期时间，支持网页端登录管理、导入导出，以及通过 **Resend** 发送到期提醒邮件。  
项目采用 **Cloudflare Workers + KV**，不依赖数据库；除绑定一个 KV 外，其它配置都在网页“设置”里完成。

## Description（用于 Cloudflare Worker 的 Description）

**中文：** 订阅账号到期管理工具（Workers + KV）：支持登录、增删改查、导入导出，并用 Resend 邮件定时提醒续订。  
**English:** Subscription expiry tracker (Workers + KV): login-protected UI, CRUD, import/export, and scheduled renewal reminders via Resend email.

## 功能

- 登录保护的管理界面：`/login`、`/admin`
- 订阅记录管理：平台、账号/邮箱、开通日期、到期日期、备注
- 一键导出：JSON / CSV；批量导入：JSON / CSV（merge/replace）
- 到期提醒邮件（Resend）：支持“测试邮件（强制发送）”与“立即检查（有到期才发）”
- 忘记密码：点击后会给收件邮箱发送新的临时密码（并强制所有已登录用户下线）
- 修改密码/用户名：保存后会邮件通知新凭据（并强制所有已登录用户下线）
- UI 主题切换：蓝/绿/橙/紫/夜/日（整套配色切换）

## 数据存储（KV）

只需要绑定一个 KV：`SUBS_KV`。应用会在 KV 内维护：

- 订阅记录：`v1:records`
- 运行配置：`v1:config`
- 会话：`v1:session:*`

## 部署（Dashboard 方式：不装 Node 也行）

### 1) 创建 Worker

Cloudflare Dashboard → **Workers & Pages** → **Create application** → **Worker** → Create  
把 `gpt-gemini-subs-worker/src/index.js` 的内容粘贴进去并保存部署。

### 2) 创建并绑定 KV（必需）

1. Cloudflare Dashboard → **Workers & Pages** → **KV** → **Create namespace**（名字随意）
2. 回到 Worker → **Settings** → **Bindings** → **KV namespace bindings** → **Add**
   - Variable name：`SUBS_KV`
   - KV namespace：选择你刚创建的 namespace

### 3) 配置 Cron（推荐：定时提醒）

提醒邮件是“定时触发”，不是保存记录就立刻发送。

Worker → **Triggers** → **Cron Triggers** → Add 两条（Cloudflare Cron 使用 UTC）：

- 北京 08:00 = UTC 00:00 → `0 0 * * *`
- 北京 20:00 = UTC 12:00 → `0 12 * * *`

### 4) 首次登录与初始化

打开 Worker 域名：

- 默认用户名：`admin`
- 默认密码：`password`

登录后进入“设置”：

1. 修改管理员用户名/密码（建议立刻修改）
2. 配置 Resend：API Key、发件人（From）、收件人（To）
3. 设置提醒策略（见下文）

## 使用说明

### 订阅记录字段说明

- 平台（Provider）：`chatgpt` / `gemini` / `other`
- 账号/邮箱（Account）：建议填写邮箱或可识别的账号标识
- 开通日期（Started）：`YYYY-MM-DD`
- 到期日期（Expires）：`YYYY-MM-DD`
- 备注（Note）：例如 Plus/Pro、年付等

页面提供“快速设置到期（基于开通日期）”：`+1周/+1月/+3月/+1年`。

### 提醒策略：7 和 30 是什么？

- **提前提醒天数（REMIND_DAYS）**：到期日在“未来 N 天内（含今天）”会提醒。默认 `7`。
- **过期提醒窗口（EXPIRED_DAYS）**：已过期但在“过去 N 天内”也会提醒。默认 `30`；填 `0` 表示不提醒过期。

提醒计算以 **UTC 日期**为准（Cron 触发也按 UTC）。想马上验证请点“立即检查”或“测试邮件”。

### Resend 配置说明

在“设置”里填写：

- **Resend API Key**：以 `re_` 开头；出于安全，页面不会回显，想更新就重新填写
- **EMAIL_FROM**：必须是你在 Resend 里验证过的域名/邮箱，例如 `SubsTracker <no-reply@yourdomain.com>`
- **EMAIL_TO**：收件人，多个用逗号分隔，例如 `a@xx.com,b@yy.com`

### 忘记密码（重要）

`/login` 页面点击“忘记密码”：

- 会向 **EMAIL_TO** 发送一封包含用户名和新临时密码的邮件
- 同时会强制所有已登录用户下线（需要重新登录）
- 有 60 秒冷却时间，避免误触/滥用

## 导入/导出格式

### JSON

导入/导出为数组：

```json
[
  {
    "provider": "chatgpt",
    "account": "a@example.com",
    "startedAt": "2026-01-01",
    "expiresAt": "2026-02-01",
    "note": "Plus"
  }
]
```

### CSV

支持带表头或不带表头，列顺序：

`provider,account,startedAt,expiresAt,note`

导入模式：

- `merge`：按 `provider + account` 合并/更新
- `replace`：清空后全量覆盖

## API（一般不需要直接调用）

登录后浏览器会带 Cookie，会话鉴权在网页内完成：

- `POST /api/login` / `POST /api/logout`
- `POST /api/forgot`（忘记密码：重置并发邮件）
- `GET /api/records` / `POST /api/records` / `PUT /api/records/:id` / `DELETE /api/records/:id`
- `GET /api/export?format=json|csv`
- `POST /api/import?format=json|csv&mode=merge|replace`
- `GET /api/config` / `POST /api/config`
- `POST /api/remind/test`（测试邮件：强制发送）
- `POST /api/remind/run`（立即检查：有到期/过期记录才发送）

## 本地运行（可选：需要 Node）

如果你电脑上有 Node.js，可以用 Wrangler 进行本地预览：

1. 安装 Wrangler：`npm i -g wrangler`
2. 在 `gpt-gemini-subs-worker/` 下执行：`wrangler dev`
3. 绑定本地 KV（或用 preview KV）后访问本地地址

如果你不想装 Node，推荐直接使用 Dashboard 方式部署。

## 安全建议

- 强烈建议把 Worker 放在私有域名下，或使用 **Cloudflare Access** 进行二次保护。
- “忘记密码”会把新密码发送到收件邮箱，请确保邮箱安全、并使用强密码。

## 常见问题（FAQ）

**1) 为什么保存一条记录后没有立刻发邮件？**  
提醒邮件由 Cron 定时触发；想立即验证请点“立即检查”或“测试邮件”。

**2) 为什么“立即检查”显示未发送？**  
只有在提醒窗口内有记录才会发送：

- 未来 `REMIND_DAYS` 天内到期，或
- 已过期但在 `EXPIRED_DAYS` 天窗口内（且 `EXPIRED_DAYS > 0`）

**3) 修改密码后为什么要重新登录？**  
为了安全：修改用户名/密码后会提升 `authVersion`，强制所有会话失效并要求重新登录。

