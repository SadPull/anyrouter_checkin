# 自动签到

每天北京时间 09:00 通过 GitHub Actions 完成各站点签到，并用 PushPlus 把所有账号的结果、当前额度合并成一条通知推送。也可以在 Actions 页面手动运行。

支持两类站点：

| 站点 | 地址 | 凭证 | 签到接口 |
| --- | --- | --- | --- |
| AnyRouter | https://anyrouter.top | Session Cookie | `POST /api/user/sign_in` |
| Justwoker | https://api.justwoker.icu | 系统访问令牌（推荐）或 Cookie | `POST /api/user/checkin` |
| Gorouter | https://gorouter.app | 同上 | 同上 |
| Tabitoken | https://tabitoken.com | 同上 | 同上 |

## 签到机制

### New-API 站点（Justwoker / Gorouter / Tabitoken）

三个站都是新版 New-API（v1.0.0-rc 系），签到接口为 `GET/POST /api/user/checkin`，奖励为管理员配置的 min~max 区间随机额度，每账号每天一次（重复签到返回「今日已签到」）。脚本流程：

1. `GET /api/status` 读取配置（是否开启签到、是否要求 Turnstile、额度换算单位）。
2. `GET /api/user/checkin` 判断今天是否已签；已签则直接推送当前额度，全程不启动浏览器。
3. 未签到且站点要求 Cloudflare Turnstile（POST 需要 `?turnstile=<令牌>`，令牌单次有效）时，脚本会启动一个**真实 Chrome**（普通子进程，无任何自动化标记，独立用户目录），通过 DevTools 协议连接后，在站点页面里用隐形 Turnstile 组件现场换取令牌并立即 POST；每次尝试都重新取令牌，最多重试 3 次。真实指纹下 Cloudflare 直接放行隐形质询，实测 3~10 秒即可拿到令牌。
4. Cloudflare 把纯 HTTP 请求拦成 HTML 时，自动降级为「浏览器内直接调用 API」，后续请求全部走浏览器通道。

**凭证（二选一，推荐前者）**：

- **系统访问令牌**（推荐）：登录站点 → 个人设置 → 系统访问令牌 → 生成并复制。长期有效、不轮换，请求头为 `Authorization: Bearer <令牌>`。全程不需要抓包。
- **刷新 Cookie**（备用）：浏览器 DevTools → Application → Cookies → 复制 `new_api_refresh` 的值（或整段 Cookie 请求头）。脚本会调 `POST /api/user/auth/refresh` 换取访问令牌。注意该 Cookie 会随刷新轮换，可能过一段时间失效，失效后请重新复制。

**运行环境说明（重要）**：

- **本机运行（推荐，最可靠）**：本机装有 Chrome 时走真实 Chrome + CDP，Cloudflare/Turnstile 稳定通过，窗口会短暂弹出约半分钟，属正常现象。可用 Windows 计划任务每天自动运行（见下文「本地计划任务」）。
- **GitHub Actions（尽力而为）**：runner 没有桌面 Chrome 时回退到 Playwright Chromium（xvfb 有头）。Cloudflare 对机房 IP 风控更严，要求 Turnstile 的站点在 CI 里**可能失败**（日志会写明原因），失败会推送通知且 Actions 变红。不要求 Turnstile 的站点在 CI 里通常没问题。

### AnyRouter

New-API 二次开发站点，有真正的签到接口 `POST /api/user/sign_in`，带上登录 Cookie 调用即可，能拿到签到前后的额度差。

脚本对阿里云 WAF 的 `acw_sc__v2` 挑战做了自动求解，对偶发的 HTML 拦截页会自动重试；Cookie 失效（HTTP 401、返回登录页、提示未登录）会被单独识别。

## 配置（GitHub Secrets）

在 GitHub 仓库的 `Settings` → `Secrets and variables` → `Actions` 中添加 Repository secrets：

| Secret | 说明 |
| --- | --- |
| `JUSTWOKER_TOKEN` | api.justwoker.icu 的系统访问令牌（推荐），或改配 `JUSTWOKER_COOKIE` |
| `GOROUTER_TOKEN` | gorouter.app 的系统访问令牌（推荐），或改配 `GOROUTER_COOKIE` |
| `TABITOKEN_TOKEN` | tabitoken.com 的系统访问令牌（推荐），或改配 `TABITOKEN_COOKIE` |
| `ANYROUTER_USER_ID` | 浏览器登录 AnyRouter 后，请求头 `New-API-User` 的值 |
| `ANYROUTER_COOKIE` | 浏览器已登录 AnyRouter 时，请求头中完整的 `Cookie` 值 |
| `PUSHPLUS_TOKEN` | PushPlus 网站获取的用户 token（所有账号共用一个） |

说明：

- 三个 New-API 站点**不配置就自动跳过**，互不影响；只配想要签到的站即可。
- `*_USER_ID` 可选：仅当站点要求 `New-Api-User` 请求头时才需要（新版令牌鉴权通常不需要）。
- `ANYROUTER_USER_ID` 和 `ANYROUTER_COOKIE` 必须成对配置。

### 多账号

按编号添加 Secrets，脚本自动发现所有编号并逐个签到：

- New-API 站点：`JUSTWOKER_TOKEN1` / `JUSTWOKER_COOKIE1`、`GOROUTER_TOKEN2`……（每个编号二选一）
- AnyRouter：`ANYROUTER_USER_ID1` + `ANYROUTER_COOKIE1` 成对添加，依此类推

脚本会自动检测所有编号变量，逐个签到并把结果合并到一条通知里。不带编号的变量也会作为一个账号一起签到（旧配置继续可用）。某个编号缺少必需变量会报错并指出缺的是哪个。工作流默认透传编号 1–5，如需更多账号，在 `.github/workflows/daily-checkin.yml` 的 `env` 中按同样格式追加即可。

## 凭证失效

Cookie/令牌会过期。失效时（HTTP 401/403、返回登录页、提示未登录或令牌无效）脚本会单独识别，在日志和通知里点名要重新生成哪个环境变量，例如：

```
JUSTWOKER_TOKEN1 已失效（…），请到站点「个人设置 → 系统访问令牌」重新生成 JUSTWOKER_TOKEN1
```

同时以非零退出码结束，让 Actions 变红。系统访问令牌长期有效，一般只需在站点重新生成后更新对应 Secret。

## 使用

将这些文件推送到 GitHub 后，工作流会按 `.github/workflows/daily-checkin.yml` 中的计划运行。首次使用建议打开仓库的 `Actions` 页面，选择 `Daily Check-in`，点击 `Run workflow` 手动验证。GitHub 的定时任务可能因平台负载延迟数分钟。

### 本地计划任务（推荐：要求 Turnstile 的站点最可靠的签到方式）

本机装了 Chrome 时，用 Windows 计划任务每天自动跑一次，比 CI 可靠（家用 IP + 真实 Chrome，Cloudflare 直接放行）。以管理员 PowerShell 运行一次即可：

```powershell
# 每天北京时间 09:05 自动签到（把路径换成你的实际路径）
schtasks /Create /TN "NewApiCheckin" /SC DAILY /ST 09:05 /TR ^
  "cmd /c cd /d C:\path\to\checkin && python checkin.py >> checkin.log 2>&1"
```

环境变量怎么持久化给计划任务？把令牌写进一个本地 `.env` 风格的启动脚本（`.gitignore` 已排除 HAR 和本地敏感文件，不要提交）：

```powershell
# save-run.bat（放在项目目录，不要提交）
@echo off
set JUSTWOKER_TOKEN=你的令牌
set GOROUTER_TOKEN=你的令牌
set TABITOKEN_TOKEN=你的令牌
set PUSHPLUS_TOKEN=你的PushPlus令牌
cd /d %~dp0
python checkin.py >> checkin.log 2>&1
```

然后计划任务指向它：`schtasks /Create /TN "NewApiCheckin" /SC DAILY /ST 09:05 /TR "C:\path\to\save-run.bat"`。

### 本地测试（Windows）

```powershell
pip install playwright
$env:JUSTWOKER_TOKEN = "你的系统访问令牌"
$env:PUSHPLUS_TOKEN = "你的PushPlus令牌"
python .\checkin.py
```

脚本本体只用 Python 标准库；playwright 仅在需要浏览器通道时加载（用于驱动真实 Chrome 的 DevTools 连接；本机没有 Chrome 时才需要 `python -m playwright install chromium` 装一个回退浏览器）。已签到的日子全程不会启动浏览器。Actions 的 ubuntu runner 由工作流自动安装 playwright 和 Chromium，并用 `xvfb-run` 提供虚拟显示（有头模式过 Cloudflare 更稳）。Windows 本地没有 `DISPLAY` 变量，回退浏览器默认无头运行。另外 Windows 本地跑可能需要 `pip install tzdata`，否则 `zoneinfo` 找不到 `Asia/Shanghai`（Actions 的 ubuntu runner 自带，不影响线上）。

不要把令牌、Cookie、PushPlus token 或 HAR 文件提交到仓库。项目已通过 `.gitignore` 排除 HAR 和本地 `.env` 文件。
