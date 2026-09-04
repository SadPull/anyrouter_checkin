# AnyRouter / JustWoker 多站点自动签到

每天北京时间 09:00 通过 GitHub Actions 给 AnyRouter（https://anyrouter.top）和 JustWoker（https://api.justwoker.icu）签到，并用 PushPlus 把所有账号的结果、当前额度合并成一条通知推送。也可以在 Actions 页面手动运行。

## 签到机制

AnyRouter 是 New-API 二次开发站点，有真正的签到接口 `POST /api/user/sign_in`，带上登录 Cookie 调用即可，能拿到签到前后的额度差。

脚本对阿里云 WAF 的 `acw_sc__v2` 挑战做了自动求解，对偶发的 HTML 拦截页会自动重试；Cookie 失效（HTTP 401、返回登录页、提示未登录）会被单独识别。

### JustWoker（api.justwoker.icu）

JustWoker 是新版 New-API 站点（Cloudflare 前置，无阿里云 WAF）。签到接口为 `POST /api/user/checkin`（若站点为旧版路径，脚本会自动回退到 `POST /api/user/sign_in`），认证使用 `Authorization: Bearer <系统访问令牌>` + `New-Api-User: <用户ID>` 请求头。签到前后的额度同样通过 `GET /api/user/self` 读取，美元换算比例从公开接口 `/api/status` 的 `quota_per_unit` 动态读取（默认 500000）。

**为什么不用浏览器里的 `new_api_refresh` Cookie：** 该站采用新版认证体系——页面用 15 分钟有效期的 JWT，`new_api_refresh` Cookie 每次刷新都会轮换，且"最近一代"令牌在容错窗口过后再次出现会**撤销整个登录会话**（浏览器也会被登出）。把这种 Cookie 存进 Secrets 每日复用最多成功一次，之后直接作废。因此这里改用长期有效、无轮换的系统访问令牌。

## 配置

在 GitHub 仓库的 `Settings` → `Secrets and variables` → `Actions` 中添加 Repository secrets：

- `ANYROUTER_USER_ID`：浏览器登录 AnyRouter 后，请求头 `New-API-User` 的值。
- `ANYROUTER_COOKIE`：浏览器已登录 AnyRouter 时，请求头中完整的 `Cookie` 值。
- `PUSHPLUS_TOKEN`：PushPlus 网站获取的用户 token（所有账号共用一个）。

`ANYROUTER_USER_ID` 和 `ANYROUTER_COOKIE` 必须成对配置。

JustWoker 账号使用系统访问令牌：

- `JUSTWOKER_USER_ID`：JustWoker 用户 ID（个人设置页可见；也可 F12 查看 `/api/user/auth/refresh` 响应中 `data.user.id` 的值）。
- `JUSTWOKER_TOKEN`：JustWoker「个人设置 → 安全 → 访问令牌」生成的系统访问令牌。注意：打开「访问令牌」弹窗会立即重新生成令牌并使旧令牌失效，生成后请立即复制保存。

`JUSTWOKER_USER_ID` 和 `JUSTWOKER_TOKEN` 必须成对配置。

### 多账号

按编号添加成对的 Secrets：

- `ANYROUTER_USER_ID1` + `ANYROUTER_COOKIE1`
- 依此类推……JustWoker 账号同理：`JUSTWOKER_USER_ID1` + `JUSTWOKER_TOKEN1`。

脚本会自动检测所有编号变量，逐个签到并把结果合并到一条通知里。不带编号的变量也会作为一个账号一起签到（旧配置继续可用）。某个编号缺少必需变量会报错并指出缺的是哪个。工作流默认透传编号 1–5，如需更多账号，在 `.github/workflows/daily-checkin.yml` 的 `env` 中按同样格式追加即可。

## Cookie 失效

Cookie 会过期。失效时（HTTP 401、返回登录页、或提示未登录）脚本会单独识别，在日志和通知里点名要刷新哪个环境变量，例如：

```
ANYROUTER_COOKIE1 已失效，请从浏览器重新复制（GET ... 返回 HTTP 401）
```

同时以非零退出码结束，让 Actions 变红。

JustWoker 的系统访问令牌同理：令牌被重新生成（再次打开「访问令牌」弹窗）或账号会话被全部撤销后，脚本会提示 `JUSTWOKER_TOKEN 已失效`，需到「个人设置 → 安全 → 访问令牌」重新生成并更新对应的 Secret。

## 使用

将这些文件推送到 GitHub 后，工作流会按 `.github/workflows/daily-checkin.yml` 中的计划运行。首次使用建议打开仓库的 `Actions` 页面，选择 `Daily Check-in`，点击 `Run workflow` 手动验证。

本地测试可以临时设置环境变量后运行：

```powershell
$env:ANYROUTER_USER_ID = "你的用户ID"
$env:ANYROUTER_COOKIE = "浏览器请求头中的完整Cookie"
$env:PUSHPLUS_TOKEN = "你的PushPlus令牌"
$env:JUSTWOKER_USER_ID = "你的JustWoker用户ID"
$env:JUSTWOKER_TOKEN = "你的JustWoker系统访问令牌"
python .\checkin.py
```

脚本仅使用 Python 标准库，不需要安装依赖。在 Windows 本地跑可能需要 `pip install tzdata`，否则 `zoneinfo` 找不到 `Asia/Shanghai`（Actions 的 ubuntu runner 自带，不影响线上）。GitHub 的定时任务可能因平台负载延迟数分钟。

不要把用户 ID、Cookie、PushPlus token 或 HAR 文件提交到仓库。项目已通过 `.gitignore` 排除 HAR 和本地 `.env` 文件。
