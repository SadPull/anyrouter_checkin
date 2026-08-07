# AnyRouter / AgentRouter 自动签到

每天北京时间 09:00 通过 GitHub Actions 给 AnyRouter 和 AgentRouter 签到，并用 PushPlus 把所有账号的结果、当前额度合并成一条通知推送。也可以在 Actions 页面手动运行。只配置其中一个站点也能正常工作。

## 两站机制不同

这不是换个域名就能通用的事，两站虽然都是 New-API 二次开发，但发放每日额度的方式完全不同：

- **AnyRouter** 有真正的签到接口 `POST /api/user/sign_in`，带上登录 Cookie 调用即可，能拿到签到前后的额度差。
- **AgentRouter 没有签到接口**（`sign_in`、`check_in`、`clock_in` 等路径全部返回 404）。它的每日额度由后台配置项 `DailyCheckinQuota` 驱动，是**认证的副作用**——登录成功时顺带发放，接口返回 `checked_in` 标记。

所以 **AgentRouter 的站点 Cookie 无法签到**：Cookie 代表「已经登录」，没有可触发的认证动作，只能用来读额度。要真正签到必须重新认证一次。账号注册来源不同，脚本会用它对应渠道的 Cookie 重放 OAuth 授权流程。

对于 **LinuxDO** 渠道注册的账号（无密码），脚本用 LinuxDO 的 Cookie：

```
GET /api/oauth/state          取签名 state，同时拿到 session cookie
GET connect.linux.do/oauth2/authorize   带 LinuxDO Cookie，从 302 里取 code
GET /api/oauth/linuxdo        回调登录，返回 checked_in
GET /api/user/self            用中继得到的 session 读权威额度
```

对于 **GitHub** 渠道注册的账号（例如抓包里的 `github_253692`），脚本用 GitHub 的 Cookie：

```
GET /api/oauth/state          取签名 state，同时拿到 session cookie
GET github.com/login/oauth/authorize   带 GitHub Cookie，从 302 里取 code
GET /api/oauth/github         回调登录，返回 checked_in
GET /api/user/self            用中继得到的 session 读权威额度
```

中继成功就是真签到；失败（阿里云 WAF 拦截、或渠道需要手动授权一次）会自动降级为只读额度，通知里明确写「未签到（仅查询额度）」并附上失败原因。

## 配置

在 GitHub 仓库的 `Settings` → `Secrets and variables` → `Actions` 中添加 Repository secrets。

### AnyRouter

- `ANYROUTER_USER_ID`：浏览器登录 AnyRouter 后，请求头 `New-API-User` 的值。
- `ANYROUTER_COOKIE`：浏览器已登录 AnyRouter 时，请求头中完整的 `Cookie` 值。

两个必须成对配置。

### AgentRouter

- `AGENTROUTER_LINUXDO_COOKIE`：**签到用（LinuxDO 渠道）**。浏览器登录 [connect.linux.do](https://connect.linux.do) 后，请求头中完整的 `Cookie` 值。
- `AGENTROUTER_GITHUB_COOKIE`：**签到用（GitHub 渠道）**。浏览器登录 [github.com](https://github.com) 后，请求头中完整的 `Cookie` 值。脚本只挑出其中的登录会话（`user_session`/`_gh_sess`）重放 GitHub OAuth（`/api/oauth/github`）。
- `AGENTROUTER_COOKIE`：**降级用**。浏览器已登录 agentrouter.org 时的完整 `Cookie` 值。中继失败时用它读额度。
- `AGENTROUTER_USER_ID`：可选，请求头 `New-API-User` 的值。

三个 Cookie 至少要配一个。建议都配：优先走中继真签到，失败还能报出额度而不是整个失败。只配 `AGENTROUTER_COOKIE` 的话每次都只会查询额度，不会签到。LinuxDO / GitHub 两个签到渠道可以同时配置，脚本按 LinuxDO → GitHub 的顺序尝试，哪个成功用哪个。

> LinuxDO / GitHub 的 Cookie 权限比站点 Cookie 大，只放进 Actions Secrets，不要写进代码或提交到仓库。

### PushPlus

- `PUSHPLUS_TOKEN`：PushPlus 网站获取的用户 token（所有账号共用一个）。

### 多账号

按编号添加成对的 Secrets，两个站点都支持：

- `ANYROUTER_USER_ID1` + `ANYROUTER_COOKIE1`
- `AGENTROUTER_LINUXDO_COOKIE1` 或 `AGENTROUTER_GITHUB_COOKIE1`（+ 可选的 `AGENTROUTER_COOKIE1`、`AGENTROUTER_USER_ID1`）
- 依此类推……

脚本会自动检测所有编号变量，逐个签到并把结果合并到一条通知里。不带编号的变量也会作为一个账号一起签到（旧配置继续可用）。某个编号缺少必需变量会报错并指出缺的是哪个。工作流默认透传编号 1–5，如需更多账号，在 `.github/workflows/daily-checkin.yml` 的 `env` 中按同样格式追加即可。

不要把用户 ID、Cookie、PushPlus token 或 HAR 文件提交到仓库。项目已通过 `.gitignore` 排除 HAR 和本地 `.env` 文件。

## Cookie 失效

Cookie 会过期。失效时（HTTP 401、返回登录页、或提示未登录）脚本会单独识别，在日志和通知里点名要刷新哪个环境变量，例如：

```
AGENTROUTER_LINUXDO_COOKIE1 已失效，请从浏览器重新复制（GET ... 返回 HTTP 401）
```

同时以非零退出码结束，让 Actions 变红。有账号没真正签到时，标题也会写成「每日签到完成，但 N 个账号未签到」，不会用「成功」盖过去。

## 使用

将这些文件推送到 GitHub 后，工作流会按 `.github/workflows/daily-checkin.yml` 中的计划运行。首次使用建议打开仓库的 `Actions` 页面，选择 `Daily Check-in`，点击 `Run workflow` 手动验证。

本地测试可以临时设置环境变量后运行：

```powershell
$env:ANYROUTER_USER_ID = "你的用户ID"
$env:ANYROUTER_COOKIE = "浏览器请求头中的完整Cookie"
$env:AGENTROUTER_LINUXDO_COOKIE = "connect.linux.do 的完整Cookie"
$env:AGENTROUTER_GITHUB_COOKIE = "github.com 的完整Cookie"
$env:AGENTROUTER_COOKIE = "agentrouter.org 的完整Cookie"
$env:PUSHPLUS_TOKEN = "你的PushPlus令牌"
python .\checkin.py
```

脚本仅使用 Python 标准库，不需要安装依赖。在 Windows 本地跑可能需要 `pip install tzdata`，否则 `zoneinfo` 找不到 `Asia/Shanghai`（Actions 的 ubuntu runner 自带，不影响线上）。GitHub 的定时任务可能因平台负载延迟数分钟。
