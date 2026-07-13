# AnyRouter 自动签到

每天北京时间 09:00 通过 GitHub Actions 调用 AnyRouter 签到接口，并使用 PushPlus 推送签到结果、当前额度和额度变化。也可以在 Actions 页面手动运行。

## 配置

在 GitHub 仓库的 `Settings` → `Secrets and variables` → `Actions` 中添加三个 Repository secrets：

- `ANYROUTER_USER_ID`：浏览器登录 AnyRouter 后，HAR 请求头 `New-API-User` 的值。
- `ANYROUTER_COOKIE`：浏览器已登录 AnyRouter 时，请求头中完整的 `Cookie` 值。当前 HAR 导出时没有包含 Cookie，必须从浏览器开发者工具的 Network 面板重新复制。
- `PUSHPLUS_TOKEN`：PushPlus 网站获取的用户 token。

不要把用户 ID、PushPlus token 或 HAR 文件提交到仓库。项目已通过 `.gitignore` 排除 HAR 和本地 `.env` 文件。

## 使用

将这些文件推送到 GitHub 后，工作流会按 `.github/workflows/daily-checkin.yml` 中的计划运行。首次使用建议打开仓库的 `Actions` 页面，选择 `AnyRouter Daily Check-in`，点击 `Run workflow` 手动验证。

本地测试可以临时设置环境变量后运行：

```powershell
$env:ANYROUTER_USER_ID = "你的用户ID"
$env:ANYROUTER_COOKIE = "浏览器请求头中的完整Cookie"
$env:PUSHPLUS_TOKEN = "你的PushPlus令牌"
python .\anyrouter_checkin.py
```

脚本仅使用 Python 标准库，不需要安装依赖。GitHub 的定时任务可能因平台负载延迟数分钟。
