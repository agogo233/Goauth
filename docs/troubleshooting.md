# 故障排除

一些常见问题及其原因。

### 无法创建会话

无法设置 `session` Cookie。请确保 `APP_SERVER_APPURL` 环境变量设置为 Goauth 的公开 URL，并且你是从该 URL 访问应用。

这也可能是由无效的 `APP_SERVER_COOKIEDOMAIN` 环境变量值引起的。浏览器可能不允许在顶级域名（如 `com`、`co.uk`、`lan`）以及某些公共域名（如 `azurewebsites.net`、`cdn.cloudflare.net`）上设置 Cookie。你可以在 [Mozilla HTTP Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#define_where_cookies_are_sent) 文档中了解更多信息，并查看当前的 [Public Suffix List](https://publicsuffix.org/list/) 了解受限制的域名。

### 登录被临时封禁

连续登录失败次数达到 `APP_SECURITY_LOGINMAXATTEMPTS`（默认 10 次）后，账户或来源 IP 会被临时封禁 `APP_SECURITY_LOGINBLOCKDURATION`（默认 30 分钟）。封禁记录保存在数据库中，重启服务不会清除。等待封禁时长结束后重试，或由管理员排查。

### TOTP 验证总是失败

请确认设备时间与服务器时间同步（TOTP 依赖时间窗口）。连续输错次数达到 `APP_SECURITY_TOTPMAXATTEMPTS`（默认 5 次）后，验证将被拒绝，请等待一段时间后重试，或由管理员重置 TOTP。

### 接口返回 429

API 请求触发了速率限制（默认 100 次/分钟）。可通过 `APP_SERVER_RATELIMIT` 调整阈值，设置为 `0` 禁用。静态资源与 `/health`、`/ready` 端点不受速率限制。

### 无效客户端

请确保已创建 OIDC 应用，并且 Goauth 和"客户端"应用中的 `Client ID` 参数完全匹配。

### 无效重定向 URI

"客户端"应用应指定正确的 `Redirect URL` 参数以输入 Goauth。这通常位于应用的 OIDC 文档中或其 OIDC 设置页面上（如果有）。你也可以在 [OIDC 应用配置指南](oidc-guides.md)页面找到该应用的示例。
