# 安全政策

## 支持的版本

仅最新发布的版本接收安全修复，请保持 Goauth 为最新版本。

## 报告漏洞

请勿在公开 Issue 中描述可被利用的细节。

- 优先使用 GitHub 的 **Private Vulnerability Reporting**（仓库 Security 标签页 → Report a vulnerability）提交。
- 也可以通过 GitHub Issue 联系维护者，先以"安全相关"标记并仅描述影响范围，细节后续私下补充。

报告时请尽量包含：影响的版本/提交、复现步骤、影响评估（机密性/完整性/可用性）、可能的修复建议。

我们会在确认后尽快修复并发布补丁版本。

## 安全特性概览

- 密码哈希：bcrypt（默认 cost=12，可配置）
- 密码强度：zxcvbn 检测，可配置最小长度与强度分数
- 暴力破解防护：登录失败次数限制 + 临时封禁（数据库持久化）
- 会话管理：`HttpOnly` Cookie，session token SHA-256 哈希存储，支持滑动续期与"记住我"
- CSRF 防护：`csrf_token` Cookie + Token 校验（登录/注册/登出等端点除外）
- 安全响应头与 CSP：统一中间件注入，HTML 模板使用 nonce
- 速率限制：API 请求限速（可配置，0=禁用）
- 数据加密：AES-256-GCM 加密 OIDC Token 与 RSA 私钥，密钥持久化于 `data/.goauth-keys`
- 审计日志：记录登录、注册、密码重置、审批、禁用等关键操作，支持保留期自动清理
