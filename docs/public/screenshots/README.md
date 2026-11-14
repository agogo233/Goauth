# 截图说明

本目录存放文档所需的截图文件。

## 已有截图

| 文件名 | 说明 | 引用文档 |
|--------|------|----------|
| login.png | 登录页面 | user-guide.md |
| signup.png | 注册页面 | user-guide.md |
| profile.png | 个人设置页面 | user-guide.md |
| invitation.png | 邀请管理页面 | user-management.md |
| user-edit.png | 用户编辑页面 | user-management.md |
| groups.png | 安全组管理页面 | security-groups.md |
| password-resets.png | 密码重置管理页面 | password-reset.md |
| oidc-client.png | OIDC 客户端配置页面 | oidc-setup.md |
| proxy-domain.png | ProxyAuth 域名设置页面 | proxy-auth.md |

## 待补充截图

以下截图尚未提供，相关文档正文暂未引用，补充后可再添加到对应文档：

- `mfa-required.png` / `mfa-register.png`（MFA 验证/注册页面，user-guide.md）
- `oidc-endpoints.png`（OIDC 端点信息面板，oidc-setup.md）
- `proxy-authz.png`（ProxyAuth 授权规则示例，proxy-auth.md）

## 截图规范

- **格式**: PNG
- **主题**: 使用应用默认主题（紫色系）
- **敏感信息**: 已模糊处理用户名、邮箱等敏感信息
- **尺寸**: 
  - 登录/注册等小型表单: 500px 宽度
  - 管理后台页面: 1400x900 全屏

## 重新生成截图

```bash
cd goauth
make build
./bin/goauth serve &
# 使用 Playwright 生成截图（可自行编写截图脚本/配置）
cd tests/e2e
npx playwright test
```
