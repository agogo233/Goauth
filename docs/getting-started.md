# 快速开始

## 快速开始

Goauth 是一个精简的 OIDC Provider，使用 SQLite 数据库，适合小规模部署。

### Docker

```bash
docker run -d \
  -p 3000:3000 \
  -v goauth-data:/app/data \
  -e APP_OIDC_ISSUER=http://localhost:3000 \
  ghcr.io/aoten/goauth:latest
```

### Docker Compose

```yaml
version: '3'
services:
  goauth:
    image: ghcr.io/aoten/goauth:latest
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - goauth-data:/app/data
    environment:
      - APP_OIDC_ISSUER=https://auth.example.com
      - APP_UI_APPNAME=Goauth

volumes:
  goauth-data:
```

> [!TIP]
> 首个注册的用户将自动成为管理员并直接通过审批；也可以通过 CLI `goauth create-admin` 创建管理员。请及时修改密码。

> [!WARNING]
> Goauth 本身不提供 HTTPS 终止，强烈建议在前面部署反向代理（如 Caddy、Traefik、Nginx）并启用 HTTPS。

## 配置

### 环境变量

所有配置使用 `APP_` 前缀：

#### 服务器配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_SERVER_PORT` | 服务端口 | `3000` |
| `APP_SERVER_HOST` | 监听地址 | `0.0.0.0` |
| `APP_SERVER_ENVIRONMENT` | 环境 (development/production) | `development` |
| `APP_SERVER_APPURL` | 应用完整 URL | - |
| `APP_SERVER_BASEPATH` | 子路径部署（如 `/auth`） | `""` |
| `APP_SERVER_TIMEZONE` | 时区 | `UTC` |
| `APP_SERVER_COOKIEDOMAIN` | Cookie 域名 | 自动从 APPURL 提取 |
| `APP_SERVER_COOKIESECURE` | Secure Cookie (auto/true/false) | `auto` |
| `APP_SERVER_COOKIESAMESITE` | SameSite (strict/lax/none) | `lax` |
| `APP_SERVER_CORSALLOWORIGINS` | CORS 允许来源（逗号分隔） | 空（仅同源；development 下为 `*`） |
| `APP_SERVER_RATELIMIT` | 速率限制（次/分钟，0=禁用） | `100` |

#### 数据库配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_DATABASE_PATH` | SQLite 数据库路径 | `./data/goauth.db` |

#### OIDC 配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_OIDC_ISSUER` | OIDC Issuer URL | 自动使用 APP_SERVER_APPURL |
| `APP_OIDC_ACCESSTOKENTTL` | Access Token 有效期 | `15m` |
| `APP_OIDC_IDTOKENTTL` | ID Token 有效期 | `30m` |
| `APP_OIDC_REFRESHTOKENTTL` | Refresh Token 有效期 | `168h` (7天) |
| `APP_OIDC_SESSIONTTL` | OIDC Session 有效期 | `720h` (30天) |

#### 会话配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_SESSION_TTL` | 普通登录会话有效期 | `24h` |
| `APP_SESSION_TTLREMEMBER` | "记住我" 会话有效期 | `720h` (30天) |

#### 安全配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_SECURITY_PASSWORDMIN` | 密码最小长度 | `8` |
| `APP_SECURITY_PASSWORDMINSCORE` | 密码强度分数 (0-4) | `3` |
| `APP_SECURITY_BCRYPTCOST` | bcrypt 哈希成本 (4-31) | `12` |
| `APP_SECURITY_LOGINMAXATTEMPTS` | 登录失败次数限制 | `10` |
| `APP_SECURITY_LOGINBLOCKDURATION` | 封禁时长 (分钟) | `30` |
| `APP_SECURITY_TOTPMAXATTEMPTS` | TOTP 最大尝试次数 | `5` |
| `APP_SECURITY_AUDITLOGRETENTION` | 审计日志保留天数 | `90` |
| `APP_SECURITY_LOGINATTEMPTCLEANUP` | 登录尝试记录清理间隔 (小时) | `24` |
| `APP_SECURITY_AUTOAPPROVEUSERS` | 自动批准所有注册用户（测试用） | `false` |
| `APP_SECURITY_CRYPTOKEY` | AES-256-GCM 加密密钥（32字节 base64，自动生成则无需设置） | 自动生成 |

> [!NOTE]
> 时长类变量（如 `APP_OIDC_*TTL`、`APP_SESSION_*`）支持 Go duration 格式（`15m`、`24h`、`720h`）；纯数字会被解析为纳秒，请务必带单位。

#### UI 配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_UI_APPNAME` | 应用名称 | `Goauth` |
| `APP_UI_APPCOLOR` | 主题颜色 | `#906bc7` |
| `APP_UI_SIGNUPENABLED` | 开放注册 | `true` |

#### 日志配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_LOGGING_LEVEL` | 日志级别 (debug/info/warn/error) | `info` |

### 配置文件

支持 YAML 格式配置文件：

```yaml
server:
  port: 3000
  host: 0.0.0.0
  environment: production
  appurl: https://auth.example.com

oidc:
  issuer: https://auth.example.com

ui:
  appname: "My Auth"
  appcolor: "#4a90d9"
  signupenabled: false

security:
  passwordmin: 10
  passwordminscore: 4
```

## CLI 命令

```bash
# 启动服务器（默认命令）
goauth serve [--config config.yaml]

# 运行数据库迁移
goauth migrate [--config config.yaml]

# 重置用户密码
goauth reset-password -u <username>

# 创建管理员
goauth create-admin -u <username> -p <password>

# 查看版本
goauth --version
```

## 用户和应用管理

用户、OIDC 客户端、ProxyAuth 域名的管理都在 Web 管理界面中完成。

### 设置受保护应用

有两种方式保护你的应用：

1. **OIDC 集成** - 如果应用支持 OIDC，参考 [OIDC 应用设置](oidc-setup.md)
2. **ProxyAuth** - 如果应用不支持 OIDC，参考 [代理认证](proxy-auth.md)

## 安全特性

- **密码哈希** - bcrypt (默认 cost=12，可通过 `APP_SECURITY_BCRYPTCOST` 配置)
- **密码强度** - zxcvbn 检测
- **暴力破解防护** - 失败次数限制 + IP 封禁
- **会话管理** - 安全 Cookie，session token SHA-256 哈希存储，支持"记住我"
- **二步验证** - TOTP 支持
- **数据加密** - AES-256-GCM 加密 OIDC Token 和 RSA 私钥
- **审计日志** - 关键操作记录

## 特性概览

| 功能 | 支持 |
|------|------|
| 数据库 | SQLite |
| 前端 | Alpine.js |
| 邮件 | ❌ (通过 CLI 重置密码) |
| Passkey | ❌ |
| 国际化 | 仅中文 |
| Consent 页面 | 自动授权 |