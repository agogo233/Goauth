# Goauth

Goauth 是一个精简的 OIDC Provider，专注于核心身份认证功能，使用 SQLite 数据库，适合小规模部署。

## 特性

- **OIDC Provider** - 完整的 OpenID Connect 支持
- **密码认证** - 支持 TOTP 二步验证
- **管理后台** - 用户/分组/客户端/邀请/代理认证管理
- **邀请注册** - 生成邀请链接，自动关联分组
- **ProxyAuth** - 支持 Traefik ForwardAuth 和 Nginx auth_request
- **单二进制** - 无外部依赖，SQLite 嵌入式数据库

## 快速开始

### 下载

```bash
# 下载预编译二进制
./goauth serve
```

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
    ports:
      - "3000:3000"
    volumes:
      - goauth-data:/app/data
    environment:
      - APP_OIDC_ISSUER=http://localhost:3000
      - APP_UI_APPNAME=Goauth

volumes:
  goauth-data:
```

## 配置

### 环境变量

所有配置使用 `APP_` 前缀：

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_SERVER_PORT` | 服务端口 | `3000` |
| `APP_SERVER_HOST` | 监听地址 | `0.0.0.0` |
| `APP_SERVER_ENVIRONMENT` | 环境 (development/production) | `development` |
| `APP_SERVER_APPURL` | 应用 URL | - |
| `APP_SERVER_BASEPATH` | 子路径部署（如 `/auth`） | `""` |
| `APP_SERVER_TIMEZONE` | 时区 | `UTC` |
| `APP_SERVER_COOKIEDOMAIN` | Cookie 域名 | 自动从 APPURL 提取 |
| `APP_SERVER_COOKIESECURE` | Cookie Secure (auto/true/false) | `auto` |
| `APP_SERVER_COOKIESAMESITE` | Cookie SameSite (strict/lax/none) | `lax` |
| `APP_SERVER_CORSALLOWORIGINS` | CORS 允许来源（逗号分隔） | 空（仅同源；development 下为 `*`） |
| `APP_SERVER_RATELIMIT` | 速率限制（次/分钟，0=禁用） | `100` |
| `APP_DATABASE_PATH` | SQLite 数据库路径 | `./data/goauth.db` |
| `APP_OIDC_ISSUER` | OIDC Issuer URL | 自动使用 APP_SERVER_APPURL |
| `APP_OIDC_ACCESSTOKENTTL` | Access Token 有效期 | `15m` |
| `APP_OIDC_IDTOKENTTL` | ID Token 有效期 | `30m` |
| `APP_OIDC_REFRESHTOKENTTL` | Refresh Token 有效期 | `168h` (7天) |
| `APP_OIDC_SESSIONTTL` | OIDC Session 有效期 | `720h` (30天) |
| `APP_SESSION_TTL` | 普通 Session 有效期 | `24h` |
| `APP_SESSION_TTLREMEMBER` | "记住我" Session 有效期 | `720h` (30天) |
| `APP_UI_APPNAME` | 应用名称 | `Goauth` |
| `APP_UI_APPCOLOR` | 主题颜色 | `#906bc7` |
| `APP_UI_SIGNUPENABLED` | 开放注册 | `true` |
| `APP_SECURITY_PASSWORDMIN` | 密码最小长度 | `8` |
| `APP_SECURITY_PASSWORDMINSCORE` | 密码强度分数 (0-4) | `3` |
| `APP_SECURITY_LOGINMAXATTEMPTS` | 登录失败次数限制 | `10` |
| `APP_SECURITY_LOGINBLOCKDURATION` | 封禁时长 (分钟) | `30` |
| `APP_SECURITY_TOTPMAXATTEMPTS` | TOTP 最大尝试次数 | `5` |
| `APP_SECURITY_AUDITLOGRETENTION` | 审计日志保留天数 | `90` |
| `APP_SECURITY_LOGINATTEMPTCLEANUP` | 登录尝试记录清理间隔 (小时) | `24` |
| `APP_SECURITY_AUTOAPPROVEUSERS` | 自动批准所有注册用户（测试用） | `false` |
| `APP_SECURITY_CRYPTOKEY` | AES-256-GCM 加密密钥（32字节 base64，自动生成则无需设置） | 自动生成 |
| `APP_LOGGING_LEVEL` | 日志级别 | `info` |

> 时长类变量支持 Go duration 格式（如 `15m`、`24h`、`720h`）；纯数字会被解析为纳秒，请务必带单位。

> **⚠️ 密钥文件**：首次启动自动生成 `./data/.goauth-keys`，包含 `cryptoKey`（AES 密钥）和 `cookieKeys`（会话签名密钥）。**此文件不可丢失**——删除后已加密数据（OIDC Token、RSA 私钥）将无法解密。可通过 `APP_SECURITY_CRYPTOKEY` 环境变量预置密钥。

### 配置文件

支持 YAML 格式配置文件：

```yaml
server:
  port: 3000
  host: 0.0.0.0
  environment: production

oidc:
  issuer: https://auth.example.com

ui:
  appName: "My Auth"
  appColor: "#4a90d9"
  signupEnabled: false

security:
  passwordMin: 10
  passwordMinScore: 4
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

## OIDC 客户端配置

在管理后台创建 OIDC 客户端后，配置你的应用：

```yaml
# 示例：Grafana OIDC 配置
auth:
  oidc:
    enabled: true
    name: Goauth
    issuer: https://auth.example.com
    clientId: your-client-id
    clientSecret: your-client-secret
    scopes: openid profile email
```

## ProxyAuth 配置

### Traefik ForwardAuth

```yaml
# docker-compose.yml
services:
  app:
    image: myapp
    labels:
      - "traefik.http.middlewares.goauth.forwardauth.address=http://goauth:3000/authz/forward-auth"
      - "traefik.http.middlewares.goauth.forwardauth.authResponseHeaders=X-User-Id,X-User-Name,X-User-Email"
      - "traefik.http.routers.app.middlewares=goauth@docker"
```

### Nginx auth_request

```nginx
server {
    location / {
        auth_request /authz;
        auth_request_set $user_id $upstream_http_x_user_id;
        auth_request_set $user_name $upstream_http_x_user_name;
        auth_request_set $user_email $upstream_http_x_user_email;
        proxy_set_header X-User-Id $user_id;
        proxy_set_header X-User-Name $user_name;
        proxy_set_header X-User-Email $user_email;
        proxy_pass http://app;
    }

    location = /authz {
        internal;
        proxy_pass http://goauth:3000/authz/auth-request;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }
}
```

## 构建

```bash
# 本地构建
go build -o goauth ./cmd/server

# Docker 构建
docker build -t goauth .
```

## 项目结构

```
goauth/
├── cmd/server/main.go        # 入口
├── internal/
│   ├── config/               # 配置管理
│   ├── db/                   # 数据库
│   ├── handler/              # HTTP 处理器
│   ├── middleware/           # 中间件
│   ├── model/                # 数据模型
│   ├── oidc/                 # OIDC Provider
│   ├── repo/                 # 数据访问层
│   ├── service/              # 业务逻辑层
│   └── util/                 # 工具函数
├── migrations/               # 数据库迁移
├── web/                      # 前端文件
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## 测试

本项目包含三层测试，覆盖单元、集成到端到端（E2E）：

| 层级 | 命令 | 说明 |
|------|------|------|
| 单元测试 | `make test` | Go 单元测试，覆盖 `internal/` 各包 |
| 集成测试 | `make test-integration` | 集成测试，覆盖 `tests/integration/`（真实 SQLite + HTTP 全链路） |
| E2E 测试 | `make test-e2e` | Playwright + Chromium，覆盖首次启动、认证、TOTP、管理后台、OIDC、邀请、ProxyAuth、会话、安全专项等 30 个 spec 文件 |

> `make test-all` 运行单元 + 集成测试。E2E 因需要浏览器和串行数据库状态，单独用 `make test-e2e` 运行。

### E2E 测试运行前提

E2E 依赖以下环境，首次运行时需先准备：

```bash
# 1. 确保 Go 工具链已安装（>= 1.26）
# 2. 编译服务器二进制（start-server.sh 依赖 bin/goauth）
make build

# 3. 安装 Playwright 依赖
cd tests/e2e && npm install

# 4. 下载 Chromium 浏览器
cd tests/e2e && npx playwright install chromium

# 5. 运行 E2E（自动清理数据库、启动服务器、创建固定管理员 e2e_admin）
make test-e2e
```

要点：
- E2E 通过 `tests/e2e/start-server.sh` 自动清理数据库、以测试配置（`APP_SECURITY_AUTOAPPROVEUSERS=true` 等）启动服务器，并创建固定管理员 `e2e_admin`，供各测试文件复用。
- 端口默认 `3000`，可用 `GOAUTH_BASE_URL` 覆盖；`APP_OIDC_ISSUER` 缺省为 `http://localhost:3000`。
- E2E 为单 worker 串行执行（数据库有状态），全量约 20-30 分钟。

## 安全特性

- **密码哈希** - bcrypt (默认 cost=12，可通过 `APP_SECURITY_BCRYPTCOST` 配置)
- **密码强度** - zxcvbn 检测
- **暴力破解防护** - 失败次数限制 + IP 封禁
- **会话管理** - 安全 Cookie + session token SHA-256 哈希存储
- **数据加密** - AES-256-GCM 加密 OIDC Token 和 RSA 私钥
- **审计日志** - 关键操作记录

## 功能概览

| 功能 | 支持 |
|------|------|
| 数据库 | SQLite |
| 前端 | Alpine.js |
| 邮件 | ❌ |
| Passkey | ❌ |
| 国际化 | 仅中文 |
| Consent 页面 | 自动授权 |

## License

MIT
