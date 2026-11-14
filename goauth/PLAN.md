# Goauth 版本计划

> [!NOTE]
> 本文档为项目初始设计规划，保留作历史参考。实际实现可能与本文档存在差异，请以代码和 `docs/` 目录下的文档为准。

## 概述

Goauth 是一个精简的 OIDC Provider，专注于核心功能，减少依赖和构建体积。

## 功能确认清单

| 功能 | 决定 |
|------|------|
| **前端技术栈** | Vanilla JS + Alpine.js（单页面应用） |
| **数据库** | SQLite3 |
| **OIDC** | 完整保留 |
| **认证方式** | 密码 + TOTP（含二维码） |
| **Passkey** | ❌ 移除 |
| **邮件功能** | ❌ 移除 |
| **国际化** | ❌ 移除，只保留中文 |
| **Consent页面** | ❌ 移除，自动授权 |
| **密码重置** | 管理员后台重置 |
| **用户审批** | 首个注册为管理员，后续需审批 |
| **管理员标识** | users表添加isAdmin字段 |
| **邀请注册** | 生成URL链接格式 `https://auth.example.com/invite/{token}` |
| **OIDC客户端创建** | 管理员在后台创建 |
| **Session存储** | SQLite独立sessions表 |
| **管理后台** | 完整管理（用户/客户端/分组/邀请/ProxyAuth） |
| **健康检查** | ✅ 保留 |
| **开发模式** | 简单重启 |
| **CDN降级** | Alpine.js本地备份 |

## 项目结构

```
goauth/
├── cmd/
│   └── server/
│       └── main.go                 # 入口
├── internal/
│   ├── config/
│   │   └── config.go               # 配置
│   ├── db/
│   │   └── sqlite.go               # SQLite连接
│   ├── handler/
│   │   ├── auth.go                 # 登录/注册
│   │   ├── oidc.go                 # OIDC端点
│   │   ├── proxy_auth.go           # ProxyAuth
│   │   ├── user.go                 # 用户管理
│   │   ├── admin.go                # 管理端点
│   │   ├── health.go               # 健康检查
│   │   └── interaction.go          # OIDC交互
│   ├── middleware/
│   │   ├── auth.go                 # 会话认证
│   │   ├── rate_limit.go           # 速率限制
│   │   ├── cors.go                 # CORS
│   │   ├── csrf.go                 # CSRF 防护
│   │   └── security_headers.go     # 安全响应头/CSP
│   ├── model/
│   │   └── models.go               # 数据模型
│   ├── oidc/
│   │   ├── provider.go             # OIDC Provider
│   │   └── storage.go              # OIDC Storage
│   ├── repo/
│   │   ├── user.go
│   │   ├── group.go
│   │   ├── oidc.go
│   │   ├── key.go
│   │   ├── invitation.go
│   │   └── proxy_auth.go
│   ├── service/
│   │   ├── auth.go                 # 认证服务
│   │   ├── user.go                 # 用户服务
│   │   ├── totp.go                 # TOTP服务
│   │   ├── password.go             # 密码服务
│   │   ├── invitation.go           # 邀请服务
│   │   └── group.go                # 分组服务
│   └── util/
│       ├── password.go             # 密码工具
│       ├── brute_force.go          # 暴力破解防护
│       └── crypto.go               # 加密工具
├── migrations/
│   └── 001_init.sql                # 数据库初始化
├── web/
│   ├── index.html                  # 单页面应用入口
│   ├── css/
│   │   └── style.css               # 样式
│   ├── js/
│   │   ├── alpine.min.js           # Alpine.js本地备份（CDN降级）
│   │   └── app.js                  # 主应用逻辑
│   └── assets/
│       └── logo.svg
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Go依赖

### 核心依赖
```go
github.com/gin-gonic/gin              // Web框架
github.com/zitadel/oidc/v3            // OIDC Provider
github.com/mattn/go-sqlite3           // SQLite驱动
github.com/jmoiron/sqlx               // SQL工具
github.com/golang-jwt/jwt/v5          // JWT
golang.org/x/crypto                   // bcrypt
```

### 安全依赖
```go
github.com/nbutton23/zxcvbn-go        // 密码强度
github.com/pquerna/otp                // TOTP
github.com/skip2/go-qrcode            // QR码生成
```

### 工具依赖
```go
github.com/rs/zerolog                 // 日志
github.com/knadh/koanf/v2             // 配置
github.com/joho/godotenv              // .env加载
github.com/google/uuid                // UUID生成
```

### 移除的依赖
```go
- github.com/go-webauthn/webauthn     // Passkey
- gopkg.in/gomail.v2                  // 邮件
- github.com/swaggo/*                 // Swagger
```

## 前端技术栈

### 核心
- **Alpine.js** (~15KB gzipped): 响应式框架
- **原生CSS**: 无框架依赖
- **Hash 路由**: 使用 `#/page` 格式，无需服务器端配置支持

### CDN引入
```html
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
```

### TOTP QR 码
- API 返回 base64 编码的 PNG 图片
- 前端使用 `data:image/png;base64,...` 格式直接展示

## API端点

### 公开端点
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| GET | `/ready` | 就绪检查 |
| GET | `/api/public/config` | 公开配置 |
| POST | `/api/public/password-strength` | 密码强度检查 |

### 认证端点
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 登录（body: `{username, password, rememberMe}`） |
| POST | `/api/auth/register` | 注册（支持邀请码，首个用户自动成为管理员） |
| POST | `/api/auth/totp` | TOTP 验证 |
| POST | `/api/auth/logout` | 登出 |

### OIDC端点
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/keys` | JWKS |
| GET, POST | `/authorize` | 授权（自动授权） |
| POST | `/oauth/token`（兼容 `/token`） | Token |
| GET, POST | `/userinfo` | UserInfo |
| POST | `/oauth/introspect`（兼容 `/introspect`） | 内省 |
| POST | `/revoke` | 撤销 |
| GET, POST | `/endsession` | 登出 |
| GET | `/interaction` | OIDC 交互（已登录用户自动完成授权） |
| ANY | `/api/cb` | OIDC 回调 |

### 用户端点（需登录）
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/user/me` | 当前用户信息 |
| PATCH | `/api/user/profile` | 更新资料 |
| PATCH | `/api/user/password` | 修改密码 |
| GET | `/api/user/sessions` | 会话列表 |
| DELETE | `/api/user/sessions/:id` | 终止指定会话 |
| GET | `/api/user/totp/backup-codes` | 生成 TOTP 备用码 |
| POST | `/api/user/totp/verify-backup-code` | 校验 TOTP 备用码 |
| DELETE | `/api/user/totp` | 移除TOTP |

### MFA 设置端点（待设置 MFA 的用户可访问）
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/mfa-setup/me` | 当前用户信息 |
| POST | `/api/mfa-setup/totp/setup` | 设置TOTP（返回 `{uri, qrBase64}`） |
| POST | `/api/mfa-setup/totp/verify` | 验证并启用 TOTP |

### 管理端点（需管理员）

#### 用户管理
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/users` | 用户列表 |
| GET | `/api/admin/users/:id` | 用户详情 |
| PATCH | `/api/admin/users/:id` | 更新用户 |
| POST | `/api/admin/users/:id/approve` | 审批用户 |
| POST | `/api/admin/users/:id/disable` | 禁用用户 |
| POST | `/api/admin/users/:id/enable` | 启用用户 |
| POST | `/api/admin/users/:id/reset-password` | 重置密码 |
| POST | `/api/admin/users/:id/admin` | 设置/取消管理员 |
| DELETE | `/api/admin/users/:id/totp` | 移除用户TOTP |
| DELETE | `/api/admin/users/:id` | 删除用户 |

#### 分组管理
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/groups` | 分组列表 |
| POST | `/api/admin/groups` | 创建分组 |
| PATCH | `/api/admin/groups/:id` | 更新分组 |
| DELETE | `/api/admin/groups/:id` | 删除分组 |
| GET | `/api/admin/groups/:id/members` | 分组成员列表 |
| POST | `/api/admin/groups/:id/members` | 添加成员 |
| DELETE | `/api/admin/groups/:id/members/:userId` | 移除成员 |

#### 客户端管理
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/clients` | 客户端列表 |
| POST | `/api/admin/clients` | 创建客户端 |
| PATCH | `/api/admin/clients/:id` | 更新客户端 |
| DELETE | `/api/admin/clients/:id` | 删除客户端 |

#### 邀请管理
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/invitations` | 邀请列表 |
| POST | `/api/admin/invitations` | 创建邀请 |
| DELETE | `/api/admin/invitations/:id` | 删除邀请 |

            # ProxyAuth管理
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/proxy-auth` | ProxyAuth列表 |
| POST | `/api/admin/proxy-auth` | 创建ProxyAuth |
| PATCH | `/api/admin/proxy-auth/:id` | 更新ProxyAuth |
| DELETE | `/api/admin/proxy-auth/:id` | 删除ProxyAuth |

#### 审计日志
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/audit-logs` | 审计日志列表 |

### ProxyAuth端点
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/authz/forward-auth` | Traefik ForwardAuth |
| GET | `/authz/auth-request` | Nginx Auth Request |

## 数据库Schema

```sql
-- 用户表
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  username TEXT UNIQUE NOT NULL,
  name TEXT,
  passwordHash TEXT,
  isAdmin INTEGER DEFAULT 0,        -- 管理员标识
  emailVerified INTEGER DEFAULT 0,
  approved INTEGER DEFAULT 0,
  mfaRequired INTEGER DEFAULT 0,
  disabled INTEGER DEFAULT 0,       -- 禁用标识
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

-- Session表
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  userId TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  amr TEXT,                         -- Authentication Methods References
  rememberMe INTEGER DEFAULT 0,     -- 是否为"记住我"会话
  expiresAt TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);

-- 分组表
CREATE TABLE groups (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  mfaRequired INTEGER DEFAULT 0,
  createdBy TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

-- 用户-分组关联
CREATE TABLE user_groups (
  userId TEXT NOT NULL,
  groupId TEXT NOT NULL,
  PRIMARY KEY (userId, groupId),
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
);

-- TOTP配置
CREATE TABLE totp (
  id TEXT PRIMARY KEY,
  userId TEXT NOT NULL UNIQUE,
  secret TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);

-- 密钥存储
CREATE TABLE keys (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  expiresAt TEXT NOT NULL,
  createdAt TEXT NOT NULL
);

-- OIDC Payloads
CREATE TABLE oidc_payloads (
  id TEXT NOT NULL,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,
  grantId TEXT,
  userCode TEXT,
  uid TEXT,
  expiresAt TEXT,
  consumedAt TEXT,
  accountId TEXT,
  PRIMARY KEY (id, type)
);

-- OIDC 客户端
CREATE TABLE clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret TEXT,
  redirectUris TEXT NOT NULL,       -- JSON array
  postLogoutUris TEXT,              -- JSON array
  scopes TEXT NOT NULL,             -- JSON array
  grantTypes TEXT NOT NULL,         -- JSON array
  responseTypes TEXT NOT NULL,      -- JSON array
  tokenEndpointAuth TEXT DEFAULT 'client_secret_basic',
  trusted INTEGER DEFAULT 0,        -- 可信客户端，自动授权
  createdBy TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  FOREIGN KEY (createdBy) REFERENCES users(id)
);

-- Consent
CREATE TABLE consent (
  userId TEXT NOT NULL,
  clientId TEXT NOT NULL,
  scope TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  expiresAt TEXT NOT NULL,
  PRIMARY KEY (userId, clientId)
);

-- 邀请
CREATE TABLE invitations (
  id TEXT PRIMARY KEY,
  email TEXT,
  username TEXT,
  name TEXT,
  challenge TEXT NOT NULL,
  emailVerified INTEGER DEFAULT 0,
  createdBy TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  expiresAt TEXT NOT NULL,
  FOREIGN KEY (createdBy) REFERENCES users(id)
);

-- 邀请-分组关联
CREATE TABLE invitation_groups (
  invitationId TEXT NOT NULL,
  groupId TEXT NOT NULL,
  PRIMARY KEY (invitationId, groupId),
  FOREIGN KEY (invitationId) REFERENCES invitations(id) ON DELETE CASCADE,
  FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
);

-- ProxyAuth
CREATE TABLE proxy_auth (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL UNIQUE,
  mfaRequired INTEGER DEFAULT 0,
  maxSessionLength INTEGER,
  createdBy TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  FOREIGN KEY (createdBy) REFERENCES users(id)
);

-- ProxyAuth-分组关联
CREATE TABLE proxy_auth_groups (
  proxyAuthId TEXT NOT NULL,
  groupId TEXT NOT NULL,
  PRIMARY KEY (proxyAuthId, groupId),
  FOREIGN KEY (proxyAuthId) REFERENCES proxy_auth(id) ON DELETE CASCADE,
  FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
);

-- 系统标志
CREATE TABLE flags (
  name TEXT PRIMARY KEY,
  value TEXT,
  createdAt TEXT NOT NULL
);

-- 登录尝试记录（暴力破解防护）
CREATE TABLE login_attempts (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  ip TEXT NOT NULL,
  success INTEGER DEFAULT 0,
  createdAt TEXT NOT NULL
);

-- 审计日志
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  actorId TEXT,
  targetId TEXT,
  details TEXT,                     -- JSON
  ip TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  FOREIGN KEY (actorId) REFERENCES users(id) ON DELETE SET NULL
);

-- 索引
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_userId ON sessions(userId);
CREATE INDEX idx_sessions_expiresAt ON sessions(expiresAt);
CREATE INDEX idx_oidc_payloads_expiresAt ON oidc_payloads(expiresAt);
CREATE INDEX idx_oidc_payloads_accountId ON oidc_payloads(accountId);
CREATE INDEX idx_users_approved ON users(approved);
CREATE INDEX idx_users_disabled ON users(disabled);
CREATE INDEX idx_login_attempts_username ON login_attempts(username);
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip);
CREATE INDEX idx_login_attempts_createdAt ON login_attempts(createdAt);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_createdAt ON audit_log(createdAt);
```

## 配置文件

### 环境变量
```bash
# 服务器
APP_SERVER_PORT=3000
APP_SERVER_HOST=0.0.0.0
APP_SERVER_ENVIRONMENT=production
APP_SERVER_APPURL=https://auth.example.com

# 数据库
APP_DATABASE_PATH=./data/goauth.db

# OIDC
APP_OIDC_ACCESSTOKENTTL=15
APP_OIDC_IDTOKENTTL=30
APP_OIDC_REFRESHTOKENTTL=7
APP_OIDC_SESSIONTTL=90
APP_SESSION_TTL=24           # 普通登录 Session TTL（小时）
APP_SESSION_TTLREMEMBER=720  # "记住我" Session TTL（小时，默认30天）

# 安全
APP_SECURITY_CRYPTOKEY=auto-generated
APP_SECURITY_PASSWORDMIN=8
APP_SECURITY_PASSWORDMINSCORE=3
APP_SECURITY_LOGINMAXATTEMPTS=10
APP_SECURITY_LOGINBLOCKDURATION=30

# UI
APP_UI_APPNAME=Goauth
APP_UI_APPCOLOR=#906bc7
APP_UI_SIGNUPENABLED=true

# 日志
APP_LOGGING_LEVEL=info
APP_LOGGING_FORMAT=text            # text/json
```

### YAML配置
```yaml
server:
  port: 3000
  environment: production
  appurl: "https://auth.example.com"

database:
  path: "./data/goauth.db"

oidc:
  accesstokenttl: 15
  idtokenttl: 30
  refreshtokenttl: 7
  sessionttl: 90

session:
  ttl: 24              # 普通登录 Session TTL（小时）
  ttlRemember: 720     # "记住我" Session TTL（小时，默认30天）

security:
  passwordmin: 8
  passwordminscore: 3
  loginmaxattempts: 10
  loginblockduration: 30

ui:
  appname: "Goauth"
  appcolor: "#906bc7"
  signupenabled: true

logging:
  level: info
  format: text
```

## 构建产物大小

| 组件 | 大小 |
|------|------|
| Go二进制（linux/amd64） | ~12MB |
| 前端静态文件 | ~30KB |
| Docker镜像（alpine基础） | ~25MB |
| Docker镜像（scratch基础） | ~15MB |

对比现有版本~100MB，**减少75-85%**。

## 实现顺序

1. **Phase 1: 核心框架**
   - [ ] go.mod 配置
   - [ ] main.go 入口
   - [ ] config 配置加载
   - [ ] db SQLite连接
   - [ ] model 数据模型

2. **Phase 2: OIDC核心**
   - [ ] oidc/provider.go
   - [ ] oidc/storage.go
   - [ ] handler/oidc.go

3. **Phase 3: 认证系统**
   - [ ] service/auth.go
   - [ ] service/password.go
   - [ ] handler/auth.go
   - [ ] middleware/auth.go

4. **Phase 4: TOTP**
   - [ ] service/totp.go
   - [ ] handler/totp相关

5. **Phase 5: 用户管理**
   - [ ] repo/user.go
   - [ ] service/user.go
   - [ ] handler/user.go

6. **Phase 6: 管理后台**
   - [ ] repo/group.go
   - [ ] repo/invitation.go
   - [ ] repo/proxy_auth.go
   - [ ] handler/admin.go

7. **Phase 7: 前端**
   - [ ] web/index.html（含CDN降级逻辑）
   - [ ] web/css/style.css
   - [ ] web/js/app.js（含URL路由同步）
   - [ ] web/js/alpine.min.js（本地备份）

8. **Phase 8: 部署配置**
   - [ ] Dockerfile
   - [ ] docker-compose.yml
   - [ ] Makefile
   - [ ] README.md

## 安全设计

### 密码
- 使用 bcrypt 哈希（cost 可配置，默认 12）
- 使用 zxcvbn 检测密码强度
- 最小长度可配置（默认8）
- 最小强度分数可配置（默认3）

### 暴力破解防护
- 用户级别：连续失败N次后封禁M分钟
- IP级别：同一IP失败过多后封禁
- 登录尝试记录存储在数据库，重启后保持有效
- 可配置阈值和时长
- 默认：10次失败封禁30分钟

### 会话管理
- Session存储在SQLite独立表
- 支持多设备登录
- 普通登录 Session TTL 可配置（默认24小时），"记住我" Session TTL 可配置（默认30天）
- OIDC Session TTL 可配置（默认30天，自 2026-11 安全基线起从 90 天缩短）
- 登录后的每次请求会滑动续期 Session
- 登出时主动删除Session

### 存储加密
- 敏感数据（TOTP密钥等）加密存储
- CryptoKey自动生成并持久化到数据库目录下的 `.goauth-keys` 文件

### 用户状态管理
- 支持用户禁用（disabled字段）
- 管理员可临时禁用/启用用户
- 禁用用户无法登录，Session立即失效

### 审计日志
- 记录关键操作：登录、登出、注册、密码重置、用户审批、用户禁用等
- 存储在 audit_log 表
- 包含操作者、目标、详情、IP等信息

### 管理员安全
- 首个注册用户自动成为管理员
- 管理员可以设置/取消其他用户的管理员权限
- 管理员操作记录审计日志

## 开发指南

### CLI命令

```bash
# 启动服务器（默认命令）
goauth serve [--config config.yaml]

# 数据库迁移
goauth migrate [--config config.yaml]

# 重置用户密码
goauth reset-password -u <username>

# 创建管理员
goauth create-admin -u <username> -p <password>

# 查看版本
goauth --version
```

### 邀请链接流程

```
1. 管理员创建邀请
2. 生成链接 https://auth.example.com/invite/{token}
3. 管理员手动发送给用户
4. 用户点击链接
5. 跳转注册页面，自动填充邀请信息
6. 用户完成注册
7. 自动关联邀请中的分组
8. 标记为已验证（如果邀请设置了emailVerified）
```

### 本地开发
```bash
# 安装依赖
make deps

# 运行
make run

# 或直接运行
go run ./cmd/server
```

### 构建
```bash
# 构建二进制
make build

# 构建Docker镜像
make docker

# 运行Docker
make docker-run
```

### 测试
```bash
# 运行测试
make test

# 运行lint
make lint
```

## 许可证

MIT License
