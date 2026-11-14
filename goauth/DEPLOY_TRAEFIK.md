# Goauth with Traefik 部署指南

## 快速启动

### 1. 修改配置

编辑 `docker-compose.traefik.yml`，替换以下域名：
- `auth.yourdomain.com` → 你的 Goauth 域名
- `app.yourdomain.com` → 你的受保护应用域名（如使用）

### 2. 启动服务

```bash
docker-compose -f docker-compose.traefik.yml up -d
```

### 3. 创建管理员账户

```bash
docker exec goauth ./goauth create-admin -u admin -p YourSecurePassword123
```

## Traefik 配置说明

### 路由器（Routers）

| 名称 | 域名 | 入口 | TLS |
|------|------|------|-----|
| goauth-http | `auth.yourdomain.com` | web (80) | 自动重定向到 HTTPS |
| goauth-https | `auth.yourdomain.com` | websecure (443) | Let's Encrypt |

### 中间件（Middleware）

`goauth-auth` - Forward Auth 中间件，用于保护其他服务：

```yaml
- "traefik.http.middlewares.goauth-auth.forwardauth.address=http://goauth:3000/authz/forward-auth"
```

## 保护其他服务

在要保护的服务上添加 label：

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=goauth-auth"
```

Traefik 会将请求先发送到 Goauth 进行认证，认证通过后：
- 响应头会携带 `X-User-Id`、`X-User-Name`、`X-User-Email`
- 配合 `authResponseHeaders`，后端服务可通过这些 header 识别用户

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_SERVER_APPURL` | Goauth 外部访问 URL | 必填 |
| `APP_SERVER_BASEPATH` | 子路径部署（可选） | `""` |
| `APP_SERVER_COOKIEDOMAIN` | Cookie 作用域域名（可选） | `""` |
| `APP_SERVER_COOKIESECURE` | Cookie Secure 属性：`auto`/`true`/`false` | `auto` |
| `APP_SERVER_COOKIESAMESITE` | Cookie SameSite 属性：`strict`/`lax`/`none` | `lax` |
| `APP_UI_APPNAME` | 应用名称 | `Goauth` |
| `APP_UI_SIGNUPENABLED` | 允许用户注册 | `true` |
| `APP_SERVER_RATELIMIT` | 速率限制（次/分钟，0=禁用） | `100` |

## Cookie 安全配置

### Secure 属性

控制 Cookie 是否仅通过 HTTPS 传输：

- `auto`（默认）：根据 `APP_SERVER_APPURL` 自动判断，`https://` 开头则启用
- `true`：强制启用，仅 HTTPS 环境使用
- `false`：强制禁用，本地开发 HTTP 环境使用

### SameSite 属性

控制 Cookie 的跨站发送行为：

- `lax`（默认）：允许安全的跨站请求携带 Cookie（推荐，平衡安全与可用性）
- `strict`：完全禁止跨站发送 Cookie（最安全，可能影响从外部链接跳转的登录状态）
- `none`：允许所有跨站请求携带 Cookie（需要 Secure=true，适用于 iframe 嵌入场景）

### 生产环境推荐配置

```yaml
environment:
  - APP_SERVER_APPURL=https://auth.yourdomain.com
  - APP_SERVER_COOKIESECURE=auto    # 自动启用 Secure
  - APP_SERVER_COOKIESAMESITE=lax   # 默认值，推荐
```

### 本地开发配置

```yaml
environment:
  - APP_SERVER_APPURL=http://localhost:3000
  - APP_SERVER_COOKIESECURE=false   # HTTP 环境必须禁用
  - APP_SERVER_COOKIESAMESITE=lax
```

## 证书配置

如需使用 Let's Encrypt，添加 certresolver：

```yaml
- "traefik.http.routers.goauth-https.tls.certresolver=letsencrypt"
```

并在 Traefik 启动命令中配置：
```bash
--certificatesresolvers.letsencrypt.acme.email=your @email.com
--certificatesresolvers.letsencrypt.acme.storage=/data/acme.json
--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web
```

## 健康检查

- 健康状态：`http://localhost:3000/health`
- 就绪状态：`http://localhost:3000/ready`

## 日志查看

```bash
# Goauth 日志
docker logs -f goauth

# Traefik 日志
docker logs -f traefik
```

## 停止服务

```bash
docker-compose -f docker-compose.traefik.yml down
```
