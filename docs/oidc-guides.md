# OIDC 应用配置指南

以下指南中，当选项设置为默认值时可能会被省略。

> [!TIP]
> 占位符用于常见设置，如 `your-client-id`、`your-client-secret`、`your-admin-role`、`https://app-name.example.com` 和 `从 Goauth OIDC 信息复制`。OIDC（端点）信息可以在管理员 OIDC 和 OIDC 应用页面的下拉标签中找到，是 OIDC 相关端点 URL 的推荐来源。

> [!CAUTION]
> Client ID 在 OIDC 应用之间**必须**唯一。Client Secret **必须**是长且随机生成的。OIDC 应用页面上的 Client Secret 字段可以随机生成并复制到剪贴板供 OIDC 应用使用。Client Secret 在磁盘上加密存储。

> [!NOTE]
> 公共 OIDC 应用可以通过在 OIDC 应用页面的 `Auth Method` 下拉菜单中选择 `None (Public)` 选项来配置。这些 OIDC 应用不需要 Client Secret，但需要 PKCE，你的公共 OIDC 应用应该提供。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/actual-budget.svg" width="28" /> Actual Budget

Actual Budget can be set up to use Goauth as an OIDC Provider in three ways: through Environment Variables, Web GUI, or Config File. See the [Actual Budget OAuth Documentation](https://actualbudget.org/docs/config/oauth-auth/) for full details.

**Environment Variables:**

```bash
ACTUAL_OPENID_DISCOVERY_URL="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
ACTUAL_OPENID_CLIENT_ID="your-client-id"
ACTUAL_OPENID_CLIENT_SECRET="your-client-secret"
ACTUAL_OPENID_SERVER_HOSTNAME="https://actual.example.com"

# Optional
# ACTUAL_OPENID_ENFORCE="true"
# ACTUAL_TOKEN_EXPIRATION="never"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://actual.example.com/openid/callback
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/arcane.svg" width="28" /> Arcane

Arcane can be set up to use Goauth as an OIDC Provider in two ways: through the Web GUI or through Environment Variables. See the [Arcane SSO Documentation](https://arcane.ofkm.dev/docs/configuration/sso) for full details.

**Environment Variables:**

```bash
OIDC_ENABLED="true"
OIDC_CLIENT_ID="your-client-id"
OIDC_CLIENT_SECRET="your-client-secret"
OIDC_ISSUER_URL="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
OIDC_SCOPES="openid email profile groups"
OIDC_ADMIN_CLAIM="groups"
OIDC_ADMIN_VALUE="your-admin-role"

# Optional: Merge accounts by email address
# OIDC_MERGE_ACCOUNTS="true"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://arcane.example.com/auth/oidc/callback
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/autocaliweb.svg" width="28" /> AutoCaliWeb

In AutoCaliWeb:

1. Navigate to **Settings** → **Configuration** → **Edit Basic Configuration** → **Feature Configuration**
2. In the **Login Type** dropdown, select `Use OAuth`.
3. Scroll down to **Generic** Fill out the config as follows:

**AutoCaliWeb OAuth Configuration:**

```
generic OAuth Client Id: your-client-id
generic OAuth Client Secret: your-client-secret
generic OAuth scope: openid profile email
generic OAuth Metadata URL: Copy from Goauth OIDC Info (Well-Known Endpoint)
generic OAuth Username mapper: preferred_username
generic OAuth Email mapper: email
generic OAuth Login Button: Goauth
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://autocaliweb.example.com/login/generic/authorized
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/beszel.svg" width="28" /> Beszel

Follow the [Beszel OAuth Guide](https://beszel.dev/guide/oauth) and select `OpenID Connect (oidc)` from the **Add Provider** dropdown.

**Beszel OAuth Configuration:**

```
Client ID: your-client-id
Client Secret: your-client-secret
Auth URL: Copy from Goauth OIDC Info (Authorization Endpoint)
Token URL: Copy from Goauth OIDC Info (Token Endpoint)
Fetch user info from: User info URL
User info URL: Copy from Goauth OIDC Info (UserInfo Endpoint)
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://beszel.example.com/api/oauth2-redirect
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/bytestash.svg" width="28" /> ByteStash

**Environment Variables:**

```bash
OIDC_ENABLED="true"
OIDC_DISPLAY_NAME="Goauth"
OIDC_ISSUER_URL="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
OIDC_CLIENT_ID="your-client-id"
OIDC_CLIENT_SECRET="your-client-secret"
OIDC_SCOPES="openid profile email groups"

# Optional: Disable internal accounts to force OIDC-only authentication
# DISABLE_INTERNAL_ACCOUNTS="true"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://bytestash.example.com/api/auth/callback
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/cloudflare.svg" width="28" /> Cloudflare ZeroTrust

Navigate to the **[Cloudflare ZeroTrust Dashboard](https://dash.teams.cloudflare.com)** > **Settings** > **Authentication**. In the `Login methods` tab, select `Add new` and choose `OpenID Connect`.

**Cloudflare Configuration:**

```
Name: Goauth
App ID: your-client-id
Client secret: your-client-secret
Auth URL: Copy from Goauth OIDC Info (Authorization Endpoint)
Token URL: Copy from Goauth OIDC Info (Token Endpoint)
Certificate URL: Copy from Goauth OIDC Info (JWKs Endpoint)
Proof Key for Code Exchange (PKCE): ON
OIDC Claims: mail, preferred_username
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://your-team-name.cloudflareaccess.com/cdn-cgi/access/callback
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/dawarich.svg" width="28" /> Dawarich

See [Dawarich v0.36.0 release notes](https://github.com/Freika/dawarich/discussions/1969) for more details on OIDC environment variables.

**Environment Variables:**

```bash
OIDC_CLIENT_ID="your-client-id"
OIDC_CLIENT_SECRET="your-client-secret"
OIDC_ISSUER="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
OIDC_REDIRECT_URI="https://dawarich.example.com/users/auth/openid_connect/callback"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://dawarich.example.com/users/auth/openid_connect/callback
```

<br>

## <img src="https://dockhand.pro/images/logo-dark.webp" width="28" /> Dockhand

Navigate to **Settings** > **Authentication** > **SSO** in Dockhand. Click **Add provider**. See the [Dockhand OIDC Configuration Guide](https://dockhand.pro/manual/#appendix-oidc) for detailed setup instructions.

**Dockhand SSO Configuration:**

```
Name: Goauth
Issuer URL: Copy from Goauth OIDC Info (OIDC Issuer Endpoint)
Client ID: your-client-id
Client Secret: your-client-secret
Redirect URI: https://dockhand.example.com/api/auth/oidc/callback
Scopes: openid profile email groups

# Optional Claim Mappings
Username claim: preferred_username
Email claim: email
Display name claim: name
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://dockhand.example.com/api/auth/oidc/callback
```

> [!NOTE]
> 基于角色的访问控制和组映射功能需要企业版许可证。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/grist.svg" width="28" /> Grist

**Environment Variables:**

```bash
GRIST_OIDC_IDP_ISSUER="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
GRIST_OIDC_IDP_CLIENT_ID="your-client-id"
GRIST_OIDC_IDP_CLIENT_SECRET="your-client-secret"
GRIST_OIDC_SP_IGNORE_EMAIL_VERIFIED="true"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://grist.example.com/oauth2/callback
PostLogout URL: https://grist.example.com/signed-out
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/immich.svg" width="28" /> Immich

Navigate to **Administration** > **Settings** > **OAuth Settings** in Immich. See the [Immich OAuth Documentation](https://immich.app/docs/administration/oauth) for full details.

**Immich OAuth Configuration:**

```
Issuer URL: Copy from Goauth OIDC Info (Well-Known Endpoint)
Client ID: your-client-id
Client Secret: your-client-secret
Scope: openid profile email
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs:
  - https://immich.example.com/auth/login
  - https://immich.example.com/user-settings
  - app.immich:///oauth-callback
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/jellyfin.svg" width="28" /> Jellyfin

Install the [Jellyfin SSO Plugin](https://github.com/9p4/jellyfin-plugin-sso). Navigate to **Dashboard** > **Plugins** > **Catalog** > **Repositories** and add:

```
Name: Jellyfin SSO
URL: https://raw.githubusercontent.com/9p4/jellyfin-plugin-sso/manifest-release/manifest.json
```

Install **SSO-Auth** from the Catalog and restart Jellyfin. Then navigate to **Dashboard** > **Plugins** > **My Plugins** > **SSO-Auth**:

**Jellyfin SSO-Auth Configuration:**

```
Name: Goauth
OID Endpoint: Copy from Goauth OIDC Info (OIDC Issuer Endpoint)
OpenID Client ID: your-client-id
OID Secret: your-client-secret
Enabled: Yes
Enable Authorization by Plugin: Yes
Enable All Folders: Yes
Roles: your-user-role
Admin Roles: your-admin-role
Role Claim: groups
Request Additional Scopes: groups
Set default username claim: preferred_username
Scheme Override: https
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://jellyfin.example.com/sso/OID/redirect/Goauth
```

> [!TIP]
> 请按照 [Jellyfin SSO Plugin](https://github.com/9p4/jellyfin-plugin-sso) 仓库中的说明，在 Jellyfin 登录页面上添加 SSO 登录按钮。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/jellyseerr.svg" width="28" /> Jellyseerr

> [!CAUTION]
> Jellyseerr 的 OIDC 支持目前处于**实验阶段**，仅在预览镜像中可用：`fallenbagel/jellyseerr:preview-OIDC`。此功能正在积极开发中，可能存在 bug 或破坏性更改。

Navigate to **Settings** from the left-hand menu in Jellyseerr. Scroll to the **OpenID Connect** section. See the [Jellyseerr OIDC Discussion](https://github.com/fallenbagel/jellyseerr/discussions/1529) for more details.

**Jellyseerr OpenID Connect Configuration:**

```
Enable OpenID Connect Sign-In: ☑ (checked)
Display Name: Goauth
Issuer URL: Copy from Goauth OIDC Info (OIDC Issuer Endpoint)
Client ID: your-client-id
Client Secret: your-client-secret
Scopes: openid profile email groups
```

Scroll down and click **Save Changes**.

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://jellyseerr.example.com/login?provider=goauth&callback=true
```

> [!TIP]
> - 如果在反向代理后运行，请在 Jellyseerr 设置中启用 **Proxy Support**
> - 确保正确配置 HTTP/HTTPS 协议以避免重定向 URI 问题

> [!NOTE]
> Jellyseerr 正在合并到统一仓库 [seerr-team/seerr](https://github.com/seerr-team/seerr)。合并完成且稳定版本支持 OIDC 后，本文档将更新。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/png/komodo.png" width="28" /> Komodo

> [!NOTE]
> 如果配置了环境变量 `KOMODO_DISABLE_USER_REGISTRATION=true`，Komodo 不会通过 OIDC 自动配置用户。如果你想阻止新用户注册：
> 1. *临时*将环境变量 `KOMODO_DISABLE_USER_REGISTRATION` 设置为 `false`
> 2. 重启 Komodo 核心容器
> 3. 通过 Goauth OIDC 登录 Komodo 创建一个禁用账户
> 4. 以管理员身份登录 Komodo，进入 Settings -> Users，启用新创建的账户，类型设为 `Oidc`。可选择将其设为管理员。
> 5. 将环境变量改回 `KOMODO_DISABLE_USER_REGISTRATION=true`
> 6. 重启 Komodo 核心容器

**Environment Variables:**

```bash
KOMODO_OIDC_ENABLED=true
KOMODO_OIDC_PROVIDER="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
KOMODO_OIDC_CLIENT_ID="your-client-id"
KOMODO_OIDC_CLIENT_SECRET="your-client-secret"

# Temporarily:
KOMODO_DISABLE_USER_REGISTRATION=false
# But generally:
KOMODO_DISABLE_USER_REGISTRATION=true
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://komodo.example.com/auth/oidc/callback
```


<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/png/manyfold.png" width="28" /> Manyfold

**Environment Variables:**

```bash
MULTIUSER="true"
PUBLIC_HOSTNAME="manyfold.example.com"
OIDC_CLIENT_ID="your-client-id"
OIDC_CLIENT_SECRET="your-client-secret"
OIDC_ISSUER="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
OIDC_NAME="Goauth"

# Optional: Force OIDC login
# FORCE_OIDC="true"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://manyfold.example.com/users/auth/openid_connect/callback
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/mastodon.svg" width="28" /> Mastodon

**Environment Variables:**

```bash
OIDC_ENABLED="true"
OIDC_DISCOVERY="true"
OIDC_ISSUER="Copy from Goauth OIDC Info (OIDC Issuer Endpoint)"
OIDC_DISPLAY_NAME="Goauth"
OIDC_CLIENT_ID="your-client-id"
OIDC_CLIENT_SECRET="your-client-secret"
OIDC_SCOPE="openid,profile,email"
OIDC_UID_FIELD="preferred_username"
OIDC_REDIRECT_URI="https://mastodon.example.com/auth/auth/openid_connect/callback"
OIDC_SECURITY_ASSUME_EMAIL_IS_VERIFIED="true"

# Optional: Allow reattaching auth providers
# ALLOW_UNSAFE_AUTH_PROVIDER_REATTACH="true"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://mastodon.example.com/auth/auth/openid_connect/callback
```

<br>

## <img src="https://raw.githubusercontent.com/usememos/.github/refs/heads/main/assets/logo-rounded.png" width="28" /> Memos

Connect to Memos as an admin user. Click on the user icon at the bottom left, then on **Settings**, and finally on **SSO**. Click on the **Create** button and select **Custom** from the **Template** menu.

**Memos SSO Configuration:**

```
Client ID: your-client-id
Client Secret: your-client-secret
Authorization endpoint: Copy from Goauth OIDC Info (Authorization Endpoint)
Token endpoint: Copy from Goauth OIDC Info (Token Endpoint)
User endpoint: Copy from Goauth OIDC Info (UserInfo Endpoint)
Scopes: openid profile email offline_access
Identifier: preferred_username
Display Name: name
Email: email
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://memos.example.com/auth/callback
```

> [!NOTE]
> Scopes 用空格分隔，**不是**逗号。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/open-webui.svg" width="28" /> Open WebUI

In the following example, only users in Goauth with the group `users` or `admins` will be able to log in. Adjust these group names as needed.

**Environment Variables:**

```bash
WEBUI_URL="https://openwebui.example.com"
ENABLE_OAUTH_SIGNUP="true"
OAUTH_MERGE_ACCOUNTS_BY_EMAIL="true"
OAUTH_CLIENT_ID="your-client-id"
OAUTH_CLIENT_SECRET="your-client-secret"
OPENID_PROVIDER_URL="Copy from Goauth OIDC Info (Well-Known Endpoint)"
OAUTH_PROVIDER_NAME="Goauth"
OAUTH_SCOPES="openid profile groups email"
ENABLE_OAUTH_ROLE_MANAGEMENT="true"
OAUTH_ROLES_CLAIM="groups"
OAUTH_ALLOWED_ROLES="users,admins"
OAUTH_ADMIN_ROLES="admins"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://openwebui.example.com/oauth/oidc/callback
```

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/pangolin.svg" width="28" /> Pangolin

Navigate to your Pangolin instance and follow the [OAuth/OIDC Guide](https://docs.pangolin.net/manage/identity-providers/openid-connect) in the Pangolin documentation.

**Pangolin OAuth Configuration:**

```
Client ID: your-client-id
Client Secret: your-client-secret
Auth URL: Copy from Goauth OIDC Info (Authorization Endpoint)
Token URL: Copy from Goauth OIDC Info (Token Endpoint)
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://pangolin.example.com/auth/idp/1/oidc/callback
```

> [!NOTE]
> 在 Pangolin 设置中创建 Goauth 作为身份提供商后会显示重定向 URL。如果你配置了多个 OIDC 提供商，回调路径可能会有所不同（例如 `/auth/idp/2/oidc/callback`）。

> [!TIP]
> 在 Pangolin 中配置 Goauth 作为身份提供商时，你可以启用自动用户创建，或者在 Pangolin 组织设置中手动创建用户，使用他们的 OpenID Connect ID 作为用户名。ID 格式为 `XXXXXXXX-XXXX-XXXX-XXXXXXXXXXXX`，可以在查看用户资料时的 Goauth URL 中找到。用户在 Pangolin 中将显示其邮箱，而不是 ID。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/paperless-ngx.svg" width="28" /> Paperless-ngx

**Environment Variables:**

```bash
PAPERLESS_APPS="allauth.socialaccount.providers.openid_connect"
PAPERLESS_SOCIALACCOUNT_PROVIDERS='{"openid_connect": {"OAUTH_PKCE_ENABLED": true, "APPS": [{"provider_id": "goauth","name": "Goauth","client_id": "your-client-id","secret": "your-client-secret","settings": {"fetch_userinfo": true,"server_url": "https://goauth.example.com/oidc","token_auth_method": "client_secret_basic"}}]}}'

# Optional: Enable during initial setup if signups are disabled
# PAPERLESS_SOCIALACCOUNT_ALLOW_SIGNUPS="true"

# Optional: Disable local login after OIDC is configured
# PAPERLESS_DISABLE_REGULAR_LOGIN="true"
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://paperless.example.com/accounts/oidc/goauth/login/callback/
```

> [!NOTE]
> 如果环境中设置了 `PAPERLESS_SOCIALACCOUNT_ALLOW_SIGNUPS` 为 `false`，请临时将其设置为 `true` 以完成初始配置，然后再改回 `false`。

> [!TIP]
> 将现有本地用户关联到 Goauth：
> - 在 Paperless 登录界面点击 Goauth 按钮登录
> - 当提示注册时，不要继续
> - 使用本地用户登录，进入 **Profile**
> - 将本地账户关联到 Goauth - Goauth 邮箱现在应该出现在已连接的第三方账户中

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/portainer.svg" width="28" /> Portainer

Navigate to **Settings** > **Authenticate** in Portainer. Select **OAuth** from the Authentication Methods, then select **Custom** OAuth Provider.

**Portainer OAuth Configuration:**

```
Client ID: your-client-id
Client secret: your-client-secret
Authorization URL: Copy from Goauth OIDC Info (Authorization Endpoint)
Access token URL: Copy from Goauth OIDC Info (Token Endpoint)
Resource URL: Copy from Goauth OIDC Info (UserInfo Endpoint)
Redirect URL: https://portainer.example.com
User identifier: preferred_username
Scopes: openid profile groups email
Auth Style: In Params
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://portainer.example.com
```

> [!NOTE]
> Scopes 用空格分隔，**不是**逗号。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons@main/svg/proxmox.svg" width="28" /> Proxmox PVE

Proxmox PVE can be set up to use Goauth as an OIDC Provider in two ways: through Web GUI or Config File. See the [Proxmox PVE Authentication Realms Documentation](https://pve.proxmox.com/wiki/User_Management#pveum_authentication_realms) for full details.

Login to your Proxmox PVE. Under Server View side panel, click **Datacenter**. Under the second side panel, click **Permissions** > **Realms**. Under the Realms panel, click **Add** > **OpenID Connect Server**.

**Proxmox OpenID Connect Configuration:**

```
Issuer URL: Copy from Goauth OIDC Info (OIDC Issuer Endpoint)
Realm: Goauth
Client ID: your-client-id
Client Key: your-client-secret
Scopes: email profile
Username Claim: preferred_username
Prompt: Auth-Provider Default

# Optional
# Default: (Make Goauth your default provider)
# Autocreate Users: (Advanced)
# Autocreate Groups: (Advanced)
# Groups Claim: (Advanced)
# Override Groups: (Advanced)
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://pve.example.com
```

> [!NOTE]
> 如果你不使用自动创建，则需要手动创建组和用户。PVE 权限可能相当复杂。我们建议按照他们的 Wiki 操作，因为每个设置都有自己的一套规则。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/seafile.svg" width="28" /> Seafile

Add these lines to the configuration file named `seahub_settings.py`:

**Seafile Configuration:**

```python
ENABLE_OAUTH = True
OAUTH_CREATE_UNKNOWN_USER = True
OAUTH_ACTIVATE_USER_AFTER_CREATION = True
OAUTH_ENABLE_INSECURE_TRANSPORT = False

OAUTH_CLIENT_ID = "your-client-id"
OAUTH_CLIENT_SECRET = "your-client-secret"
OAUTH_REDIRECT_URL = "https://seafile.example.com/oauth/callback/"
OAUTH_PROVIDER_DOMAIN = "goauth.example.com"
OAUTH_PROVIDER = "goauth.example.com"
OAUTH_AUTHORIZATION_URL = "https://goauth.example.com/oidc/auth"
OAUTH_TOKEN_URL = "https://goauth.example.com/oidc/token"
OAUTH_USER_INFO_URL = "https://goauth.example.com/oidc/me"
OAUTH_SCOPE = ["openid", "profile", "email"]
OAUTH_ATTRIBUTE_MAP = {
    "sub": (True, "uid"),
    "email": (False, "email"),
    "name": (False, "name"),
}
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Basic
Client Secret: your-client-secret
Redirect URLs: https://seafile.example.com/oauth/callback/
```

> [!NOTE]
> 你需要重启 Seafile 服务器才能使修改生效。

<br>

## <img src="https://cdn.jsdelivr.net/gh/selfhst/icons/svg/wiki-js.svg" width="28" /> WikiJS

Connect to WikiJS portal as an admin. Go to Configuration Panel, and then Authentication Tab. Create a new authentication strategy using "Generic OpenID Connect / OAuth 2".

**WikiJS Authentication Configuration:**

```
Client ID: your-client-id
Client Secret: your-client-secret
Authorization Endpoint URL: Copy from Goauth OIDC Info (Authorization Endpoint)
Token Endpoint URL: Copy from Goauth OIDC Info (Token Endpoint)
User Info Endpoint URL: Copy from Goauth OIDC Info (UserInfo Endpoint)
Issuer: Copy from Goauth OIDC Info (OIDC Issuer Endpoint)
Email Claim: email
Display Name Claim: name
Groups Claim: groups
Logout URL: Copy from Goauth OIDC Info (Logout Endpoint)
```

**In Goauth OIDC App Page:**

```plaintext
Client ID: your-client-id
Auth Method: Client Secret Post
Client Secret: your-client-secret
Redirect URLs: https://wikijs.example.com/login/{token-from-wikijs-strategy}/callback
```

> [!NOTE]
> 确保你已启用身份验证策略。重定向 URL 包含一个唯一令牌，该令牌显示在 WikiJS 身份验证策略视图中。
