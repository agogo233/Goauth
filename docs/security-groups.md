# 安全组

安全组在管理员安全组页面创建，用户可以从安全组更新或用户更新页面添加到安全组。

> [!IMPORTANT]
> Goauth 的管理员由用户账户上的 `isAdmin` 标识决定：首个注册的用户自动成为管理员，也可以通过 CLI `goauth create-admin` 创建或由管理员在用户页面设置。管理员身份与安全组无关。

> [!TIP]
> 如需限制某个 OIDC 应用或 ProxyAuth 域名的访问，请为其分配对应的安全组；未分配任何安全组的应用/域名对所有已登录用户开放。

<p align=center>
<img width="336" alt="安全组页面" src="/public/screenshots/groups.png" />
</p>

安全组用于 OIDC 应用和 ProxyAuth 域名。

### ProxyAuth
安全组在 ProxyAuth 域名中用于：
* ProxyAuth 域名授权，限制哪些安全组的用户可以访问该域名

有关 ProxyAuth 设置的信息，请访问 [代理认证设置](proxy-auth.md)。

### OIDC
安全组在 OIDC 应用中用于：
* OIDC 应用授权
* 当 OIDC 应用请求 'groups' 作用域时随令牌发送。OIDC 应用可以使用组进行自己的授权，例如 [Jellyfin SSO Plugin](https://github.com/9p4/jellyfin-plugin-sso)

有关 OIDC 设置的信息，请访问 [OIDC 应用设置](oidc-setup.md)。
