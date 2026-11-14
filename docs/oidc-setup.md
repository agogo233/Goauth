# OIDC 应用设置

设置 OIDC 应用时，应遵循"客户端"应用提供的指南。你可以从管理员 OIDC 页面创建新的 OIDC 应用。以下是一个示例应用的 OIDC 配置指南：

```
Client ID: your-client-id
Client Secret: your-client-secret
Redirect URLs: https://client-domain.com/oidc/callback
Auth Method: Client Secret Post
Response Types: code
Grant Types: authorization_code
```

可以在 Goauth 中按如下方式填写：

<p align=center>
<img src="/public/screenshots/oidc-client.png" width="500" alt="OIDC 客户端配置">
</p>

如果 [OIDC 应用配置指南](oidc-guides.md)中省略了某个配置属性，通常使用默认值即可。OIDC 应用页面顶部还包含可选配置，如 `显示名称`、`Logo URL`、`安全组`、`跳过授权确认` 和 `需要 MFA`。

> [!IMPORTANT]
> 在 OIDC 应用页面顶部有一个下拉面板，包含 Goauth OIDC Provider 的相关信息，"客户端"应用在 OIDC 设置时可能需要这些信息。

> [!NOTE]
> `Redirect URLs` 和 `PostLogout URL` 字段支持通配符，但使用时需谨慎。使用通配符 Redirect URLs 时，请务必遵循应用文档。

OIDC 应用页面已设置合理的默认值，但你必须严格按照应用 OIDC 设置指南的参数进行配置，否则 OIDC 集成可能无法正常工作。你可以在 [OIDC 应用配置指南](oidc-guides.md)页面查看部分应用的设置指南。
