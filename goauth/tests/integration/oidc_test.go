package integration

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	zitadeloidc "github.com/zitadel/oidc/v3/pkg/oidc"

	"goauth/internal/model"
	"goauth/internal/oidc"
	"goauth/internal/repo"
	"goauth/tests/helper"
)

// ========== OIDC 发现端点测试 ==========

func TestOIDC_Discovery(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	provider := createTestOIDCProvider(t, server)
	require.NotNil(t, provider)

	// 验证 Provider 的 Storage 可以工作
	storage := provider.Storage()
	require.NotNil(t, storage)

	// 验证签名密钥可以获取；ID 应为非空（来自 DB 记录 ID）
	signingKey, err := storage.SigningKey(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, signingKey.ID())
	assert.Equal(t, signingKey.ID(), storage.SigningKeyIDForTest())
}

func TestOIDC_JWKS(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	provider := createTestOIDCProvider(t, server)

	// 获取密钥集
	keySet, err := provider.Storage().KeySet(context.Background())
	require.NoError(t, err)
	require.Len(t, keySet, 1)

	// 验证密钥属性（kid 来自 DB 记录 ID，非硬编码）
	key := keySet[0]
	assert.NotEmpty(t, key.ID())
	assert.Equal(t, "sig", key.Use())
}

// ========== OIDC 客户端测试 ==========

func TestOIDC_ClientValidation(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 通过 clients 表创建测试客户端（repo.Create 会自动 bcrypt 哈希 Secret，这里传明文）
	server.CreateClient(t,
		helper.WithClientID("test-client"),
		helper.WithClientSecret("test-secret"),
		helper.WithClientName("Test Client"),
		helper.WithRedirectURIs([]string{"http://localhost:3000/callback"}),
		helper.WithScopes([]string{"openid", "profile", "email"}),
	)

	// 验证客户端可以被获取
	foundClient, err := storage.GetClientByClientID(context.Background(), "test-client")
	require.NoError(t, err)
	assert.Equal(t, "test-client", foundClient.GetID())
}

func TestOIDC_ClientSecretValidation(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 通过 clients 表创建测试客户端（带密钥）
	// 注意：repo.Create 会对 Secret 做 bcrypt 哈希，这里传明文
	server.CreateClient(t,
		helper.WithClientID("secret-client"),
		helper.WithClientSecret("client-secret-123"),
		helper.WithClientName("Secret Client"),
		helper.WithRedirectURIs([]string{"http://localhost:3000/callback"}),
		helper.WithScopes([]string{"openid", "profile"}),
	)

	// 验证正确的密钥
	err := storage.AuthorizeClientIDSecret(context.Background(), "secret-client", "client-secret-123")
	assert.NoError(t, err)

	// 验证错误的密钥
	err = storage.AuthorizeClientIDSecret(context.Background(), "secret-client", "wrong-secret")
	assert.Error(t, err)
}

// ========== OIDC 用户认证测试 ==========

func TestOIDC_UserAuthentication(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t,
		helper.WithUsername("oidcuser"),
		helper.WithEmail("oidc@example.com"),
		helper.WithEmailVerified(true),
		helper.WithApproved(true),
	)

	// 验证用户名密码
	userID, err := storage.CheckUsernamePassword(context.Background(), "oidcuser", "My-Test-Pass-2024-Secure!")
	require.NoError(t, err)
	assert.Equal(t, user.ID, userID)
}

func TestOIDC_UserAuthentication_WrongPassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("oidcuser"),
		helper.WithEmail("oidc@example.com"),
		helper.WithEmailVerified(true),
		helper.WithApproved(true),
	)

	// 验证错误密码
	_, err := storage.CheckUsernamePassword(context.Background(), "oidcuser", "wrong-password")
	assert.Error(t, err)
}

func TestOIDC_UserAuthentication_UnapprovedUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建未批准用户
	server.CreateUser(t,
		helper.WithUsername("unapproved"),
		helper.WithEmail("unapproved@example.com"),
		helper.WithEmailVerified(true),
		helper.WithApproved(false),
	)

	// 未批准用户无法认证
	_, err := storage.CheckUsernamePassword(context.Background(), "unapproved", "My-Test-Pass-2024-Secure!")
	assert.Error(t, err)
}

func TestOIDC_UserAuthentication_DisabledUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建已禁用用户
	server.CreateUser(t,
		helper.WithUsername("disabled"),
		helper.WithEmail("disabled@example.com"),
		helper.WithEmailVerified(true),
		helper.WithApproved(true),
		helper.WithDisabled(true),
	)

	// 已禁用用户无法认证
	_, err := storage.CheckUsernamePassword(context.Background(), "disabled", "My-Test-Pass-2024-Secure!")
	assert.Error(t, err)
}

// ========== OIDC 授权请求测试 ==========

func TestOIDC_CreateAuthRequest(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t, helper.WithUsername("authuser"))

	// 创建授权请求
	authReq := &zitadeloidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: zitadeloidc.ResponseTypeCode,
		Scopes:       []string{"openid", "profile"},
		State:        "test-state",
		Nonce:        "test-nonce",
	}

	req, err := storage.CreateAuthRequest(context.Background(), authReq, user.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, req.GetID())
	assert.Equal(t, user.ID, req.GetSubject())
}

func TestOIDC_AuthRequestByID(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t, helper.WithUsername("authuser"))

	// 创建授权请求
	authReq := &zitadeloidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: zitadeloidc.ResponseTypeCode,
		Scopes:       []string{"openid"},
	}

	created, err := storage.CreateAuthRequest(context.Background(), authReq, user.ID)
	require.NoError(t, err)

	// 通过 ID 获取授权请求
	found, err := storage.AuthRequestByID(context.Background(), created.GetID())
	require.NoError(t, err)
	assert.Equal(t, created.GetID(), found.GetID())
}

func TestOIDC_CompleteAuthRequest(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t, helper.WithUsername("authuser"))

	// 创建授权请求
	authReq := &zitadeloidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: zitadeloidc.ResponseTypeCode,
		Scopes:       []string{"openid"},
	}

	created, err := storage.CreateAuthRequest(context.Background(), authReq, "")
	require.NoError(t, err)

	// 完成授权请求
	err = storage.CompleteAuthRequest(context.Background(), created.GetID(), user.ID)
	require.NoError(t, err)

	// 验证授权请求已更新
	found, err := storage.AuthRequestByID(context.Background(), created.GetID())
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.GetSubject())
	assert.True(t, found.Done())
}

// ========== OIDC 令牌测试 ==========

func TestOIDC_CreateAccessToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t, helper.WithUsername("tokenuser"))

	// 创建访问令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	tokenID, exp, err := storage.CreateAccessToken(context.Background(), tokenReq)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenID)
	assert.True(t, exp.After(time.Now()))
}

func TestOIDC_CreateAccessAndRefreshTokens(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t, helper.WithUsername("tokenuser"))

	// 创建访问令牌和刷新令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	accessToken, refreshToken, exp, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
	assert.True(t, exp.After(time.Now()))
}

func TestOIDC_RefreshToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t, helper.WithUsername("tokenuser"))

	// 创建令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	_, refreshToken, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)

	// 使用刷新令牌获取新的令牌请求
	refreshReq, err := storage.TokenRequestByRefreshToken(context.Background(), refreshToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, refreshReq.GetSubject())
}

// ========== OIDC 用户信息测试 ==========

func TestOIDC_SetUserinfoFromScopes(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Provider
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t,
		helper.WithUsername("infouser"),
		helper.WithEmail("info@example.com"),
		helper.WithName("Info User"),
	)

	// 设置用户信息
	userinfo := &zitadeloidc.UserInfo{}
	err := storage.SetUserinfoFromScopes(context.Background(), userinfo, user.ID, "", []string{"openid", "profile", "email"})
	require.NoError(t, err)

	assert.Equal(t, user.ID, userinfo.Subject)
	assert.Equal(t, "infouser", userinfo.PreferredUsername)
	assert.Equal(t, "info@example.com", userinfo.Email)
	assert.Equal(t, "Info User", userinfo.Name)
}

// ========== 辅助函数 ==========

func createTestStorage(t *testing.T, server *helper.TestServer) *oidc.Storage {
	t.Helper()

	keyRepo := repo.NewKeyRepo(server.DB)
	oidcRepo := repo.NewOIDCRepo(server.DB)

	storage, err := oidc.NewStorage(server.UserRepo, server.GroupRepo, keyRepo, oidcRepo, server.ClientRepo, server.SessionRepo, server.Cfg)
	require.NoError(t, err, "Failed to create OIDC storage")

	return storage
}

func createTestOIDCProvider(t *testing.T, server *helper.TestServer) *oidc.Provider {
	t.Helper()

	storage := createTestStorage(t, server)
	provider, err := oidc.NewProvider(server.Cfg, storage)
	require.NoError(t, err, "Failed to create OIDC provider")

	return provider
}

// ========== OIDC 授权码测试 ==========

func TestOIDC_SaveAuthCode(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("codeuser"))

	// 创建授权请求
	authReq := &zitadeloidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: zitadeloidc.ResponseTypeCode,
		Scopes:       []string{"openid"},
	}

	created, err := storage.CreateAuthRequest(context.Background(), authReq, user.ID)
	require.NoError(t, err)

	// 保存授权码
	code := "test-auth-code-123"
	err = storage.SaveAuthCode(context.Background(), created.GetID(), code)
	require.NoError(t, err)

	// 通过授权码获取授权请求
	found, err := storage.AuthRequestByCode(context.Background(), code)
	require.NoError(t, err)
	assert.Equal(t, created.GetID(), found.GetID())
}

func TestOIDC_AuthRequestByCode_InvalidCode(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 使用无效的授权码
	_, err := storage.AuthRequestByCode(context.Background(), "invalid-code")
	assert.Error(t, err)
	assert.Equal(t, oidc.ErrInvalidRequest, err)
}

func TestOIDC_DeleteAuthRequest(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("deleteuser"))

	// 创建授权请求
	authReq := &zitadeloidc.AuthRequest{
		ClientID:     "test-client",
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: zitadeloidc.ResponseTypeCode,
		Scopes:       []string{"openid"},
	}

	created, err := storage.CreateAuthRequest(context.Background(), authReq, user.ID)
	require.NoError(t, err)

	// 删除授权请求
	err = storage.DeleteAuthRequest(context.Background(), created.GetID())
	require.NoError(t, err)

	// 验证已删除
	_, err = storage.AuthRequestByID(context.Background(), created.GetID())
	assert.Error(t, err)
}

// ========== OIDC 令牌撤销测试 ==========

func TestOIDC_RevokeToken_RefreshToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("revokeuser"))

	// 创建令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	_, refreshToken, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)

	// 验证刷新令牌可用
	_, err = storage.TokenRequestByRefreshToken(context.Background(), refreshToken)
	require.NoError(t, err)

	// 撤销令牌
	err = storage.RevokeToken(context.Background(), refreshToken, user.ID, "")
	assert.Nil(t, err)

	// 验证令牌已撤销
	_, err = storage.TokenRequestByRefreshToken(context.Background(), refreshToken)
	assert.Error(t, err)
}

func TestOIDC_RevokeToken_AccessToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("revokeaccess"))

	// 创建访问令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	accessToken, _, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)

	// 撤销访问令牌
	err = storage.RevokeToken(context.Background(), accessToken, user.ID, "")
	assert.Nil(t, err)
}

// ========== OIDC 内省测试 ==========

func TestOIDC_SetIntrospectionFromToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("introspectuser"))

	// 创建访问令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	accessToken, _, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)

	// 设置内省信息
	introspection := &zitadeloidc.IntrospectionResponse{}
	err = storage.SetIntrospectionFromToken(context.Background(), introspection, accessToken, user.ID, "test-client")
	require.NoError(t, err)

	assert.True(t, introspection.Active)
	assert.Equal(t, user.ID, introspection.Subject)
}

// ========== OIDC 签名密钥测试 ==========

func TestOIDC_SigningKeyPersistence(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建第一个 storage
	storage1 := createTestStorage(t, server)
	key1, err := storage1.SigningKey(context.Background())
	require.NoError(t, err)

	// 创建第二个 storage（模拟重启）
	storage2 := createTestStorage(t, server)
	key2, err := storage2.SigningKey(context.Background())
	require.NoError(t, err)

	// 验证密钥相同（持久化）
	assert.Equal(t, key1.ID(), key2.ID())
}

func TestOIDC_SignatureAlgorithms(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	algs, err := storage.SignatureAlgorithms(context.Background())
	require.NoError(t, err)
	assert.Contains(t, algs, jose.SignatureAlgorithm("RS256"))
}

// ========== OIDC 客户端功能测试 ==========

func TestOIDC_ClientMethods(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 通过 clients 表创建测试客户端
	// 注意：repo.Create 会对 Secret 做 bcrypt 哈希，这里传明文
	server.CreateClient(t,
		helper.WithClientID("method-test-client"),
		helper.WithClientSecret("secret"),
		helper.WithClientName("Method Test Client"),
		helper.WithRedirectURIs([]string{"http://localhost:3000/callback", "http://localhost:3000/callback2"}),
		helper.WithPostLogoutURIs([]string{"http://localhost:3000/logout"}),
		helper.WithScopes([]string{"openid", "profile", "email"}),
		helper.WithTrusted(true),
	)

	// 验证客户端方法
	storage := createTestStorage(t, server)
	foundClient, err := storage.GetClientByClientID(context.Background(), "method-test-client")
	require.NoError(t, err)

	// 类型断言以访问 Client 的特定方法
	c, ok := foundClient.(*oidc.Client)
	require.True(t, ok, "should be *oidc.Client type")

	assert.Equal(t, "method-test-client", foundClient.GetID())
	assert.Equal(t, "Method Test Client", c.GetName())
	assert.Len(t, foundClient.RedirectURIs(), 2)
	assert.Len(t, foundClient.PostLogoutRedirectURIs(), 1)
	assert.True(t, c.SkipConsent())
	assert.True(t, c.IsScopeAllowed("openid"))
	assert.False(t, c.IsScopeAllowed("invalid-scope"))
}

func TestOIDC_ClientNotFound(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	_, err := storage.GetClientByClientID(context.Background(), "nonexistent-client")
	assert.Error(t, err)
	assert.Equal(t, oidc.ErrInvalidClient, err)
}

func TestOIDC_ClientSecretValidation_EmptySecret(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 创建无密钥的客户端（通过 clients 表）
	server.CreateClient(t,
		helper.WithClientID("no-secret-client"),
		helper.WithClientName("No Secret Client"),
		helper.WithRedirectURIs([]string{"http://localhost:3000/callback"}),
		helper.WithScopes([]string{"openid"}),
	)

	// 验证空密钥客户端
	err := storage.AuthorizeClientIDSecret(context.Background(), "no-secret-client", "any-secret")
	assert.Error(t, err) // 空密钥客户端不应该能验证
}

// ========== OIDC 用户认证边界测试 ==========

func TestOIDC_UserAuthentication_EmailUnverified(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 创建邮箱未验证用户
	server.CreateUser(t,
		helper.WithUsername("unverified"),
		helper.WithEmail("unverified@example.com"),
		helper.WithEmailVerified(false),
		helper.WithApproved(true),
	)

	// 邮箱未验证用户无法认证
	_, err := storage.CheckUsernamePassword(context.Background(), "unverified", "My-Test-Pass-2024-Secure!")
	assert.Error(t, err)
}

func TestOIDC_UserAuthentication_UserNotFound(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 不存在的用户
	_, err := storage.CheckUsernamePassword(context.Background(), "nonexistent", "password")
	assert.Error(t, err)
	assert.Equal(t, oidc.ErrUnauthorizedUser, err)
}

func TestOIDC_UserAuthentication_NoPassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 创建无密码用户
	user := &model.User{
		Username:      "nopassword",
		Email:         strPtr("nopassword@example.com"),
		PasswordHash:  nil, // 无密码
		EmailVerified: true,
		Approved:      true,
	}
	err := server.UserRepo.Create(context.Background(), user)
	require.NoError(t, err)

	// 无密码用户无法通过密码认证
	_, err = storage.CheckUsernamePassword(context.Background(), "nopassword", "any-password")
	assert.Error(t, err)
}

// ========== OIDC 刷新令牌边界测试 ==========

func TestOIDC_RefreshToken_InvalidToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 使用无效的刷新令牌
	_, err := storage.TokenRequestByRefreshToken(context.Background(), "invalid-refresh-token")
	assert.Error(t, err)
	assert.Equal(t, oidc.ErrInvalidGrant, err)
}

func TestOIDC_GetRefreshTokenInfo(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("tokeninfouser"))

	// 创建令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	_, refreshToken, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)

	// 获取刷新令牌信息
	tokenID, userID, err := storage.GetRefreshTokenInfo(context.Background(), "test-client", refreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenID)
	assert.Equal(t, user.ID, userID)
}

func TestOIDC_GetRefreshTokenInfo_InvalidToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 使用无效的刷新令牌
	_, _, err := storage.GetRefreshTokenInfo(context.Background(), "test-client", "invalid-token")
	assert.Error(t, err)
}

// ========== OIDC 用户信息边界测试 ==========

func TestOIDC_SetUserinfoFromScopes_OpenIDOnly(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t,
		helper.WithUsername("openiduser"),
		helper.WithEmail("openid@example.com"),
		helper.WithName("OpenID User"),
	)

	// 只请求 openid scope
	userinfo := &zitadeloidc.UserInfo{}
	err := storage.SetUserinfoFromScopes(context.Background(), userinfo, user.ID, "", []string{"openid"})
	require.NoError(t, err)

	// 只有 subject 应该被设置
	assert.Equal(t, user.ID, userinfo.Subject)
	assert.Empty(t, userinfo.Email)    // email scope 未请求
	assert.Empty(t, userinfo.Name)     // profile scope 未请求
}

func TestOIDC_SetUserinfoFromScopes_UserNotFound(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 不存在的用户
	userinfo := &zitadeloidc.UserInfo{}
	err := storage.SetUserinfoFromScopes(context.Background(), userinfo, "nonexistent-user-id", "", []string{"openid"})
	assert.Error(t, err)
}

// ========== OIDC 授权请求边界测试 ==========

func TestOIDC_AuthRequestByID_NotFound(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	_, err := storage.AuthRequestByID(context.Background(), "nonexistent-id")
	assert.Error(t, err)
	assert.Equal(t, oidc.ErrInvalidRequest, err)
}

func TestOIDC_CompleteAuthRequest_NotFound(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("completenonexist"))

	err := storage.CompleteAuthRequest(context.Background(), "nonexistent-id", user.ID)
	assert.Error(t, err)
}

// ========== OIDC KeySet 测试 ==========

func TestOIDC_KeySet(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	keySet, err := storage.KeySet(context.Background())
	require.NoError(t, err)
	require.Len(t, keySet, 1)

	// 验证密钥属性（kid 来自 DB 记录 ID，非硬编码）
	key := keySet[0]
	assert.NotEmpty(t, key.ID())
	assert.Equal(t, "sig", key.Use())
	assert.Equal(t, jose.SignatureAlgorithm("RS256"), key.Algorithm())
}

// ========== OIDC Health 和 TerminateSession 测试 ==========

func TestOIDC_Health(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	err := storage.Health(context.Background())
	assert.NoError(t, err)
}

func TestOIDC_TerminateSession(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)
	user := server.CreateUser(t, helper.WithUsername("terminatesession"))

	// TerminateSession 目前是空实现，只验证不报错
	err := storage.TerminateSession(context.Background(), user.ID, "test-client")
	assert.NoError(t, err)
}

// ========== 辅助函数 ==========

// mockTokenRequest 实现 op.TokenRequest 接口
type mockTokenRequest struct {
	subject string
}

func (m *mockTokenRequest) GetSubject() string   { return m.subject }
func (m *mockTokenRequest) GetAudience() []string { return nil }
func (m *mockTokenRequest) GetScopes() []string  { return []string{"openid"} }
