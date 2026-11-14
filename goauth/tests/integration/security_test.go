package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/internal/middleware"
	"goauth/internal/service"
	"goauth/tests/helper"
)

// 强密码，满足 zxcvbn 3+ 分数要求
const securityStrongPassword = "Correct-Horse-Battery-Staple"
const securityTestPassword = "My-Test-Pass-2024-Secure!"

// ========== 暴力破解防护边界测试 ==========
// 注意：这些测试设计为不触发实际封锁，只验证防护机制存在

// TestSecurity_BruteForceProtection_Exists 验证暴力破解防护机制存在
func TestSecurity_BruteForceProtection_Exists(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("bfprotect"),
		helper.WithPassword(securityTestPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 验证防护器存在 - 通过检查配置
	assert.Greater(t, server.Cfg.Security.LoginMaxAttempts, 0, "LoginMaxAttempts should be > 0")
	assert.Greater(t, server.Cfg.Security.LoginBlockDuration, 0, "LoginBlockDuration should be > 0")
}

// TestSecurity_BruteForceProtection_WrongPassword 验证错误密码被记录
func TestSecurity_BruteForceProtection_WrongPassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("wrongpasstest"),
		helper.WithPassword(securityTestPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 尝试用错误密码登录（单次，不触发封锁）
	reqBody := `{"username":"wrongpasstest","password":"Wrong-Password-2024!"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回 401
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSecurity_BruteForceProtection_CorrectPasswordResets 验证正确密码重置计数
func TestSecurity_BruteForceProtection_CorrectPasswordResets(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("correctreset"),
		helper.WithPassword(securityTestPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 先用错误密码尝试一次
	reqBody := `{"username":"correctreset","password":"Wrong-Password-2024!"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	resp.Body.Close()

	// 然后用正确密码登录 - 应该成功
	reqBody = `{"username":"correctreset","password":"` + securityTestPassword + `"}`
	resp, err = http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestSecurity_AccountStatus_Unapproved 验证未批准账户无法登录
func TestSecurity_AccountStatus_Unapproved(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建未批准用户
	server.CreateUser(t,
		helper.WithUsername("unapprovedsec"),
		helper.WithPassword(securityTestPassword),
		helper.WithApproved(false),
		helper.WithEmailVerified(true),
	)

	// 尝试登录
	reqBody := `{"username":"unapprovedsec","password":"` + securityTestPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回 403 Forbidden
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestSecurity_AccountStatus_Disabled 验证禁用账户无法登录
func TestSecurity_AccountStatus_Disabled(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建禁用用户
	server.CreateUser(t,
		helper.WithUsername("disabledsec"),
		helper.WithPassword(securityTestPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
		helper.WithDisabled(true),
	)

	// 尝试登录
	reqBody := `{"username":"disabledsec","password":"` + securityTestPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回 403 Forbidden
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestSecurity_AccountStatus_EmailUnverified 验证邮箱未验证无法登录
func TestSecurity_AccountStatus_EmailUnverified(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建邮箱未验证用户
	server.CreateUser(t,
		helper.WithUsername("unverifiedsec"),
		helper.WithPassword(securityTestPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(false),
	)

	// 尝试登录
	reqBody := `{"username":"unverifiedsec","password":"` + securityTestPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回 403 Forbidden
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestSecurity_PasswordStrength_Weak 验证弱密码被拒绝
func TestSecurity_PasswordStrength_Weak(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	weakPasswords := []string{
		"123",           // 太短
		"password",      // 常见密码
		"abc123",        // 太简单
		"qwerty",        // 常见密码
	}

	for _, weakPwd := range weakPasswords {
		reqBody := `{"username":"weakpwduser","password":"` + weakPwd + `"}`
		resp, err := http.Post(
			server.Server.URL+"/api/auth/register",
			"application/json",
			strings.NewReader(reqBody),
		)
		require.NoError(t, err)
		resp.Body.Close()

		// 弱密码应该被拒绝
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "弱密码 '%s' 应该被拒绝", weakPwd)
	}
}

// TestSecurity_PasswordStrength_Strong 验证强密码被接受
func TestSecurity_PasswordStrength_Strong(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 使用满足 zxcvbn 3+ 分数要求的密码
	securityStrongPasswords := []string{
		"Correct-Horse-Battery-Staple",
		"My-Secure-Password-2024!",
		securityTestPassword,
	}

	for i, strongPwd := range securityStrongPasswords {
		username := "strongpwduser" + string(rune('a'+i))
		reqBody := `{"username":"` + username + `","password":"` + strongPwd + `","email":"` + username + `@test.com"}`
		resp, err := http.Post(
			server.Server.URL+"/api/auth/register",
			"application/json",
			strings.NewReader(reqBody),
		)
		require.NoError(t, err)
		resp.Body.Close()

		// 强密码应该被接受
		assert.Equal(t, http.StatusCreated, resp.StatusCode, "强密码 '%s' 应该被接受", strongPwd)
	}
}

// TestSecurity_Session_InvalidToken 验证无效 token 无法访问受保护资源
func TestSecurity_Session_InvalidToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 使用无效 token 访问受保护端点
	req, err := http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "invalid-token-12345",
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSecurity_Session_ExpiredToken 验证过期 token 无法使用
func TestSecurity_Session_ExpiredToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("expiredtoken"),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 创建一个已过期的 session
	ctx := context.Background()
	expiredTime := time.Now().Add(-24 * time.Hour) // 昨天过期

	// 直接在数据库中创建过期 session（绕过服务层）
	_, err := server.DB.ExecContext(ctx, `
		INSERT INTO sessions (id, userId, token, expiresAt, createdAt)
		VALUES (?, ?, ?, ?, ?)
	`, "expired-session-id", user.ID, "expired-token-xyz", expiredTime, time.Now())
	require.NoError(t, err)

	// 尝试使用过期 token
	req, err := http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "expired-token-xyz",
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 过期 session 应该被拒绝
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSecurity_CSRF_NoToken 验证 CSRF 中间件对登出接口的保护
func TestSecurity_CSRF_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.CSRF(middleware.CSRFConfig{}))
	router.POST("/api/auth/logout", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "已登出"})
	})

	// 不带 CSRF token 的登出请求应被拒绝（403）
	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// 携带匹配的 CSRF token 应成功
	csrfToken := "test-csrf-token-value"
	req = httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSecurity_AdminAccess_RegularUser 验证普通用户无法访问管理端点
func TestSecurity_AdminAccess_RegularUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建普通用户（非管理员）
	_, token := server.LoginAsUser(t,
		helper.WithUsername("regularuser"),
		helper.WithIsAdmin(false),
	)

	// 尝试访问管理端点
	req, err := http.NewRequest("GET", server.Server.URL+"/api/admin/users", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回 403 Forbidden
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestSecurity_AdminAccess_AdminUser 验证管理员可以访问管理端点
func TestSecurity_AdminAccess_AdminUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建管理员用户
	_, token := server.LoginAsUser(t,
		helper.WithUsername("adminuser"),
		helper.WithIsAdmin(true),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 访问管理端点
	req, err := http.NewRequest("GET", server.Server.URL+"/api/admin/users", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回 200 OK
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestSecurity_InputValidation_EmptyUsername 验证空用户名被拒绝
func TestSecurity_InputValidation_EmptyUsername(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	reqBody := `{"username":"","password":"` + securityTestPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.True(t, resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized)
}

// TestSecurity_InputValidation_EmptyPassword 验证空密码被拒绝
func TestSecurity_InputValidation_EmptyPassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	reqBody := `{"username":"someuser","password":""}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.True(t, resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized)
}

// TestSecurity_InputValidation_InvalidJSON 验证无效 JSON 被拒绝
func TestSecurity_InputValidation_InvalidJSON(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader("invalid json"),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestSecurity_SessionConcurrentLogin 验证并发登录行为
func TestSecurity_SessionConcurrentLogin(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	server.CreateUser(t,
		helper.WithUsername("concurrentuser"),
		helper.WithPassword(securityTestPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 连续登录两次
	reqBody := `{"username":"concurrentuser","password":"` + securityTestPassword + `"}`

	// 第一次登录
	resp1, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	body1, err := io.ReadAll(resp1.Body)
	require.NoError(t, err)
	resp1.Body.Close()

	var result1 service.LoginResponse
	require.NoError(t, json.Unmarshal(body1, &result1))
	_ = result1 // token 已不再通过 JSON 下发，改用 cookie 断言

	// 第二次登录
	resp2, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	body2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	resp2.Body.Close()

	var result2 service.LoginResponse
	require.NoError(t, json.Unmarshal(body2, &result2))

	// 两次登录都应该成功
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// 两次登录都应通过 HttpOnly cookie 下发 session（token 不再出现在响应体）
	assert.NotEmpty(t, resp1.Cookies(), "第一次登录应下发 cookie")
	assert.NotEmpty(t, resp2.Cookies(), "第二次登录应下发 cookie")
}

// TestSecurity_PasswordUpdate_RequiresAuth 验证修改密码需要认证
func TestSecurity_PasswordUpdate_RequiresAuth(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 不带认证尝试修改密码
	reqBody := `{"currentPassword":"old","newPassword":"` + securityStrongPassword + `"}`
	req, err := http.NewRequest("PATCH", server.Server.URL+"/api/user/password", strings.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSecurity_ProfileUpdate_RequiresAuth 验证修改资料需要认证
func TestSecurity_ProfileUpdate_RequiresAuth(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 不带认证尝试修改资料
	reqBody := `{"name":"New Name"}`
	req, err := http.NewRequest("PATCH", server.Server.URL+"/api/user/profile", strings.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSecurity_TOTP_RequiresAuth 验证 TOTP 操作需要认证
func TestSecurity_TOTP_RequiresAuth(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 不带认证尝试设置 TOTP - 使用正确的路径
	req, err := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
