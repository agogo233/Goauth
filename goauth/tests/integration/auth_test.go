package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/internal/model"
	"goauth/internal/service"
	"goauth/tests/helper"
)

// 强密码，满足 zxcvbn 3+ 分数要求
const strongPassword = "Correct-Horse-Battery-Staple"
const testPassword = "My-Test-Pass-2024-Secure!"

// TestAuth_Register_FirstUser 测试第一个用户自动成为管理员
func TestAuth_Register_FirstUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 注册第一个用户
	reqBody := `{"username":"firstuser","password":"` + strongPassword + `","email":"first@example.com"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/register",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusCreated, resp.StatusCode, "注册应该成功，响应: %s", string(body))

	var result service.RegisterResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// 验证第一个用户是管理员
	assert.Equal(t, "firstuser", result.User.Username)
	assert.True(t, result.User.IsAdmin, "第一个用户应该是管理员")
	assert.True(t, result.User.EmailVerified, "第一个用户应该自动验证邮箱")
	assert.True(t, result.User.Approved, "第一个用户应该自动批准")
	assert.Equal(t, "注册成功", result.Message)

	// 验证数据库中的用户
	user, err := server.UserRepo.FindByUsername(context.Background(), "firstuser")
	require.NoError(t, err)
	assert.True(t, user.IsAdmin)
	assert.True(t, user.EmailVerified)
	assert.True(t, user.Approved)
}

// TestAuth_Register_SubsequentUser 测试后续用户需要审批
func TestAuth_Register_SubsequentUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 先创建一个管理员（模拟第一个用户）
	server.CreateAdmin(t)

	// 注册第二个用户
	reqBody := `{"username":"seconduser","password":"` + strongPassword + `","email":"second@example.com"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/register",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "注册应该成功，响应: %s", string(body))

	var result service.RegisterResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// 验证后续用户不是管理员，需要审批
	assert.Equal(t, "seconduser", result.User.Username)
	assert.False(t, result.User.IsAdmin, "后续用户不应该是管理员")
	assert.False(t, result.User.EmailVerified, "后续用户需要验证邮箱")
	assert.False(t, result.User.Approved, "后续用户需要审批")
	assert.Equal(t, "注册成功，请等待管理员审批", result.Message)

	// 验证数据库中的用户
	user, err := server.UserRepo.FindByUsername(context.Background(), "seconduser")
	require.NoError(t, err)
	assert.False(t, user.IsAdmin)
	assert.False(t, user.EmailVerified)
	assert.False(t, user.Approved)
}

// TestAuth_Register_DuplicateUsername 测试重复用户名注册失败
func TestAuth_Register_DuplicateUsername(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 先创建一个用户
	server.CreateUser(t, helper.WithUsername("existinguser"))

	// 尝试用相同用户名注册
	reqBody := `{"username":"existinguser","password":"` + strongPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/register",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 409 Conflict 更符合"用户名已存在"的语义
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// TestAuth_Register_WeakPassword 测试弱密码注册失败
func TestAuth_Register_WeakPassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 尝试用弱密码注册
	reqBody := `{"username":"weakuser","password":"123"}` // 太短且太简单
	resp, err := http.Post(
		server.Server.URL+"/api/auth/register",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAuth_Login_Success 测试登录成功
func TestAuth_Login_Success(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("loginuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 登录
	reqBody := `{"username":"loginuser","password":"` + testPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "登录应该成功，响应: %s", string(body))

	var result service.LoginResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// Token 已改为 json:"-"，不再出现在 JSON 响应体中（防 XSS 窃取）
	assert.Empty(t, result.Token, "登录响应体不应包含 token")

	// 从 Set-Cookie 中提取 session token
	var sessionToken string
	for _, ck := range resp.Cookies() {
		if ck.Name == "session" {
			sessionToken = ck.Value
		}
	}
	assert.NotEmpty(t, sessionToken, "登录响应应通过 HttpOnly cookie 下发 session")

	assert.NotNil(t, result.User, "应该返回用户信息")
	assert.Equal(t, "loginuser", result.User.Username)
	assert.False(t, result.RequireTotp, "未启用 TOTP 时不应要求验证")
	assert.True(t, result.ExpiresAt.After(time.Now()), "过期时间应该是未来时间")
}

// TestAuth_Login_WrongPassword 测试错误密码登录失败
func TestAuth_Login_WrongPassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("wrongpassuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 用错误密码登录
	reqBody := `{"username":"wrongpassuser","password":"Wrong-Password-2024!"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_Login_UserNotFound 测试用户不存在
func TestAuth_Login_UserNotFound(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 尝试登录不存在的用户
	reqBody := `{"username":"nonexistent","password":"` + strongPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_Login_UserNotApproved 测试未批准用户无法登录
func TestAuth_Login_UserNotApproved(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建未批准的用户
	server.CreateUser(t,
		helper.WithUsername("notapproved"),
		helper.WithPassword(testPassword),
		helper.WithApproved(false),
		helper.WithEmailVerified(true),
	)

	// 尝试登录
	reqBody := `{"username":"notapproved","password":"` + testPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestAuth_Login_UserDisabled 测试禁用用户无法登录
func TestAuth_Login_UserDisabled(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建禁用的用户
	server.CreateUser(t,
		helper.WithUsername("disableduser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
		helper.WithDisabled(true),
	)

	// 尝试登录
	reqBody := `{"username":"disableduser","password":"` + testPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestAuth_Login_EmailNotVerified 测试邮箱未验证无法登录
func TestAuth_Login_EmailNotVerified(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建邮箱未验证的用户
	server.CreateUser(t,
		helper.WithUsername("unverified"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(false),
	)

	// 尝试登录
	reqBody := `{"username":"unverified","password":"` + testPassword + `"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestAuth_GetMe 测试获取当前用户信息
func TestAuth_GetMe(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建并登录用户
	user, token := server.LoginAsUser(t,
		helper.WithUsername("meuser"),
		helper.WithEmail("me@example.com"),
		helper.WithName("Me User"),
	)

	// 获取当前用户信息
	req, err := http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result model.UserResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, "meuser", result.Username)
	assert.Equal(t, "me@example.com", *result.Email)
	assert.Equal(t, "Me User", *result.Name)
}

// TestAuth_GetMe_Unauthorized 测试未登录时获取用户信息失败
func TestAuth_GetMe_Unauthorized(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 不带 cookie 获取用户信息
	resp, err := http.Get(server.Server.URL + "/api/user/me")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAuth_Logout 测试登出
func TestAuth_Logout(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建并登录用户（HTTP 登录以获取 CSRF token）
	_, token, csrfToken := server.LoginAsUserHTTP(t, helper.WithUsername("logoutuser"))

	// 登出（必须携带 CSRF token）
	req, err := http.NewRequest("POST", server.Server.URL+"/api/auth/logout", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	req.Header.Set("X-CSRF-Token", csrfToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 验证 session 已被删除
	_, err = server.SessionRepo.FindByToken(context.Background(), token)
	assert.Error(t, err, "登出后 session 应该被删除")
}

// TestAuth_Login_RememberMe 测试记住我功能
func TestAuth_Login_RememberMe(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("rememberuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 带记住我登录
	reqBody := `{"username":"rememberuser","password":"` + testPassword + `","rememberMe":true}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(reqBody),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "登录应该成功，响应: %s", string(body))

	var result service.LoginResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// 验证过期时间更长（30天）
	assert.True(t, result.ExpiresAt.After(time.Now().Add(24*time.Hour)), "记住我应该延长过期时间")
}

// TestAuth_Service_Login_Direct 测试直接调用 Service 方法登录
func TestAuth_Service_Login_Direct(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	server.CreateUser(t,
		helper.WithUsername("serviceuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 直接调用 Service 登录
	resp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   "serviceuser",
		Password:   testPassword,
		RememberMe: false,
	}, "127.0.0.1")

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.NotNil(t, resp.User)
	assert.Equal(t, "serviceuser", resp.User.Username)
}

// TestAuth_Service_Register_Direct 测试直接调用 Service 方法注册
func TestAuth_Service_Register_Direct(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 直接调用 Service 注册
	resp, err := server.AuthService.Register(context.Background(), &service.RegisterRequest{
		Username: "directuser",
		Password: strongPassword,
		Email:    strPtr("direct@example.com"),
	})

	require.NoError(t, err)
	assert.NotNil(t, resp.User)
	assert.Equal(t, "directuser", resp.User.Username)
	assert.True(t, resp.User.IsAdmin, "第一个用户应该是管理员")
}

// TestAuth_FullFlow 完整的用户流程测试
func TestAuth_FullFlow(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 1. 第一个用户注册（自动成为管理员）
	registerBody := `{"username":"flowuser","password":"` + strongPassword + `","email":"flow@example.com","name":"Flow User"}`
	resp, err := http.Post(
		server.Server.URL+"/api/auth/register",
		"application/json",
		strings.NewReader(registerBody),
	)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "注册响应: %s", string(body))
	resp.Body.Close()

	// 2. 登录
	loginBody := `{"username":"flowuser","password":"` + strongPassword + `"}`
	resp, err = http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(loginBody),
	)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "登录响应: %s", string(body))

	var loginResult service.LoginResponse
	err = json.Unmarshal(body, &loginResult)
	require.NoError(t, err)
	_ = loginResult // token 已不再通过 JSON 下发，改用下方 cookie 中的 session

	// 提取登录响应中的 session token（HttpOnly cookie）
	var csrfToken string
	var sessionToken string
	for _, ck := range resp.Cookies() {
		if ck.Name == "csrf_token" {
			csrfToken = ck.Value
		}
		if ck.Name == "session" {
			sessionToken = ck.Value
		}
	}
	require.NotEmpty(t, csrfToken, "登录响应应携带 csrf_token cookie")
	require.NotEmpty(t, sessionToken, "登录响应应通过 HttpOnly cookie 下发 session")
	resp.Body.Close()

	token := sessionToken

	// 3. 获取用户信息
	req, err := http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})

	client := &http.Client{}
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// 4. 登出（必须携带 CSRF token）
	req, err = http.NewRequest("POST", server.Server.URL+"/api/auth/logout", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	req.Header.Set("X-CSRF-Token", csrfToken)

	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// 5. 验证登出后无法获取用户信息
	req, err = http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})

	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

// TestAuth_Login_WithJSONRequest 使用 JSON body 的登录测试
func TestAuth_Login_WithJSONRequest(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	server.CreateUser(t,
		helper.WithUsername("jsonuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 构造 JSON 请求
	loginReq := map[string]interface{}{
		"username":   "jsonuser",
		"password":   testPassword,
		"rememberMe": false,
	}
	body, err := json.Marshal(loginReq)
	require.NoError(t, err)

	resp, err := http.Post(
		server.Server.URL+"/api/auth/login",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// strPtr 辅助函数，返回字符串指针
func strPtr(s string) *string {
	return &s
}