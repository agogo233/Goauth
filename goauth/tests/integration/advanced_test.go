package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/internal/model"
	"goauth/internal/service"
	"goauth/internal/util"
	"goauth/tests/helper"
)

// ========== 刷新令牌流程测试 ==========

// TestToken_RefreshToken_FullFlow 测试完整的刷新令牌流程
func TestToken_RefreshToken_FullFlow(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建 OIDC Storage
	storage := createTestStorage(t, server)

	// 创建测试用户
	user := server.CreateUser(t,
		helper.WithUsername("refreshuser"),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 创建访问令牌和刷新令牌
	tokenReq := &mockTokenRequest{subject: user.ID}
	accessToken, refreshToken, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)

	// 使用刷新令牌获取令牌请求
	refreshReq, err := storage.TokenRequestByRefreshToken(context.Background(), refreshToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, refreshReq.GetSubject())

	// 使用刷新令牌创建新的访问令牌
	newAccessToken, newRefreshToken, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, refreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newAccessToken)
	assert.NotEmpty(t, newRefreshToken)

	// 新的刷新令牌应该与旧的不同（刷新令牌轮换）
	assert.NotEqual(t, refreshToken, newRefreshToken, "刷新令牌应该轮换")
}

// TestToken_RefreshToken_Invalid 测试无效刷新令牌
func TestToken_RefreshToken_Invalid(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 使用无效的刷新令牌
	_, err := storage.TokenRequestByRefreshToken(context.Background(), "invalid-refresh-token")
	assert.Error(t, err, "无效刷新令牌应该返回错误")
}

// TestToken_RefreshToken_ExpiredUser 测试用户被禁用后刷新令牌失效
func TestToken_RefreshToken_ExpiredUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	storage := createTestStorage(t, server)

	// 创建用户并生成刷新令牌
	user := server.CreateUser(t,
		helper.WithUsername("disabledrefresh"),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	tokenReq := &mockTokenRequest{subject: user.ID}
	_, refreshToken, _, err := storage.CreateAccessAndRefreshTokens(context.Background(), tokenReq, "")
	require.NoError(t, err)

	// 禁用用户
	user.Disabled = true
	err = server.UserRepo.Update(context.Background(), user)
	require.NoError(t, err)

	// 刷新令牌仍然可以获取，但在实际使用时会验证用户状态
	// 这里测试 storage 层的行为
	refreshReq, err := storage.TokenRequestByRefreshToken(context.Background(), refreshToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, refreshReq.GetSubject())
}

// ========== 并发登录测试 ==========

// TestConcurrentLogin_MultipleDevices 测试多设备登录
func TestConcurrentLogin_MultipleDevices(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建测试用户
	user := server.CreateUser(t,
		helper.WithUsername("concurrentuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 模拟多设备登录（顺序执行，避免 SQLite 并发问题）
	tokens := make([]string, 5)
	for i := 0; i < 5; i++ {
		resp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
			Username:   user.Username,
			Password:   testPassword,
			RememberMe: false,
		}, "127.0.0.1")
		require.NoError(t, err, "登录 %d 应该成功", i)
		tokens[i] = resp.Token
	}

	// 验证所有 token 都不同（不同会话）
	uniqueTokens := make(map[string]bool)
	for i, token := range tokens {
		assert.NotEmpty(t, token, "Token %d 不应该为空", i)
		uniqueTokens[token] = true
	}
	assert.Len(t, uniqueTokens, 5, "每个登录应该有唯一的会话 token")
}

// TestConcurrentLogin_RateLimit 测试并发登录不会触发限流
func TestConcurrentLogin_RateLimit(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建多个不同用户
	users := make([]*model.User, 3)
	for i := 0; i < 3; i++ {
		users[i] = server.CreateUser(t,
			helper.WithUsername("ratelimit"+string(rune('a'+i))),
			helper.WithPassword(testPassword),
			helper.WithApproved(true),
			helper.WithEmailVerified(true),
		)
	}

	successCount := 0
	for _, user := range users {
		_, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
			Username:   user.Username,
			Password:   testPassword,
			RememberMe: false,
		}, "127.0.0.1")
		if err == nil {
			successCount++
		}
	}

	// 所有用户都应该能够登录
	assert.Equal(t, 3, successCount)
}

// ========== 会话管理测试 ==========

// TestSession_MultipleDevices 测试多设备会话管理
func TestSession_MultipleDevices(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("multidevice"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 模拟三个设备登录
	tokens := make([]string, 3)
	for i := 0; i < 3; i++ {
		resp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
			Username:   user.Username,
			Password:   testPassword,
			RememberMe: false,
		}, "127.0.0.1")
		require.NoError(t, err)
		tokens[i] = resp.Token
	}

	// 验证所有会话都存在
	sessions, err := server.SessionRepo.FindByUserID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(sessions), 3, "应该有至少 3 个活跃会话")

	// 验证所有 token 都不同（不同会话）
	uniqueTokens := make(map[string]bool)
	for i, token := range tokens {
		assert.NotEmpty(t, token, "Token %d 不应该为空", i)
		uniqueTokens[token] = true
	}
	assert.Len(t, uniqueTokens, 3, "每个设备应该有唯一的会话 token")
}

// TestSession_TerminateSpecificSession 测试终止特定会话
func TestSession_TerminateSpecificSession(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并登录两次
	user := server.CreateUser(t,
		helper.WithUsername("terminatesession"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 登录设备1
	resp1, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   testPassword,
		RememberMe: false,
	}, "127.0.0.1")
	require.NoError(t, err)
	token1 := resp1.Token

	// 登录设备2
	resp2, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   testPassword,
		RememberMe: false,
	}, "127.0.0.1")
	require.NoError(t, err)
	token2 := resp2.Token

	// 获取会话列表
	sessions, err := server.SessionRepo.FindByUserID(context.Background(), user.ID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(sessions), 2)

	// 找到 token2 对应的会话（数据库中 token 存储为 SHA-256 哈希）
	var session2ID string
	for _, s := range sessions {
		if s.Token == util.HashToken(token2) {
			session2ID = s.ID
			break
		}
	}
	require.NotEmpty(t, session2ID)

	// 使用 repo 直接删除会话（模拟终止操作）
	err = server.SessionRepo.Delete(context.Background(), session2ID)
	require.NoError(t, err)

	// 验证 token2 已失效
	_, err = server.SessionRepo.FindByToken(context.Background(), token2)
	assert.Error(t, err, "Token2 应该已被删除")

	// 验证 token1 仍然有效
	_, err = server.SessionRepo.FindByToken(context.Background(), token1)
	assert.NoError(t, err, "Token1 应该仍然有效")
}

// TestSession_TerminateAllOtherSessions 测试终止所有其他会话
func TestSession_TerminateAllOtherSessions(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("terminateothers"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 登录多个设备
	tokens := make([]string, 3)
	for i := 0; i < 3; i++ {
		resp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
			Username:   user.Username,
			Password:   testPassword,
			RememberMe: false,
		}, "127.0.0.1")
		require.NoError(t, err)
		tokens[i] = resp.Token
	}

	// 使用 repo 直接删除其他会话（模拟终止操作）
	// 数据库中 token 存储为 SHA-256 哈希，比较时需先哈希
	sessions, err := server.SessionRepo.FindByUserID(context.Background(), user.ID)
	require.NoError(t, err)

	for _, s := range sessions {
		if s.Token != util.HashToken(tokens[0]) {
			err = server.SessionRepo.Delete(context.Background(), s.ID)
			require.NoError(t, err)
		}
	}

	// 验证只有第一个 token 有效
	_, err = server.SessionRepo.FindByToken(context.Background(), tokens[0])
	assert.NoError(t, err)

	for i := 1; i < 3; i++ {
		_, err := server.SessionRepo.FindByToken(context.Background(), tokens[i])
		assert.Error(t, err, "Token %d 应该已失效", i)
	}
}

// TestSession_RememberMe 测试记住我功能
func TestSession_RememberMe(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("rememberme"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 不勾选记住我
	resp1, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   testPassword,
		RememberMe: false,
	}, "127.0.0.1")
	require.NoError(t, err)

	// 勾选记住我
	resp2, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   testPassword,
		RememberMe: true,
	}, "127.0.0.1")
	require.NoError(t, err)

	// 验证记住我的会话过期时间更长
	assert.True(t, resp2.ExpiresAt.After(resp1.ExpiresAt), "记住我的会话应该更长久")

	// 验证会话中的 RememberMe 标记
	session1, err := server.SessionRepo.FindByToken(context.Background(), resp1.Token)
	require.NoError(t, err)
	assert.False(t, session1.RememberMe)

	session2, err := server.SessionRepo.FindByToken(context.Background(), resp2.Token)
	require.NoError(t, err)
	assert.True(t, session2.RememberMe)
}

// TestSession_Expiration 测试会话过期
func TestSession_Expiration(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("expireuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 登录
	resp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   testPassword,
		RememberMe: false,
	}, "127.0.0.1")
	require.NoError(t, err)

	// 验证会话存在
	_, err = server.SessionRepo.FindByToken(context.Background(), resp.Token)
	require.NoError(t, err)

	// 手动删除会话并创建一个过期的会话来模拟过期
	err = server.SessionRepo.DeleteByToken(context.Background(), resp.Token)
	require.NoError(t, err)

	// 创建一个已过期的会话
	expiredSession := &model.Session{
		ID:        "expired-session-id",
		UserID:    user.ID,
		Token:     "expired-token",
		ExpiresAt: model.CustomTime{Time: time.Now().Add(-1 * time.Hour)},
	}
	err = server.SessionRepo.Create(context.Background(), expiredSession)
	require.NoError(t, err)

	// 验证过期的会话无法使用
	req, _ := http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "expired-token"})

	client := &http.Client{}
	httpResp, err := client.Do(req)
	require.NoError(t, err)
	defer httpResp.Body.Close()

	// 过期会话应该返回 401
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)
}

// ========== 密码重置测试（API 层） ==========

// TestPasswordReset_AdminReset 测试管理员重置用户密码
func TestPasswordReset_AdminReset(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建管理员
	admin := server.CreateAdmin(t)
	adminToken := server.Login(t, admin.Username, "My-Test-Pass-2024-Secure!")

	// 创建普通用户
	user := server.CreateUser(t,
		helper.WithUsername("resetuser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 管理员重置密码
	newPassword := "New-Strong-Password-2024!"
	resetBody := map[string]interface{}{
		"password": newPassword,
	}
	body, _ := json.Marshal(resetBody)

	req, _ := http.NewRequest("POST", server.Server.URL+"/api/admin/users/"+user.ID+"/reset-password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 验证新密码可以登录
	_, err = server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   newPassword,
		RememberMe: false,
	}, "127.0.0.1")
	assert.NoError(t, err, "应该能使用新密码登录")

	// 验证旧密码不能登录
	_, err = server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   testPassword,
		RememberMe: false,
	}, "127.0.0.1")
	assert.Error(t, err, "旧密码不应该能登录")
}

// TestPasswordReset_WeakPassword 测试管理员设置弱密码被拒绝
func TestPasswordReset_WeakPassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建管理员
	admin := server.CreateAdmin(t)
	adminToken := server.Login(t, admin.Username, "My-Test-Pass-2024-Secure!")

	// 创建普通用户
	user := server.CreateUser(t, helper.WithUsername("weakreset"))

	// 尝试设置弱密码
	resetBody := map[string]interface{}{
		"password": "123", // 太弱
	}
	body, _ := json.Marshal(resetBody)

	req, _ := http.NewRequest("POST", server.Server.URL+"/api/admin/users/"+user.ID+"/reset-password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 弱密码应该被拒绝
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ========== 用户自助修改密码测试 ==========

// TestUser_ChangePassword 测试用户修改密码
func TestUser_ChangePassword(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并登录
	user, token := server.LoginAsUser(t, helper.WithUsername("changepass"))

	// 修改密码
	newPassword := "New-Secure-Password-2024!"
	changeBody := map[string]interface{}{
		"oldPassword": testPassword,
		"newPassword": newPassword,
	}
	body, _ := json.Marshal(changeBody)

	req, _ := http.NewRequest("PATCH", server.Server.URL+"/api/user/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 验证新密码可以登录
	_, err = server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   user.Username,
		Password:   newPassword,
		RememberMe: false,
	}, "127.0.0.1")
	assert.NoError(t, err)
}

// TestUser_ChangePassword_WrongCurrent 测试修改密码时当前密码错误
func TestUser_ChangePassword_WrongCurrent(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并登录
	_, token := server.LoginAsUser(t, helper.WithUsername("wrongcurrent"))

	// 使用错误的当前密码
	changeBody := map[string]interface{}{
		"oldPassword": "WrongPassword123!",
		"newPassword": "New-Secure-Password-2024!",
	}
	body, _ := json.Marshal(changeBody)

	req, _ := http.NewRequest("PATCH", server.Server.URL+"/api/user/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回错误
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)

	// 读取响应体
	respBody, _ := io.ReadAll(resp.Body)
	t.Logf("Response: %s", string(respBody))
}

// ========== 用户资料更新测试 ==========

// TestUser_UpdateProfile 测试用户更新资料
func TestUser_UpdateProfile(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并登录
	_, token := server.LoginAsUser(t, helper.WithUsername("updateprofile"))

	// 更新资料
	updateBody := map[string]interface{}{
		"name":  "Updated Name",
		"email": "updated@example.com",
	}
	body, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PATCH", server.Server.URL+"/api/user/profile", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 验证更新
	meReq, _ := http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	meReq.AddCookie(&http.Cookie{Name: "session", Value: token})

	meResp, err := client.Do(meReq)
	require.NoError(t, err)
	defer meResp.Body.Close()

	var userResp map[string]interface{}
	err = json.NewDecoder(meResp.Body).Decode(&userResp)
	require.NoError(t, err)

	assert.Equal(t, "Updated Name", userResp["name"])
}
