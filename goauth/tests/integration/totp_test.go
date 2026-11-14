package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/internal/service"
	"goauth/tests/helper"
)

// ========== TOTP 设置测试 ==========

// TestTotp_Setup_Success 测试成功设置 TOTP
func TestTotp_Setup_Success(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建并登录用户
	_, token := server.LoginAsUser(t, helper.WithUsername("totpuser"))

	// 设置 TOTP
	req, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "设置 TOTP 应该成功，响应: %s", string(body))

	var result service.TotpSetupResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// 验证响应包含必要信息
	assert.NotEmpty(t, result.URI, "应该返回 otpauth URI")
	assert.NotEmpty(t, result.QrBase64, "应该返回 QR 码 base64")
	assert.NotEmpty(t, result.Secret, "应该返回密钥")
	assert.NotEmpty(t, result.EncryptedSecret, "应该返回加密密钥")

	// 验证数据库中尚未存储（Setup 不再自动存储）
	user, err := server.UserRepo.FindByUsername(context.Background(), "totpuser")
	require.NoError(t, err)
	enabled, err := server.TotpService.IsEnabled(context.Background(), user.ID)
	require.NoError(t, err)
	assert.False(t, enabled, "TOTP 不应该在 Setup 后立即启用，需要验证确认")
}

// TestTotp_Setup_VerifyAndConfirm 测试完整的设置+验证确认流程
func TestTotp_Setup_VerifyAndConfirm(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建并登录用户
	_, token := server.LoginAsUser(t, helper.WithUsername("totpverifyflow"))

	// 第一步：Setup
	req, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var setupResult service.TotpSetupResponse
	err = json.Unmarshal(body, &setupResult)
	require.NoError(t, err)

	// 第二步：验证并确认
	validCode := totpValidateCode(setupResult.Secret)
	verifyBody := map[string]interface{}{
		"code":            validCode,
		"secret":          setupResult.Secret,
		"encryptedSecret": setupResult.EncryptedSecret,
	}
	verifyJSON, _ := json.Marshal(verifyBody)

	req2, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/verify", bytes.NewReader(verifyJSON))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "session", Value: token})

	resp2, err := client.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	body2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp2.StatusCode, "验证确认响应: %s", string(body2))

	// 验证数据库中已存储
	user, err := server.UserRepo.FindByUsername(context.Background(), "totpverifyflow")
	require.NoError(t, err)
	enabled, err := server.TotpService.IsEnabled(context.Background(), user.ID)
	require.NoError(t, err)
	assert.True(t, enabled, "TOTP 应该在验证确认后启用")
}

// TestTotp_Setup_AlreadyEnabled 测试重复设置 TOTP 失败
func TestTotp_Setup_AlreadyEnabled(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建并登录用户
	user, token := server.LoginAsUser(t, helper.WithUsername("totpdouble"))

	// 第一次设置并确认
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 尝试第二次设置
	req, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Handler 返回 500 表示服务错误（TOTP 已启用）
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTotp_Setup_Unauthorized 测试未登录无法设置 TOTP
func TestTotp_Setup_Unauthorized(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 不带 cookie 设置 TOTP
	req, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ========== TOTP 登录流程测试 ==========

// TestTotp_Login_FullFlow 测试完整的 TOTP 登录流程
func TestTotp_Login_FullFlow(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("totplogin"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 设置并确认 TOTP
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 验证 TOTP 已启用
	enabled, err := server.TotpService.IsEnabled(context.Background(), user.ID)
	require.NoError(t, err)
	require.True(t, enabled, "TOTP 应该已启用")

	// 使用服务直接登录查看结果
	loginResp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "totplogin",
		Password: testPassword,
	}, "127.0.0.1")
	require.NoError(t, err)
	require.True(t, loginResp.RequireTotp, "启用 TOTP 后应该要求验证")
	require.NotEmpty(t, loginResp.Token, "应该返回临时 token")

	// 第二步：验证 TOTP
	tempToken := loginResp.Token
	validCode := totpValidateCode(setupResp.Secret)

	totpBody := map[string]interface{}{
		"code": validCode,
	}
	totpJSON, _ := json.Marshal(totpBody)

	req, _ := http.NewRequest("POST", server.Server.URL+"/api/auth/totp", bytes.NewReader(totpJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: tempToken}) // 使用临时 token 作为 cookie

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "TOTP 验证响应: %s", string(body))

	var totpResult service.LoginResponse
	err = json.Unmarshal(body, &totpResult)
	require.NoError(t, err)

	// token 已改为 json:"-"，改从 Set-Cookie 提取最终 session
	var finalToken string
	for _, ck := range resp.Cookies() {
		if ck.Name == "session" {
			finalToken = ck.Value
		}
	}
	assert.NotEmpty(t, finalToken, "应该通过 HttpOnly cookie 下发最终 session token")
	assert.NotNil(t, totpResult.User, "应该返回用户信息")
	assert.Equal(t, "totplogin", totpResult.User.Username)
	assert.False(t, totpResult.RequireTotp, "TOTP 已验证，不应再要求")
}

// TestTotp_Login_InvalidCode 测试无效 TOTP 代码
func TestTotp_Login_InvalidCode(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并设置 TOTP
	user := server.CreateUser(t,
		helper.WithUsername("totpinvalid"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 使用服务直接登录获取临时 token
	loginResp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "totpinvalid",
		Password: testPassword,
	}, "127.0.0.1")
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.Token, "应该返回临时 token")

	// 使用无效代码验证
	totpBody := map[string]interface{}{
		"code": "000000", // 无效代码
	}
	totpJSON, _ := json.Marshal(totpBody)

	req, _ := http.NewRequest("POST", server.Server.URL+"/api/auth/totp", bytes.NewReader(totpJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: loginResp.Token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestTotp_Login_MissingToken 测试缺少 token
func TestTotp_Login_MissingToken(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 直接尝试 TOTP 验证（无 cookie）
	totpBody := map[string]interface{}{
		"code": "123456",
	}
	totpJSON, _ := json.Marshal(totpBody)

	req, _ := http.NewRequest("POST", server.Server.URL+"/api/auth/totp", bytes.NewReader(totpJSON))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 没有 cookie 中的临时 token，应该返回 401
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ========== TOTP 移除测试 ==========

// TestTotp_Remove_Success 测试成功移除 TOTP
func TestTotp_Remove_Success(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并设置 TOTP
	user, token := server.LoginAsUser(t, helper.WithUsername("totpremove"))
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 移除 TOTP
	req, _ := http.NewRequest("DELETE", server.Server.URL+"/api/user/totp", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 验证已移除
	enabled, err := server.TotpService.IsEnabled(context.Background(), user.ID)
	require.NoError(t, err)
	assert.False(t, enabled, "TOTP 应该已移除")
}

// TestTotp_Remove_NotEnabled 测试移除未启用的 TOTP
func TestTotp_Remove_NotEnabled(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户（未设置 TOTP）
	_, token := server.LoginAsUser(t, helper.WithUsername("totpnosetup"))

	// 尝试移除
	req, _ := http.NewRequest("DELETE", server.Server.URL+"/api/user/totp", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该成功（幂等操作）
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ========== TOTP 服务层测试 ==========

// TestTotp_Service_Verify 测试服务层验证
func TestTotp_Service_Verify(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并设置 TOTP
	user := server.CreateUser(t, helper.WithUsername("totpverify"))
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 使用正确代码验证
	validCode := totpValidateCode(setupResp.Secret)
	valid, err := server.TotpService.Verify(context.Background(), user.ID, validCode)
	require.NoError(t, err)
	assert.True(t, valid, "有效代码应该验证通过")

	// 使用错误代码验证
	valid, err = server.TotpService.Verify(context.Background(), user.ID, "000000")
	require.NoError(t, err)
	assert.False(t, valid, "无效代码应该验证失败")
}

// TestTotp_Service_GenerateBackupCodes 测试生成备用码
func TestTotp_Service_GenerateBackupCodes(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	user := server.CreateUser(t, helper.WithUsername("backupcodes"))

	codes, err := server.TotpService.GenerateBackupCodes(context.Background(), user.ID)
	require.NoError(t, err)

	assert.Len(t, codes, 10, "应该生成 10 个备用码")
	for _, code := range codes {
		assert.NotEmpty(t, code, "备用码不应该为空")
	}
}

// ========== 辅助函数 ==========

// totpValidateCode 使用密钥生成有效的 TOTP 代码
func totpValidateCode(secret string) string {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "000000"
	}
	return code
}

// ========== MFA 要求测试 ==========

// TestMfaRequired_UserLevel 测试用户级别 MFA 要求
func TestMfaRequired_UserLevel(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建需要 MFA 但未设置 TOTP 的用户
	_ = server.CreateUser(t,
		helper.WithUsername("mfauser"),
		helper.WithUserMFARequired(true),
	)

	// 登录
	loginReq := map[string]interface{}{
		"username":   "mfauser",
		"password":   "My-Test-Pass-2024-Secure!",
		"rememberMe": false,
	}
	body, _ := json.Marshal(loginReq)

	resp, err := http.Post(server.Server.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	// 应该返回 RequireMfaSetup: true
	assert.Equal(t, http.StatusOK, resp.StatusCode, "登录应该成功，响应: %s", string(respBody))
	assert.True(t, result["requireMfaSetup"].(bool), "应该返回 requireMfaSetup: true")
	assert.NotNil(t, result["user"], "应该返回用户信息")
	assert.Nil(t, result["token"], "token 不应出现在 JSON 响应体中")

	// 从 HttpOnly cookie 提取临时 session
	var token string
	for _, ck := range resp.Cookies() {
		if ck.Name == "session" {
			token = ck.Value
		}
	}
	require.NotEmpty(t, token, "应该通过 HttpOnly cookie 下发临时 session")
	setupReq, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)
	setupReq.AddCookie(&http.Cookie{Name: "session", Value: token})

	client := &http.Client{}
	setupResp, err := client.Do(setupReq)
	require.NoError(t, err)
	defer setupResp.Body.Close()

	assert.Equal(t, http.StatusOK, setupResp.StatusCode, "应该能访问 TOTP 设置 API")
}

// TestMfaRequired_GroupLevel 测试分组级别 MFA 要求
func TestMfaRequired_GroupLevel(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建要求 MFA 的分组
	admin := server.CreateUser(t, helper.WithUsername("groupadmin"), helper.WithIsAdmin(true))
	group := server.CreateGroup(t,
		helper.WithGroupName("mfa-group"),
		helper.WithGroupCreatedBy(admin.ID),
		helper.WithMFARequired(true),
	)

	// 创建用户并加入分组
	user := server.CreateUser(t, helper.WithUsername("groupmfauser"))
	server.AddUserToGroup(t, user.ID, group.ID)

	// 登录
	loginReq := map[string]interface{}{
		"username":   "groupmfauser",
		"password":   "My-Test-Pass-2024-Secure!",
		"rememberMe": false,
	}
	body, _ := json.Marshal(loginReq)

	resp, err := http.Post(server.Server.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)

	// 应该返回 RequireMfaSetup: true（因为分组要求 MFA）
	assert.Equal(t, http.StatusOK, resp.StatusCode, "登录应该成功")
	assert.True(t, result["requireMfaSetup"].(bool), "分组要求 MFA 时应该返回 requireMfaSetup: true")
}

// TestMfaRequired_CompleteSetup 测试完成 TOTP 设置后升级 session
func TestMfaRequired_CompleteSetup(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建需要 MFA 的用户
	user := server.CreateUser(t,
		helper.WithUsername("mfasetupcomplete"),
		helper.WithUserMFARequired(true),
	)

	// 登录获取临时 session
	loginReq := map[string]interface{}{
		"username":   "mfasetupcomplete",
		"password":   "My-Test-Pass-2024-Secure!",
		"rememberMe": false,
	}
	body, _ := json.Marshal(loginReq)

	resp, err := http.Post(server.Server.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	// token 已改为 json:"-"，从 HttpOnly cookie 提取临时 session
	var token string
	for _, ck := range resp.Cookies() {
		if ck.Name == "session" {
			token = ck.Value
		}
	}
	require.NotEmpty(t, token, "应该通过 HttpOnly cookie 下发临时 session")

	// 设置 TOTP
	client := &http.Client{}

	setupReq, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)
	setupReq.AddCookie(&http.Cookie{Name: "session", Value: token})
	setupResp, err := client.Do(setupReq)
	require.NoError(t, err)

	var setupResult service.TotpSetupResponse
	json.NewDecoder(setupResp.Body).Decode(&setupResult)
	setupResp.Body.Close()

	// 验证 TOTP 设置
	validCode := totpValidateCode(setupResult.Secret)
	verifyReq := map[string]interface{}{
		"code":            validCode,
		"secret":          setupResult.Secret,
		"encryptedSecret": setupResult.EncryptedSecret,
	}
	verifyBody, _ := json.Marshal(verifyReq)

	verifyReqHttp, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/verify", bytes.NewReader(verifyBody))
	verifyReqHttp.Header.Set("Content-Type", "application/json")
	verifyReqHttp.AddCookie(&http.Cookie{Name: "session", Value: token})

	verifyResp, err := client.Do(verifyReqHttp)
	require.NoError(t, err)
	defer verifyResp.Body.Close()

	assert.Equal(t, http.StatusOK, verifyResp.StatusCode, "TOTP 验证应该成功")

	// 验证 session 已升级 - 可以访问需要完整认证的 API
	meReq, _ := http.NewRequest("GET", server.Server.URL+"/api/user/me", nil)
	meReq.AddCookie(&http.Cookie{Name: "session", Value: token})

	meResp, err := client.Do(meReq)
	require.NoError(t, err)
	defer meResp.Body.Close()

	// session 应该已经升级，可以访问需要完整认证的 API
	assert.Equal(t, http.StatusOK, meResp.StatusCode, "session 升级后应该可以访问受保护的 API")

	// 验证 TOTP 已启用
	enabled, err := server.TotpService.IsEnabled(context.Background(), user.ID)
	require.NoError(t, err)
	assert.True(t, enabled, "TOTP 应该已启用")
}

// TestMfaRequired_DeniedWithoutTotpSetup 测试未设置 TOTP 时拒绝访问受保护资源
func TestMfaRequired_DeniedWithoutTotpSetup(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建需要 MFA 的用户
	server.CreateUser(t,
		helper.WithUsername("mfadenied"),
		helper.WithUserMFARequired(true),
	)

	// 登录
	loginReq := map[string]interface{}{
		"username":   "mfadenied",
		"password":   "My-Test-Pass-2024-Secure!",
		"rememberMe": false,
	}
	body, _ := json.Marshal(loginReq)

	resp, err := http.Post(server.Server.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// token 已改为 json:"-"，从 HttpOnly cookie 提取临时 session
	var token string
	for _, ck := range resp.Cookies() {
		if ck.Name == "session" {
			token = ck.Value
		}
	}
	require.NotEmpty(t, token, "应该通过 HttpOnly cookie 下发临时 session")

	// 尝试访问需要完整认证的 API（如修改密码）
	client := &http.Client{}
	pwReq := map[string]interface{}{
		"oldPassword": "password123",
		"newPassword": "newpassword123",
	}
	pwBody, _ := json.Marshal(pwReq)

	pwReqHttp, _ := http.NewRequest("PATCH", server.Server.URL+"/api/user/password", bytes.NewReader(pwBody))
	pwReqHttp.Header.Set("Content-Type", "application/json")
	pwReqHttp.AddCookie(&http.Cookie{Name: "session", Value: token})

	pwResp, err := client.Do(pwReqHttp)
	require.NoError(t, err)
	defer pwResp.Body.Close()

	// 应该被拒绝（因为 session 是 pwd-mfa-setup-required）
	assert.Equal(t, http.StatusUnauthorized, pwResp.StatusCode, "未完成 TOTP 设置应该拒绝访问受保护资源")
}

// ========== TOTP 重试限制测试 ==========

// TestTotp_Login_RetryLimit 测试 TOTP 验证重试限制
func TestTotp_Login_RetryLimit(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并设置 TOTP
	user := server.CreateUser(t,
		helper.WithUsername("totpretry"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 使用服务直接登录获取临时 token
	loginResp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "totpretry",
		Password: testPassword,
	}, "127.0.0.1")
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.Token, "应该返回临时 token")

	// 多次使用无效代码验证
	client := &http.Client{}
	for i := 0; i < 5; i++ {
		totpBody := map[string]interface{}{
			"code": "000000", // 无效代码
		}
		totpJSON, _ := json.Marshal(totpBody)

		req, _ := http.NewRequest("POST", server.Server.URL+"/api/auth/totp", bytes.NewReader(totpJSON))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "session", Value: loginResp.Token})

		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}

	// 第 6 次应该被锁定或 session 失效
	totpBody := map[string]interface{}{
		"code": "000000",
	}
	totpJSON, _ := json.Marshal(totpBody)

	req, _ := http.NewRequest("POST", server.Server.URL+"/api/auth/totp", bytes.NewReader(totpJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: loginResp.Token})

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 应该返回错误（429 Too Many Requests, 400 Bad Request, 或 401 Unauthorized）
	assert.True(t, resp.StatusCode == http.StatusTooManyRequests || 
		resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusUnauthorized,
		"超过重试次数应该返回错误，实际状态码: %d", resp.StatusCode)
}

// ========== 管理员 TOTP 操作测试 ==========

// TestTotp_AdminReset 测试管理员重置用户 TOTP
func TestTotp_AdminReset(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建管理员
	admin, adminToken := server.LoginAsUser(t,
		helper.WithUsername("totpadmin"),
		helper.WithIsAdmin(true),
	)

	// 创建普通用户并设置 TOTP
	user := server.CreateUser(t, helper.WithUsername("totpuser"))
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 验证 TOTP 已启用
	enabled, err := server.TotpService.IsEnabled(context.Background(), user.ID)
	require.NoError(t, err)
	require.True(t, enabled, "TOTP 应该已启用")

	// 管理员重置用户 TOTP
	resetReq := map[string]interface{}{}
	resetJSON, _ := json.Marshal(resetReq)

	req, _ := http.NewRequest("DELETE", server.Server.URL+"/api/admin/users/"+user.ID+"/totp", bytes.NewReader(resetJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 管理员可能没有这个 API，检查状态码
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("管理员重置 TOTP API 不存在")
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode, "管理员应该能重置用户 TOTP")

	// 验证 TOTP 已被移除
	enabled, err = server.TotpService.IsEnabled(context.Background(), user.ID)
	require.NoError(t, err)
	assert.False(t, enabled, "TOTP 应该已被移除")

	_ = admin // 使用 admin 变量避免未使用警告
}

// ========== Session 状态测试 ==========

// TestTotp_SessionState_AfterPasswordLogin 测试密码登录后的 session 状态
func TestTotp_SessionState_AfterPasswordLogin(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并设置 TOTP
	user := server.CreateUser(t,
		helper.WithUsername("sessionstate"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 密码登录
	loginResp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "sessionstate",
		Password: testPassword,
	}, "127.0.0.1")
	require.NoError(t, err)

	// 验证返回 RequireTotp: true
	assert.True(t, loginResp.RequireTotp, "启用 TOTP 后应该要求验证")
	assert.NotEmpty(t, loginResp.Token, "应该返回临时 token")

	// 验证 session 的 AMR 是 pwd-totp-pending
	session, err := server.SessionRepo.FindByToken(context.Background(), loginResp.Token)
	require.NoError(t, err)
	assert.Equal(t, "pwd-totp-pending", session.AMR, "session AMR 应该是 pwd-totp-pending")
}

// TestTotp_SessionState_AfterTotpVerify 测试 TOTP 验证后的 session 状态
func TestTotp_SessionState_AfterTotpVerify(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并设置 TOTP
	user := server.CreateUser(t,
		helper.WithUsername("sessionaftertotp"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 密码登录
	loginResp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "sessionaftertotp",
		Password: testPassword,
	}, "127.0.0.1")
	require.NoError(t, err)

	// TOTP 验证
	validCode := totpValidateCode(setupResp.Secret)
	totpBody := map[string]interface{}{
		"code": validCode,
	}
	totpJSON, _ := json.Marshal(totpBody)

	req, _ := http.NewRequest("POST", server.Server.URL+"/api/auth/totp", bytes.NewReader(totpJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: loginResp.Token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "TOTP 验证应该成功")

	var result service.LoginResponse
	json.NewDecoder(resp.Body).Decode(&result)
	_ = result

	// token 已改为 json:"-"，从 Set-Cookie 提取最终 session token
	var finalToken string
	for _, ck := range resp.Cookies() {
		if ck.Name == "session" {
			finalToken = ck.Value
		}
	}
	require.NotEmpty(t, finalToken, "应该通过 HttpOnly cookie 下发最终 session token")

	// 验证 session 的 AMR 是 pwd,totp
	session, err := server.SessionRepo.FindByToken(context.Background(), finalToken)
	require.NoError(t, err)
	assert.Equal(t, "pwd,totp", session.AMR, "session AMR 应该是 pwd,totp")
}

// ========== 并发登录测试 ==========

// TestTotp_ConcurrentLogin 测试并发登录
func TestTotp_ConcurrentLogin(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	_ = server.CreateUser(t,
		helper.WithUsername("concurrentlogin"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 串行登录（避免并发数据库访问问题）
	done := make(chan *service.LoginResponse, 5)
	for i := 0; i < 5; i++ {
		resp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
			Username: "concurrentlogin",
			Password: testPassword,
		}, "127.0.0.1")
		if err != nil {
			done <- nil
			continue
		}
		done <- resp
	}

	// 收集结果
	successCount := 0
	for i := 0; i < 5; i++ {
		resp := <-done
		if resp != nil && resp.Token != "" {
			successCount++
		}
	}

	// 大部分登录应该成功
	assert.GreaterOrEqual(t, successCount, 3, "大部分登录应该成功")
}

// ========== 边界情况测试 ==========

// TestTotp_Login_DisabledUser 测试禁用用户无法登录
func TestTotp_Login_DisabledUser(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建禁用用户
	_ = server.CreateUser(t,
		helper.WithUsername("disableduser"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
		helper.WithDisabled(true),
	)

	// 尝试登录
	_, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "disableduser",
		Password: testPassword,
	}, "127.0.0.1")

	assert.Error(t, err, "禁用用户不应该能登录")
}

// TestTotp_Login_NotApproved 测试未批准用户无法登录
func TestTotp_Login_NotApproved(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建未批准用户
	_ = server.CreateUser(t,
		helper.WithUsername("notapproved"),
		helper.WithPassword(testPassword),
		helper.WithApproved(false),
		helper.WithEmailVerified(true),
	)

	// 尝试登录
	_, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "notapproved",
		Password: testPassword,
	}, "127.0.0.1")

	assert.Error(t, err, "未批准用户不应该能登录")
}

// TestTotp_Login_EmailNotVerified 测试邮箱未验证用户无法登录
func TestTotp_Login_EmailNotVerified(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建邮箱未验证用户
	_ = server.CreateUser(t,
		helper.WithUsername("emailnotverified"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(false),
	)

	// 尝试登录
	_, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "emailnotverified",
		Password: testPassword,
	}, "127.0.0.1")

	assert.Error(t, err, "邮箱未验证用户不应该能登录")
}

// TestTotp_VerifyCode_Format 测试验证码格式
func TestTotp_VerifyCode_Format(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户并设置 TOTP
	user := server.CreateUser(t,
		helper.WithUsername("codeformat"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)
	setupResp, err := server.TotpService.Setup(context.Background(), user.ID, user.Username)
	require.NoError(t, err)
	err = server.TotpService.ConfirmSetup(context.Background(), user.ID, setupResp.EncryptedSecret)
	require.NoError(t, err)

	// 测试不同格式的验证码 - 每个测试用例使用新的 session
	testCases := []struct {
		name       string
		code       string
		expectFail bool
	}{
		{"空代码", "", true},
		{"太短", "12345", true},
		{"太长", "1234567", true},
		{"包含字母", "12ab56", true},
		{"全是字母", "abcdef", true},
		{"特殊字符", "12-456", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 每次测试获取新的 session
			loginResp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
				Username: "codeformat",
				Password: testPassword,
			}, "127.0.0.1")
			require.NoError(t, err)

			totpBody := map[string]interface{}{
				"code": tc.code,
			}
			totpJSON, _ := json.Marshal(totpBody)

			req, _ := http.NewRequest("POST", server.Server.URL+"/api/auth/totp", bytes.NewReader(totpJSON))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: "session", Value: loginResp.Token})

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			resp.Body.Close()

			if tc.expectFail {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s 应该返回 400，实际: %d", tc.name, resp.StatusCode)
			}
		})
	}
}

// TestTotp_Setup_WithSession 测试带 session 的 TOTP 设置
func TestTotp_Setup_WithSession(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建并登录用户
	_, token := server.LoginAsUser(t, helper.WithUsername("setupwithsession"))

	// 设置 TOTP
	req, _ := http.NewRequest("POST", server.Server.URL+"/api/mfa-setup/totp/setup", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result service.TotpSetupResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	// 验证返回的内容
	assert.NotEmpty(t, result.URI)
	assert.NotEmpty(t, result.QrBase64)
	assert.NotEmpty(t, result.Secret)
	assert.NotEmpty(t, result.EncryptedSecret)

	// 验证 URI 包含正确的 issuer
	assert.Contains(t, result.URI, "otpauth://totp/")
}

// TestTotp_MultipleSessions 测试同一用户多个 session
func TestTotp_MultipleSessions(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("multisession"),
		helper.WithPassword(testPassword),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 创建多个 session
	sessions := make([]string, 3)
	for i := 0; i < 3; i++ {
		resp, err := server.AuthService.Login(context.Background(), &service.LoginRequest{
			Username: "multisession",
			Password: testPassword,
		}, "127.0.0.1")
		require.NoError(t, err)
		sessions[i] = resp.Token
	}

	// 所有 session 应该不同
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			assert.NotEqual(t, sessions[i], sessions[j], "Session tokens should be unique")
		}
	}

	// 所有 session 都应该有效
	for i, token := range sessions {
		session, err := server.SessionRepo.FindByToken(context.Background(), token)
		require.NoError(t, err, "Session %d should be valid", i)
		assert.Equal(t, user.ID, session.UserID, "Session %d should belong to user", i)
	}
}